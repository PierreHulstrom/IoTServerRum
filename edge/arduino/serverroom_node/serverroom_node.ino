/* =========================================================================
 * Serverrum IoT - Elegoo / Arduino Mega 2560
 * Azure MQTTS + Pi + Lokal 2FA + Vedvarende Alarm + PWM Blæser (Pin 12)
 * ========================================================================= */
#include <Keypad.h>
#include <dhtnew.h>
#include <Wire.h>
#include <RTClib.h>
#include <LiquidCrystal.h>
#include <SPI.h>
#include <MFRC522.h>

// Holdets fysiske pins (RC522 RST på Pin 5 - nul konflikt med LCD ben 6-11)
#define RST_PIN 5
#define SS_PIN  53
MFRC522 mfrc522(SS_PIN, RST_PIN);

byte gyldigUID[] = { 0xF1, 0xEF, 0xBE, 0x53 };

// DHT22 (Pin 48) & Lydsensor (A0)
DHTNEW mySensor(48);
const int soundAnalogPin = A0;
const int sampleWindow = 50;
unsigned long previousSensorMillis = 0;
const unsigned long sensorInterval = 10000;
unsigned int maxPeakInInterval = 0;

// LED, Buzzer og PWM-Blæser (Pin 12 fra lab02 - Timer 1, ingen konflikt med tone())
const int ledPinG = 2;
const int ledPinR = 22;
const int buzzerPin = 24;
const int fanPin = 12;

// Blæserhastigheder (0-255, justér frit efter ønsket effekt) & ASHRAE-grænse
const int FAN_PWM_PREVENTIVE = 90;       // Præventiv AI-køling / dashboard "Start blæser"
const int FAN_PWM_CRITICAL   = 180;      // Kraftig køling ved overophedning >= 27.0 C
const float TEMP_MAX_THRESHOLD   = 27.0; // ASHRAE TC 9.9 max temperatur
const float TEMP_RESET_THRESHOLD = 25.5; // Hysterese ved automatisk nedkøling

// LCD: Ben 6, 7, 8, 9, 10, 11
LiquidCrystal lcd(6, 7, 8, 9, 10, 11);

// Keypad: Raekker (31, 33, 35, 37), Kolonner (39, 41, 43, 45)
const byte ROWS = 4;
const byte COLS = 4;
char hexaKeys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {31, 33, 35, 37};
byte colPins[COLS] = {39, 41, 43, 45};
Keypad customKeypad = Keypad(makeKeymap(hexaKeys), rowPins, colPins, ROWS, COLS);

RTC_DS3231 rtc;
bool rtcOk = false;

// Tilstande
bool kortGodkendt = false;
String indtastetKode = "";
String korrektKode = "1984";
String senesteUID = "";
int wrongAttempts = 0;
const int maxAttempts = 3;

bool doorIsOpen = false;
unsigned long doorOpenUntil = 0;
unsigned long tempMsgUntil = 0;

// Blæser-tilstand
bool fanActive = false;
int fanPwmCurrent = 0;
bool fanManualOn = false;
bool tempOverheatLatched = false;

// Non-blocking vedvarende alarm (stopper KUN ved PIN 1984# eller Azure alarm_stop!)
bool alarmActive = false;
unsigned long lastSirenToggleMs = 0;
bool sirenHigh = false;
String alarmPinBuf = "";

String serialBuf = "";

// --- BLÆSERSTYRING (PWM PIN 12) ---
void setFanSpeed(int pwm) {
  if (pwm <= 0) {
    analogWrite(fanPin, 0);
    fanActive = false;
    fanPwmCurrent = 0;
    return;
  }
  if (pwm > 255) pwm = 255;
  // Kort kickstart fra stilstand så DC-blæseren altid starter sikkert
  if (!fanActive && pwm < 180) {
    analogWrite(fanPin, 180);
    delay(120);
  }
  analogWrite(fanPin, pwm);
  fanActive = true;
  fanPwmCurrent = pwm;
}

// --- HJÆLPEFUNKTIONER ---
void wakeRfid() {
  pinMode(RST_PIN, OUTPUT);
  digitalWrite(RST_PIN, HIGH);
  delay(5);
  mfrc522.PCD_Init();
}

String getRtcString() {
  if (!rtcOk) return "no_rtc";
  DateTime now = rtc.now();
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
           now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());
  return String(buf);
}

String getUidHex() {
  String uid = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(mfrc522.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

void visStartSkaerm() {
  lcd.clear();
  lcd.setCursor(3, 0);
  lcd.print("Scan Card");
  lcd.setCursor(4, 1);
  lcd.print(fanActive ? "Fan: ON " : "To Start");
  wakeRfid();
}

void showTempStatus(const String &l1, const String &l2, unsigned long ms) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(l1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd.print(l2.substring(0, 16));
  tempMsgUntil = millis() + ms;
  wakeRfid();
}

void resetToLocked() {
  alarmActive = false;
  alarmPinBuf = "";
  noTone(buzzerPin);
  doorIsOpen = false;
  kortGodkendt = false;
  indtastetKode = "";
  tempMsgUntil = 0;
  digitalWrite(ledPinG, LOW);
  digitalWrite(ledPinR, HIGH);
  visStartSkaerm();
}

void startPersistentAlarm(const String &subtext) {
  if (alarmActive) return; // Allerede i alarm - afbryd ikke evt. PIN-indtastning!
  alarmActive = true;
  alarmPinBuf = "";
  doorIsOpen = false;
  kortGodkendt = false;
  indtastetKode = "";
  tempMsgUntil = 0;
  digitalWrite(ledPinG, LOW);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ALARM ACTIVE!");
  lcd.setCursor(0, 1);
  lcd.print(subtext.substring(0, 16));
}

void disarmLocalAlarm(const String &who) {
  alarmActive = false;
  alarmPinBuf = "";
  wrongAttempts = 0;
  noTone(buzzerPin);
  digitalWrite(ledPinG, LOW);
  digitalWrite(ledPinR, HIGH);
  tone(buzzerPin, 1800, 150);
  showTempStatus("Alarm Disarmed", who, 2500);
  Serial.println("{\"type\":\"access_event\",\"event\":\"alarm_disarmed\"}");
}

void updateAlarmSiren(unsigned long nowMs) {
  if (!alarmActive) return;
  maxPeakInInterval = 0; // Ignorér egen sirene på lydsensoren!
  if (nowMs - lastSirenToggleMs >= 220) {
    lastSirenToggleMs = nowMs;
    sirenHigh = !sirenHigh;
    tone(buzzerPin, sirenHigh ? 2200 : 1200);
    digitalWrite(ledPinR, sirenHigh ? HIGH : LOW);
  }
}

bool tjekUID() {
  if (mfrc522.uid.size != 4) return false;
  for (byte i = 0; i < 4; i++) {
    if (mfrc522.uid.uidByte[i] != gyldigUID[i]) return false;
  }
  return true;
}

void openDoorNonBlocking(const String &l1, const String &l2, unsigned long ms) {
  alarmActive = false;
  alarmPinBuf = "";
  noTone(buzzerPin);
  digitalWrite(ledPinR, LOW);
  digitalWrite(ledPinG, HIGH);
  tone(buzzerPin, 2500, 500);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(l1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd.print(l2.substring(0, 16));
  doorIsOpen = true;
  doorOpenUntil = millis() + ms;
  tempMsgUntil = 0;
  wrongAttempts = 0;
  kortGodkendt = false;
  indtastetKode = "";
}

// --- MODTAG FJERNSTYRING FRA AZURE -> PI ---
void handleIncomingCommand(const String &line) {
  if (line.indexOf("\"alarm_stop\"") >= 0) {
    disarmLocalAlarm("By Azure Auth");
  } else if (line.indexOf("\"alarm_test\"") >= 0) {
    startPersistentAlarm("Code/Azure Stop");
  } else if (line.indexOf("\"unlock_door\"") >= 0) {
    openDoorNonBlocking("Remote Unlocked", "Serverroom open", 8000);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_unlock\"}");
  } else if (line.indexOf("\"lock_door\"") >= 0) {
    resetToLocked();
    tone(buzzerPin, 900, 200);
    showTempStatus("Door Locked", "By Azure Admin", 2000);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_lock\"}");
  } else if (line.indexOf("\"fan_on\"") >= 0) {
    fanManualOn = true;
    int targetPwm = (fanPwmCurrent > FAN_PWM_PREVENTIVE) ? fanPwmCurrent : FAN_PWM_PREVENTIVE;
    setFanSpeed(targetPwm);
    if (!alarmActive) {
      tone(buzzerPin, 1400, 120);
      showTempStatus("Cooling: ON", "Azure / AI Auto", 3000);
    }
  } else if (line.indexOf("\"fan_off\"") >= 0) {
    fanManualOn = false;
    setFanSpeed(0);
    if (!alarmActive) {
      tone(buzzerPin, 900, 120);
      showTempStatus("Cooling: OFF", "Normal mode", 3000);
    }
  } else if (line.indexOf("\"ping\"") >= 0) {
    if (!alarmActive) {
      tone(buzzerPin, 1800, 80);
      showTempStatus("Azure Ping OK", getRtcString().substring(11), 2500);
    }
  } else if (line.indexOf("\"reset_state\"") >= 0) {
    wrongAttempts = 0;
    fanManualOn = false;
    tempOverheatLatched = false;
    setFanSpeed(0);
    lcd.begin(16, 2);
    resetToLocked();
    tone(buzzerPin, 1500, 100);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_reset\"}");
  }
}

void checkSerialFromPi() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      serialBuf.trim();
      if (serialBuf.length() > 0) handleIncomingCommand(serialBuf);
      serialBuf = "";
    } else {
      serialBuf += c;
    }
  }
}

void setup() {
  Serial.begin(115200);
  SPI.begin();

  rtcOk = rtc.begin();
  if (rtcOk && rtc.lostPower()) {
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  }

  pinMode(ledPinG, OUTPUT);
  pinMode(ledPinR, OUTPUT);
  pinMode(buzzerPin, OUTPUT);
  pinMode(fanPin, OUTPUT);
  analogWrite(fanPin, 0);

  lcd.begin(16, 2);
  resetToLocked();
}

void loop() {
  unsigned long currentMillis = millis();

  // 0. Lyt altid efter fjernstyring fra Raspberry Pi / Azure
  checkSerialFromPi();

  // Hold non-blocking sirene i gang hvis alarm er aktiv
  if (alarmActive) {
    updateAlarmSiren(currentMillis);
    // Tillad fysisk afstilling via 1984# på keypaden mens sirenen hyler!
    char ak = customKeypad.getKey();
    if (ak) {
      if (ak == '#') {
        if (alarmPinBuf == korrektKode) {
          disarmLocalAlarm("By Local PIN");
        } else {
          alarmPinBuf = "";
          lcd.setCursor(0, 1);
          lcd.print("Wrong PIN!      ");
        }
      } else if (ak == '*') {
        alarmPinBuf = "";
        lcd.setCursor(0, 1);
        lcd.print("PIN:            ");
      } else if (alarmPinBuf.length() < 4) {
        alarmPinBuf += ak;
        lcd.setCursor(0, 1);
        lcd.print("PIN: ");
        for (unsigned int i = 0; i < alarmPinBuf.length(); i++) lcd.print("*");
        lcd.print("       ");
      }
    }
  } else {
    // Automatisk tilbagevenden til laast startskaerm
    if (doorIsOpen && currentMillis >= doorOpenUntil) {
      resetToLocked();
    }
    if (tempMsgUntil > 0 && currentMillis >= tempMsgUntil && !doorIsOpen && !kortGodkendt) {
      tempMsgUntil = 0;
      visStartSkaerm();
    }
  }

  // --- 1. Lydsensor maaling (kun naar egen sirene ikke hyler) ---
  if (!alarmActive) {
    unsigned long startMillis = millis();
    unsigned int signalMax = 0;
    unsigned int signalMin = 1024;
    while (millis() - startMillis < sampleWindow) {
      unsigned int sample = analogRead(soundAnalogPin);
      if (sample < 1024) {
        if (sample > signalMax) signalMax = sample;
        else if (sample < signalMin) signalMin = sample;
      }
    }
    unsigned int peakToPeak = (signalMax > signalMin) ? (signalMax - signalMin) : 0;
    if (peakToPeak > maxPeakInInterval) maxPeakInInterval = peakToPeak;
  }

  // --- 2. Mål DHT22, tjek lokal overophedning og send JSON telemetri hvert 10. sek ---
  if (currentMillis - previousSensorMillis >= sensorInterval) {
    previousSensorMillis = currentMillis;

    double volts = (maxPeakInInterval * 5.0) / 1024.0;
    if (volts < 0.0005) volts = 0.0005;
    double estimateddB = 20.0 * log10(volts / 0.0005);
    if (estimateddB < 35.0) estimateddB = 35.0;
    if (estimateddB > 100.0) estimateddB = 100.0;

    int status = mySensor.read();
    bool dhtSuccess = (status == DHTLIB_OK);
    float tempVal = 0.0;
    float humVal = 0.0;

    if (dhtSuccess) {
      tempVal = mySensor.getTemperature();
      humVal = mySensor.getHumidity();

      // Lokal Edge Fail-Safe: Ved overophedning (>= 27.0 C) tænd blæser + alarm med det samme!
      if (tempVal >= TEMP_MAX_THRESHOLD) {
        if (!tempOverheatLatched) {
          tempOverheatLatched = true;
          setFanSpeed(FAN_PWM_CRITICAL);
          startPersistentAlarm("OVERHEAT! >27C");
          Serial.println("{\"type\":\"access_event\",\"event\":\"local_overheat_alarm\"}");
        }
      } else if (tempVal <= TEMP_RESET_THRESHOLD && tempOverheatLatched) {
        tempOverheatLatched = false;
        if (!fanManualOn) {
          setFanSpeed(0);
          if (!alarmActive && !doorIsOpen && !kortGodkendt) visStartSkaerm();
        }
      }
    }

    Serial.print("{\"type\":\"telemetry\",\"zone\":\"rack1\",\"temperature\":");
    if (dhtSuccess) Serial.print(tempVal, 2);
    else Serial.print("null");
    Serial.print(",\"humidity\":");
    if (dhtSuccess) Serial.print(humVal, 2);
    else Serial.print("null");
    Serial.print(",\"noise_db\":");
    Serial.print(estimateddB, 1);
    Serial.print(",\"fan\":");
    Serial.print(fanActive ? 1 : 0);
    Serial.print(",\"rtc\":\"");
    Serial.print(getRtcString());
    Serial.println("\"}");

    maxPeakInInterval = 0;
  }

  // --- 3. Normal 2FA Adgangskontrol (naar alarm ikke er aktiv) ---
  if (!alarmActive) {
    if (!kortGodkendt && !doorIsOpen) {
      if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
        senesteUID = getUidHex();
        if (tjekUID()) {
          tone(buzzerPin, 2000, 200);
          kortGodkendt = true;
          lcd.clear();
          lcd.setCursor(1, 0);
          lcd.print("Card Accepted!");
          delay(1000);
          lcd.clear();
          lcd.setCursor(2, 0);
          lcd.print("Enter Code");
        } else {
          tone(buzzerPin, 300, 500);
          Serial.print("{\"type\":\"access_request\",\"credential\":\"");
          Serial.print(senesteUID);
          Serial.println("\",\"method\":\"rfid_invalid\"}");
          lcd.clear();
          lcd.setCursor(1, 0);
          lcd.print("Invalid Card!");
          delay(2000);
          visStartSkaerm();
        }
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
      }
    } else if (kortGodkendt) {
      char key = customKeypad.getKey();
      if (key) {
        if (key == '#') {
          Serial.print("{\"type\":\"access_request\",\"credential\":\"");
          Serial.print(senesteUID);
          Serial.print(":");
          Serial.print(indtastetKode);
          Serial.println("\",\"method\":\"rfid_2fa\"}");

          if (indtastetKode == korrektKode) {
            openDoorNonBlocking("Access Granted!", "Serverroom open", 15000);
            Serial.println("{\"type\":\"access_event\",\"event\":\"door_unlocked\"}");
          } else {
            wrongAttempts++;
            tone(buzzerPin, 400, 300);
            lcd.clear();
            lcd.setCursor(1, 0);
            lcd.print("Wrong Code!");
            lcd.setCursor(2, 1);
            lcd.print("Attempts: "); lcd.print(wrongAttempts);
            delay(2000);

            if (wrongAttempts >= maxAttempts) {
              Serial.println("{\"type\":\"access_event\",\"event\":\"local_bruteforce_alarm\"}");
              wrongAttempts = 0;
              startPersistentAlarm("Enter PIN / Web");
            } else {
              digitalWrite(ledPinR, HIGH);
              lcd.clear();
              lcd.setCursor(2, 0);
              lcd.print("Enter Code");
            }
          }
          indtastetKode = "";
        } else if (key == '*') {
          indtastetKode = "";
          lcd.setCursor(0, 1);
          lcd.print("                ");
        } else {
          if (indtastetKode.length() < 4) {
            indtastetKode += key;
            lcd.setCursor(6 + indtastetKode.length() - 1, 1);
            lcd.print("*");
          }
        }
      }
    }
  }
}
