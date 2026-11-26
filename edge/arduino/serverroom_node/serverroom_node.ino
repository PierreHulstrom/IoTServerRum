/* =========================================================================
 * Server Room IoT - Elegoo / Arduino Mega 2560 Edge Node
 *
 * Capabilities:
 * - Reads DHT22 (temp/humidity), analog sound sensor (peak-to-peak dB), and DS3231 RTC.
 * - Sends JSON telemetry to Raspberry Pi -> Azure MQTTS every 10 seconds (115200 baud).
 * - Local 2FA door access control: RC522 RFID card + 4x4 Keypad PIN ("1984#").
 * - Persistent non-blocking alarm (ALL alarms require manual disarm via PIN 1984# or Azure).
 * - PWM cooling fan on Pin 12 with soft-start (AI preventive + local >= 27 C fail-safe;
 *   auto-stops when temp drops < 27 C; manual remote override from Dashboard).
 * - HD44780 LCD auto-resync to prevent garbled characters after motor/buzzer power spikes.
 * ========================================================================= */
#include <Keypad.h>
#include <dhtnew.h>
#include <Wire.h>
#include <RTClib.h>
#include <LiquidCrystal.h>
#include <SPI.h>
#include <MFRC522.h>

// --- RFID-RC522 (SPI pins 50-53; RST on Pin 5 to avoid LCD pins 6-11) ---
#define RST_PIN 5
#define SS_PIN  53
MFRC522 mfrc522(SS_PIN, RST_PIN);

// Authorized local fallback RFID card UID
byte gyldigUID[] = { 0xF1, 0xEF, 0xBE, 0x53 };

// --- Environmental sensors: DHT22 (Pin 48) & Analog sound sensor (A0) ---
DHTNEW mySensor(48);
const int soundAnalogPin = A0;
const int sampleWindow = 50;                 // Sound sampling window in ms
unsigned long previousSensorMillis = 0;
const unsigned long sensorInterval = 10000;  // Telemetry interval: 10 seconds
unsigned int maxPeakInInterval = 0;

// --- Actuators: Status LEDs, Passive Buzzer (Timer 2), PWM Fan (Pin 12, Timer 1) ---
const int ledPinG = 2;
const int ledPinR = 22;
const int buzzerPin = 24;
const int fanPin = 12;

// --- Cooling PWM speeds (0-255) & ASHRAE TC 9.9 max temperature ---
const int FAN_PWM_PREVENTIVE = 90;       // Preventive AI cooling / manual dashboard "fan_on"
const int FAN_PWM_CRITICAL   = 180;      // High-speed cooling when temp >= 27.0 C
const float TEMP_MAX_THRESHOLD = 27.0;   // Overheating threshold in Celsius

// --- 16x2 LCD in 4-bit parallel mode (Pins 6-11) ---
LiquidCrystal lcd(6, 7, 8, 9, 10, 11);

// --- 4x4 Matrix Keypad (Rows 31-37, Cols 39-45) ---
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

// --- DS3231 Real-Time Clock (I2C pins 20/21) ---
RTC_DS3231 rtc;
bool rtcOk = false;

// --- Access control state ---
bool kortGodkendt = false;
String indtastetKode = "";
String korrektKode = "1984";
String senesteUID = "";
int wrongAttempts = 0;
const int maxAttempts = 3;

bool doorIsOpen = false;
unsigned long doorOpenUntil = 0;
unsigned long tempMsgUntil = 0;

// --- Cooling fan state (separates manual dashboard control from automatic AI/DHT control) ---
bool fanActive = false;
int fanPwmCurrent = 0;
bool fanManualOn = false;
bool fanAutoOn = false;
bool localTempHigh = false;

// --- Persistent alarm state (ONLY stopped manually via PIN 1984# or Azure alarm_stop) ---
bool alarmActive = false;
bool tempAlarmMutedWhileHot = false;
unsigned long lastSirenToggleMs = 0;
bool sirenHigh = false;
String alarmPinBuf = "";

// Buffer for incoming newline-delimited JSON commands from Raspberry Pi
String serialBuf = "";

// --- Re-initialize LCD before printing to clear any HD44780 4-bit glitches from power spikes ---
void lcdWriteSafe(const String &l1, const String &l2) {
  lcd.begin(16, 2);
  delay(5);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(l1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd.print(l2.substring(0, 16));
}

// --- Set PWM fan speed on Pin 12 using a gentle soft-start ramp to prevent 5V rail dips ---
void setFanSpeed(int pwm) {
  if (pwm <= 0) {
    analogWrite(fanPin, 0);
    fanActive = false;
    fanPwmCurrent = 0;
    return;
  }
  if (pwm > 255) pwm = 255;
  if (!fanActive) {
    int step1 = (pwm > 60) ? 60 : pwm;
    int step2 = (pwm > 120) ? 120 : pwm;
    analogWrite(fanPin, step1);
    delay(25);
    analogWrite(fanPin, step2);
    delay(25);
  }
  analogWrite(fanPin, pwm);
  fanActive = true;
  fanPwmCurrent = pwm;
}

// --- Resolve final fan speed from local overheat, AI auto-cooling, and manual override flags ---
void syncFanState() {
  if (localTempHigh) {
    setFanSpeed(FAN_PWM_CRITICAL);
  } else if (fanAutoOn || fanManualOn) {
    setFanSpeed(FAN_PWM_PREVENTIVE);
  } else {
    setFanSpeed(0);
  }
}

// --- Re-initialize RC522 RFID reader after state transitions so card scans stay responsive ---
void wakeRfid() {
  pinMode(RST_PIN, OUTPUT);
  digitalWrite(RST_PIN, HIGH);
  delay(5);
  mfrc522.PCD_Init();
}

// --- Format current DS3231 RTC date/time as "YYYY-MM-DD HH:MM:SS" ---
String getRtcString() {
  if (!rtcOk) return "no_rtc";
  DateTime now = rtc.now();
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
           now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());
  return String(buf);
}

// --- Convert the scanned RFID UID bytes to an uppercase hex string (e.g. "F1EFBE53") ---
String getUidHex() {
  String uid = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(mfrc522.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  return uid;
}

// --- Display idle welcome screen (also indicates when the cooling fan is running) ---
void visStartSkaerm() {
  lcdWriteSafe("   Scan Card", fanActive ? "    Fan: ON" : "    To Start");
  wakeRfid();
}

// --- Show a temporary 2-line status message for `ms` milliseconds, then return to idle ---
void showTempStatus(const String &l1, const String &l2, unsigned long ms) {
  lcdWriteSafe(l1, l2);
  tempMsgUntil = millis() + ms;
  wakeRfid();
}

// --- Return door and access state to locked (Red LED ON, Green LED OFF) ---
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

// --- Start latched non-blocking alarm (stays active until PIN 1984# or Azure alarm_stop) ---
void startPersistentAlarm(const String &subtext) {
  if (alarmActive) return;  // Already sounding: do not interrupt an ongoing keypad PIN entry
  alarmActive = true;
  alarmPinBuf = "";
  doorIsOpen = false;
  kortGodkendt = false;
  indtastetKode = "";
  tempMsgUntil = 0;
  digitalWrite(ledPinG, LOW);
  // Start buzzer first, let 5V rail settle for 20ms, then resync LCD for clean text
  tone(buzzerPin, 2200);
  digitalWrite(ledPinR, HIGH);
  sirenHigh = true;
  lastSirenToggleMs = millis();
  delay(20);
  lcdWriteSafe("ALARM ACTIVE!", subtext);
}

// --- Manually disarm active alarm (fan keeps cooling if temperature is still >= 27 C) ---
void disarmLocalAlarm(const String &who) {
  if (localTempHigh) {
    tempAlarmMutedWhileHot = true;  // Prevent immediate re-trigger while room is still cooling down
  }
  alarmActive = false;
  alarmPinBuf = "";
  wrongAttempts = 0;
  noTone(buzzerPin);
  digitalWrite(ledPinG, LOW);
  digitalWrite(ledPinR, HIGH);
  tone(buzzerPin, 1800, 150);
  delay(15);
  showTempStatus("Alarm Disarmed", who, 2500);
  Serial.println("{\"type\":\"access_event\",\"event\":\"alarm_disarmed\"}");
}

// --- Toggle siren frequency (1200/2200 Hz) and Red LED every 220ms without blocking loop() ---
void updateAlarmSiren(unsigned long nowMs) {
  if (!alarmActive) return;
  maxPeakInInterval = 0;  // Ignore own siren on the sound sensor to prevent feedback loops
  if (nowMs - lastSirenToggleMs >= 220) {
    lastSirenToggleMs = nowMs;
    sirenHigh = !sirenHigh;
    tone(buzzerPin, sirenHigh ? 2200 : 1200);
    digitalWrite(ledPinR, sirenHigh ? HIGH : LOW);
  }
}

// --- Compare scanned 4-byte RFID UID against the local authorized card UID ---
bool tjekUID() {
  if (mfrc522.uid.size != 4) return false;
  for (byte i = 0; i < 4; i++) {
    if (mfrc522.uid.uidByte[i] != gyldigUID[i]) return false;
  }
  return true;
}

// --- Unlock door non-blocking (Green LED ON) for `ms` milliseconds, then auto-relock ---
void openDoorNonBlocking(const String &l1, const String &l2, unsigned long ms) {
  alarmActive = false;
  alarmPinBuf = "";
  noTone(buzzerPin);
  digitalWrite(ledPinR, LOW);
  digitalWrite(ledPinG, HIGH);
  tone(buzzerPin, 2500, 500);
  delay(15);
  lcdWriteSafe(l1, l2);
  doorIsOpen = true;
  doorOpenUntil = millis() + ms;
  tempMsgUntil = 0;
  wrongAttempts = 0;
  kortGodkendt = false;
  indtastetKode = "";
}

// --- Execute compact JSON remote commands received from Azure -> Raspberry Pi ---
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
  } else if (line.indexOf("\"fan_auto_off\"") >= 0) {
    // AI reports normal temperature -> stop auto fan (keeps running if manually enabled)
    fanAutoOn = false;
    syncFanState();
    if (!alarmActive && !fanActive) {
      showTempStatus("AI Cooling: OFF", "Temp normal", 2500);
    }
  } else if (line.indexOf("\"fan_auto\"") >= 0) {
    // AI predicts overheating or breach -> activate preventive cooling on Pin 12
    fanAutoOn = true;
    syncFanState();
    if (!alarmActive) {
      tone(buzzerPin, 1400, 120);
      delay(15);
      showTempStatus("AI Cooling: ON", "Preventive Fan", 2500);
    }
  } else if (line.indexOf("\"fan_on\"") >= 0) {
    // Manual dashboard override: turn cooling fan ON
    fanManualOn = true;
    syncFanState();
    if (!alarmActive) {
      tone(buzzerPin, 1400, 120);
      delay(15);
      showTempStatus("Cooling: ON", "Manual Remote", 2500);
    }
  } else if (line.indexOf("\"fan_off\"") >= 0) {
    // Manual dashboard override: force cooling fan OFF
    fanManualOn = false;
    fanAutoOn = false;
    localTempHigh = false;
    setFanSpeed(0);
    if (!alarmActive) {
      tone(buzzerPin, 900, 120);
      delay(15);
      showTempStatus("Cooling: OFF", "Normal mode", 2500);
    }
  } else if (line.indexOf("\"ping\"") >= 0) {
    if (!alarmActive) {
      tone(buzzerPin, 1800, 80);
      showTempStatus("Azure Ping OK", getRtcString().substring(11), 2500);
    }
  } else if (line.indexOf("\"reset_state\"") >= 0) {
    // Full software reset of alarm, fan, and access states
    wrongAttempts = 0;
    fanManualOn = false;
    fanAutoOn = false;
    localTempHigh = false;
    tempAlarmMutedWhileHot = false;
    setFanSpeed(0);
    resetToLocked();
    tone(buzzerPin, 1500, 100);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_reset\"}");
  }
}

// --- Non-blocking USB Serial reader for newline-terminated commands from Raspberry Pi ---
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

// --- Arduino boot initialization ---
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
  analogWrite(fanPin, 0);  // Ensure fan starts OFF

  resetToLocked();
}

// --- Main non-blocking control loop ---
void loop() {
  unsigned long currentMillis = millis();

  // 0. Always check for incoming remote commands from Raspberry Pi / Azure
  checkSerialFromPi();

  // Handle active siren and allow local manual disarm via PIN 1984# on keypad
  if (alarmActive) {
    updateAlarmSiren(currentMillis);
    char ak = customKeypad.getKey();
    if (ak) {
      if (ak == '#') {
        if (alarmPinBuf == korrektKode) {
          disarmLocalAlarm("By Local PIN");
        } else {
          alarmPinBuf = "";
          lcdWriteSafe("ALARM ACTIVE!", "Wrong PIN!");
        }
      } else if (ak == '*') {
        alarmPinBuf = "";
        lcdWriteSafe("ALARM ACTIVE!", "PIN: ");
      } else if (alarmPinBuf.length() < 4) {
        alarmPinBuf += ak;
        String mask = "PIN: ";
        for (unsigned int i = 0; i < alarmPinBuf.length(); i++) mask += "*";
        lcdWriteSafe("ALARM ACTIVE!", mask);
      }
    }
  } else {
    // Auto-relock door after open timeout and clear temporary LCD banners
    if (doorIsOpen && currentMillis >= doorOpenUntil) {
      resetToLocked();
    }
    if (tempMsgUntil > 0 && currentMillis >= tempMsgUntil && !doorIsOpen && !kortGodkendt) {
      tempMsgUntil = 0;
      visStartSkaerm();
    }
  }

  // 1. Sample analog sound sensor peak-to-peak amplitude (skipped while own siren sounds)
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

  // 2. Every 10 seconds: read DHT22, enforce local overheat fail-safe, and emit JSON telemetry
  if (currentMillis - previousSensorMillis >= sensorInterval) {
    previousSensorMillis = currentMillis;

    // Convert peak-to-peak ADC reading to estimated dB (clamped to 35-100 dB)
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

      // Local Edge Fail-Safe (works even if Wi-Fi/Azure drops):
      // - temp >= 27.0 C -> start full-speed fan + latched alarm (requires manual disarm)
      // - temp <  27.0 C -> auto-stop fan only (alarm stays active until manually disarmed)
      if (tempVal >= TEMP_MAX_THRESHOLD) {
        if (!localTempHigh) {
          localTempHigh = true;
          fanAutoOn = true;
          syncFanState();
          if (!tempAlarmMutedWhileHot) {
            startPersistentAlarm("OVERHEAT! >27C");
            Serial.println("{\"type\":\"access_event\",\"event\":\"local_overheat_alarm\"}");
          }
        }
      } else {
        tempAlarmMutedWhileHot = false;
        if (localTempHigh) {
          localTempHigh = false;
          fanAutoOn = false;
          syncFanState();
          if (!alarmActive && !doorIsOpen && !kortGodkendt) visStartSkaerm();
        }
      }
    }

    // Stream JSON telemetry line to Raspberry Pi over USB Serial
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

  // 3. Normal physical 2FA access control (RFID card first, then 4-digit PIN + #)
  if (!alarmActive) {
    if (!kortGodkendt && !doorIsOpen) {
      if (mfrc522.PICC_IsNewCardPresent() && mfrc522.PICC_ReadCardSerial()) {
        senesteUID = getUidHex();
        if (tjekUID()) {
          tone(buzzerPin, 2000, 200);
          kortGodkendt = true;
          lcdWriteSafe(" Card Accepted!", "");
          delay(1000);
          lcdWriteSafe("   Enter Code", "");
        } else {
          // Invalid RFID card: beep, log to Azure for brute-force tracking, and reset
          tone(buzzerPin, 300, 500);
          Serial.print("{\"type\":\"access_request\",\"credential\":\"");
          Serial.print(senesteUID);
          Serial.println("\",\"method\":\"rfid_invalid\"}");
          lcdWriteSafe(" Invalid Card!", "");
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
          // Send combined UID:PIN to Azure for centralized SHA-256 verification & audit logging
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
            lcdWriteSafe("  Wrong Code!", "  Attempts: " + String(wrongAttempts));
            delay(2000);

            // 3 consecutive wrong PIN attempts -> trigger persistent intruder alarm
            if (wrongAttempts >= maxAttempts) {
              Serial.println("{\"type\":\"access_event\",\"event\":\"local_bruteforce_alarm\"}");
              wrongAttempts = 0;
              startPersistentAlarm("Enter PIN / Web");
            } else {
              digitalWrite(ledPinR, HIGH);
              lcdWriteSafe("   Enter Code", "");
            }
          }
          indtastetKode = "";
        } else if (key == '*') {
          // Clear current PIN entry
          indtastetKode = "";
          lcdWriteSafe("   Enter Code", "");
        } else {
          if (indtastetKode.length() < 4) {
            indtastetKode += key;
            String mask = "      ";
            for (unsigned int i = 0; i < indtastetKode.length(); i++) mask += "*";
            lcdWriteSafe("   Enter Code", mask);
          }
        }
      }
    }
  }
}
