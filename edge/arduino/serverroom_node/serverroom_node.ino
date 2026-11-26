/* =========================================================================
 * Serverrum IoT – Elegoo / Arduino Mega 2560 (Azure + Pi + Lokal 2FA)
 * ========================================================================= */
#include <Keypad.h>
#include <dhtnew.h>
#include <Wire.h>
#include <RTClib.h>
#include <LiquidCrystal.h>
#include <SPI.h>
#include <MFRC522.h>

/* =========================================================================
 * Hardware & Sensorer (Holdets fysiske pins – nul konflikter!)
 * ========================================================================= */
#define RST_PIN 5
#define SS_PIN  53
MFRC522 mfrc522(SS_PIN, RST_PIN);

byte gyldigUID[] = { 0xF1, 0xEF, 0xBE, 0x53 };

// DHT22 Sensor (Digital Pin 48)
DHTNEW mySensor(48);

// Lydsensor (Analog udgang A0)
const int soundAnalogPin = A0;
const int sampleWindow = 50;
unsigned long previousSensorMillis = 0;
const unsigned long sensorInterval = 10000;
unsigned int maxPeakInInterval = 0;

// LED og Buzzer pins
const int ledPinG = 2;
const int ledPinR = 22;
const int buzzerPin = 24;

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

// DS3231 RTC-modul (I2C: Pin 20/21)
RTC_DS3231 rtc;
bool rtcOk = false;

// Tilstand og pinkode
bool kortGodkendt = false;
String indtastetKode = "";
String korrektKode = "1984";
String senesteUID = "";

int wrongAttempts = 0;
const int maxAttempts = 3;

bool doorIsOpen = false;
unsigned long doorOpenUntil = 0;
unsigned long tempMsgUntil = 0;
String serialBuf = "";

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
  lcd.print("To Start");
  wakeRfid();
}

void showTempStatus(const String &l1, const String &l2, unsigned long ms) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(l1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd
cat << 'EOF' > /opt/serverroom-iot/edge/arduino/serverroom_node/serverroom_node.ino
/* =========================================================================
 * Serverrum IoT – Elegoo / Arduino Mega 2560 (Azure + Pi + Lokal 2FA)
 * ========================================================================= */
#include <Keypad.h>
#include <dhtnew.h>
#include <Wire.h>
#include <RTClib.h>
#include <LiquidCrystal.h>
#include <SPI.h>
#include <MFRC522.h>

/* =========================================================================
 * Hardware & Sensorer (Holdets fysiske pins – nul konflikter!)
 * ========================================================================= */
#define RST_PIN 5
#define SS_PIN  53
MFRC522 mfrc522(SS_PIN, RST_PIN);

byte gyldigUID[] = { 0xF1, 0xEF, 0xBE, 0x53 };

// DHT22 Sensor (Digital Pin 48)
DHTNEW mySensor(48);

// Lydsensor (Analog udgang A0)
const int soundAnalogPin = A0;
const int sampleWindow = 50;
unsigned long previousSensorMillis = 0;
const unsigned long sensorInterval = 10000;
unsigned int maxPeakInInterval = 0;

// LED og Buzzer pins
const int ledPinG = 2;
const int ledPinR = 22;
const int buzzerPin = 24;

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

// DS3231 RTC-modul (I2C: Pin 20/21)
RTC_DS3231 rtc;
bool rtcOk = false;

// Tilstand og pinkode
bool kortGodkendt = false;
String indtastetKode = "";
String korrektKode = "1984";
String senesteUID = "";

int wrongAttempts = 0;
const int maxAttempts = 3;

bool doorIsOpen = false;
unsigned long doorOpenUntil = 0;
unsigned long tempMsgUntil = 0;
String serialBuf = "";

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
  lcd.print("To Start");
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
  noTone(buzzerPin);
  doorIsOpen = false;
  kortGodkendt = false;
  indtastetKode = "";
  tempMsgUntil = 0;
  digitalWrite(ledPinG, LOW);
  digitalWrite(ledPinR, HIGH);
  visStartSkaerm();
}

bool tjekUID() {
  if (mfrc522.uid.size != 4) return false;
  for (byte i = 0; i < 4; i++) {
    if (mfrc522.uid.uidByte[i] != gyldigUID[i]) return false;
  }
  return true;
}

void triggerSiren(int loops) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ALARM: LOCKED!");
  for (int alarmLoop = 0; alarmLoop < loops; alarmLoop++) {
    for (int hz = 1000; hz <= 2500; hz += 100) {
      tone(buzzerPin, hz);
      digitalWrite(ledPinR, HIGH);
      delay(25);
    }
    for (int hz = 2500; hz >= 1000; hz -= 100) {
      tone(buzzerPin, hz);
      digitalWrite(ledPinR, LOW);
      delay(25);
    }
  }
  resetToLocked();
}

void openDoorNonBlocking(const String &l1, const String &l2, unsigned long ms) {
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
  if (line.indexOf("\"unlock_door\"") >= 0) {
    openDoorNonBlocking("Remote Unlocked", "Serverroom open", 8000);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_unlock\"}");
  } else if (line.indexOf("\"lock_door\"") >= 0) {
    tone(buzzerPin, 600, 150);
    resetToLocked();
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_lock\"}");
  } else if (line.indexOf("\"fan_on\"") >= 0) {
    tone(buzzerPin, 1400, 120);
    showTempStatus("Cooling: ON", "Azure / AI Auto", 3000);
  } else if (line.indexOf("\"fan_off\"") >= 0) {
    tone(buzzerPin, 900, 120);
    showTempStatus("Cooling: OFF", "Normal mode", 3000);
  } else if (line.indexOf("\"alarm_test\"") >= 0) {
    triggerSiren(6);
  } else if (line.indexOf("\"ping\"") >= 0) {
    tone(buzzerPin, 1800, 80);
    showTempStatus("Azure Ping OK", getRtcString().substring(11), 2500);
  } else if (line.indexOf("\"reset_state\"") >= 0) {
    wrongAttempts = 0;
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

  lcd.begin(16, 2);
  resetToLocked();
}

void loop() {
  unsigned long currentMillis = millis();

  // 0. Lyt altid efter fjernstyring fra Raspberry Pi / Azure
  checkSerialFromPi();

  // Automatisk tilbagevenden til laast startskaerm
  if (doorIsOpen && currentMillis >= doorOpenUntil) {
    resetToLocked();
  }
  if (tempMsgUntil > 0 && currentMillis >= tempMsgUntil && !doorIsOpen && !kortGodkendt) {
    tempMsgUntil = 0;
    visStartSkaerm();
  }

  // --- 1. Lydsensor maaling ---
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

  // --- 2. Send JSON telemetri til Raspberry Pi -> Azure ---
  if (currentMillis - previousSensorMillis >= sensorInterval) {
    previousSensorMillis = currentMillis;

    double volts = (maxPeakInInterval * 5.0) / 1024.0;
    if (volts < 0.0005) volts = 0.0005;
    double estimateddB = 20.0 * log10(volts / 0.0005);
    if (estimateddB < 35.0) estimateddB = 35.0;
    if (estimateddB > 100.0) estimateddB = 100.0;

    int status = mySensor.read();
    bool dhtSuccess = (status == DHTLIB_OK);

    Serial.print("{\"type\":\"telemetry\",\"zone\":\"rack1\",\"temperature\":");
    if (dhtSuccess) Serial.print(mySensor.getTemperature(), 2);
    else Serial.print("null");
    Serial.print(",\"humidity\":");
    if (dhtSuccess) Serial.print(mySensor.getHumidity(), 2);
    else Serial.print("null");
    Serial.print(",\"noise_db\":");
    Serial.print(estimateddB, 1);
    Serial.print(",\"rtc\":\"");
    Serial.print(getRtcString());
    Serial.println("\"}");

    maxPeakInInterval = 0;
  }

  // --- 3. Adgangskontrol (RFID foerst, derefter Keypad) ---
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
            triggerSiren(15);
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
