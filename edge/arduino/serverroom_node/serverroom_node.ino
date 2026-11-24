#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <RTClib.h>
#include <DHT.h>
#include <Keypad.h>
#include <LiquidCrystal.h>

// --- PIN-KONFIGURATION (Arduino Mega 2560) ---
#define DHT_PIN       2
#define DHT_TYPE      DHT22
#define SOUND_PIN     A0

#define LED_GREEN     40
#define LED_YELLOW    41
#define LED_RED       42
#define BUZZER_PIN    44

#define RFID_SS       53
#define RFID_RST      49

// LCD 1602 (4-bit parallel med potentiometer på V0)
LiquidCrystal lcd(22, 23, 24, 25, 26, 27);

// Sensorer & RTC
DHT dht(DHT_PIN, DHT_TYPE);
RTC_DS3231 rtc;
MFRC522 rfid(RFID_SS, RFID_RST);
bool rtcOk = false;

// 4x4 Keypad
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {30, 31, 32, 33};
byte colPins[COLS] = {34, 35, 36, 37};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// Tilstand & timere (non-blocking)
unsigned long lastTelemetryMs = 0;
const unsigned long TELEMETRY_INTERVAL = 5000;

String scannedUid = "";
String enteredPin = "";
unsigned long accessModeUntil = 0;
unsigned long messageUntil = 0;

bool fanActive = false;
float lastTemp = 22.0;
float lastHum = 45.0;
float lastNoise = 45.0;

String serialBuf = "";

// --- HJÆLPEFUNKTIONER ---
void setLeds(bool g, bool y, bool r) {
  digitalWrite(LED_GREEN,  g ? HIGH : LOW);
  digitalWrite(LED_YELLOW, y ? HIGH : LOW);
  digitalWrite(LED_RED,    r ? HIGH : LOW);
}

void beep(int freq, int ms) {
  tone(BUZZER_PIN, freq, ms);
}

void showLcdTemp(const String &line1, const String &line2, unsigned long holdMs = 3500) {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(line1.substring(0, 16));
  lcd.setCursor(0, 1);
  lcd.print(line2.substring(0, 16));
  messageUntil = millis() + holdMs;
}

String getRtcString() {
  if (!rtcOk) return "no_rtc";
  DateTime now = rtc.now();
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
           now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());
  return String(buf);
}

float readNoiseDb() {
  unsigned long start = millis();
  int sigMax = 0;
  int sigMin = 1023;
  while (millis() - start < 50) {
    int sample = analogRead(SOUND_PIN);
    if (sample > sigMax) sigMax = sample;
    if (sample < sigMin) sigMin = sample;
  }
  int peakToPeak = sigMax - sigMin;
  float db = 35.0 + (peakToPeak / 1023.0) * 65.0;
  if (db < 35.0) db = 35.0;
  if (db > 100.0) db = 100.0;
  return db;
}

void updateEnvDisplayAndLeds() {
  if (millis() < messageUntil || scannedUid.length() > 0 || enteredPin.length() > 0) return;

  lcd.setCursor(0, 0);
  lcd.print("T:");
  lcd.print(lastTemp, 1);
  lcd.print("C H:");
  lcd.print((int)lastHum);
  lcd.print("%    ");

  lcd.setCursor(0, 1);
  lcd.print("S:");
  lcd.print((int)lastNoise);
  lcd.print("dB ");
  lcd.print(fanActive ? "FAN:ON " : "OK     ");

  if (lastTemp > 27.0 || lastTemp < 18.0 || lastNoise > 75.0) {
    setLeds(false, false, true);
  } else if (lastTemp > 25.0 || lastNoise > 68.0 || fanActive) {
    setLeds(false, true, false);
  } else {
    setLeds(true, false, false);
  }
}

void sendTelemetry() {
  float h = dht.readHumidity();
  float t = dht.readTemperature();
  float n = readNoiseDb();

  if (!isnan(t)) lastTemp = t;
  if (!isnan(h)) lastHum = h;
  lastNoise = n;

  Serial.print("{\"type\":\"telemetry\",\"zone\":\"rack1\",\"temperature\":");
  Serial.print(lastTemp, 2);
  Serial.print(",\"humidity\":");
  Serial.print(lastHum, 2);
  Serial.print(",\"noise_db\":");
  Serial.print(lastNoise, 1);
  Serial.print(",\"rtc\":\"");
  Serial.print(getRtcString());
  Serial.println("\"}");

  updateEnvDisplayAndLeds();
}

void sendAccessRequest(const String &cred, const String &method) {
  Serial.print("{\"type\":\"access_request\",\"credential\":\"");
  Serial.print(cred);
  Serial.print("\",\"method\":\"");
  Serial.print(method);
  Serial.print("\",\"rtc\":\"");
  Serial.print(getRtcString());
  Serial.println("\"}");

  showLcdTemp("Tjekker adgang..", "Vent et oejeblik", 4000);
}

void checkRfid() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) return;

  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  scannedUid = uid;
  enteredPin = "";
  accessModeUntil = millis() + 15000;

  setLeds(false, true, false);
  beep(1400, 120);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Kort:" + uid.substring(0, 11));
  lcd.setCursor(0, 1);
  lcd.print("Tast PIN + #");

  Serial.println("RFID_SCANNED_UID=" + uid);
}

void checkKeypad() {
  char k = keypad.getKey();
  if (!k) return;

  beep(1000, 40);
  accessModeUntil = millis() + 15000;

  if (k == '*') {
    scannedUid = "";
    enteredPin = "";
    showLcdTemp("Nulstillet", "Scan kort / PIN", 1500);
    return;
  }

  if (k == '#') {
    if (scannedUid.length() > 0 && enteredPin.length() > 0) {
      sendAccessRequest(scannedUid + ":" + enteredPin, "rfid_2fa");
    } else if (scannedUid.length() > 0) {
      sendAccessRequest(scannedUid, "rfid_only");
    } else if (enteredPin.length() > 0) {
      sendAccessRequest(enteredPin, "pin_only");
    }
    scannedUid = "";
    enteredPin = "";
    return;
  }

  if (enteredPin.length() < 8) {
    enteredPin += k;
    setLeds(false, true, false);
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print(scannedUid.length() > 0 ? "2FA PIN + #" : "Tast PIN + #");
    lcd.setCursor(0, 1);
    for (unsigned int i = 0; i < enteredPin.length(); i++) lcd.print("*");
  }
}

void handleIncomingLine(const String &line) {
  if (line.indexOf("\"access_response\"") >= 0) {
    bool granted = line.indexOf("\"granted\": true") >= 0 || line.indexOf("\"granted\":true") >= 0;
    if (granted) {
      setLeds(true, false, false);
      beep(1800, 120); delay(150); beep(2400, 180);
      showLcdTemp("ADGANG GODKENDT", "Velkommen!", 5000);
      Serial.println("{\"type\":\"access_event\",\"event\":\"door_unlocked\"}");
    } else {
      setLeds(false, false, true);
      beep(350, 600);
      showLcdTemp("ADGANG AFVIST!", "Ugyldigt kort/PIN", 4000);
    }
    return;
  }

  if (line.indexOf("\"unlock_door\"") >= 0) {
    setLeds(true, false, false);
    beep(1800, 120); delay(150); beep(2400, 180);
    showLcdTemp("FJERN-OPLAAST", "Doer aaben (5s)", 5000);
    Serial.println("{\"type\":\"access_event\",\"event\":\"remote_unlock\"}");
  } else if (line.indexOf("\"lock_door\"") >= 0) {
    setLeds(false, false, true);
    beep(600, 150);
    showLcdTemp("DOER LAAST", "Sikret via Azure", 3000);
  } else if (line.indexOf("\"fan_on\"") >= 0) {
    fanActive = true;
    setLeds(false, true, false);
    beep(1200, 100);
    showLcdTemp("KOELING: TAENDT", "Fjernstyret", 3000);
  } else if (line.indexOf("\"fan_off\"") >= 0) {
    fanActive = false;
    beep(800, 100);
    showLcdTemp("KOELING: SLUKKET", "Normal drift", 3000);
  } else if (line.indexOf("\"alarm_test\"") >= 0) {
    setLeds(false, false, true);
    showLcdTemp("ALARM TEST!", "Fjernstyret", 3500);
    for (int i = 0; i < 4; i++) {
      beep(2000, 200); delay(250);
      beep(900, 200);  delay(250);
    }
  } else if (line.indexOf("\"ping\"") >= 0) {
    beep(1600, 80);
    showLcdTemp("AZURE PING OK", getRtcString().substring(11), 2500);
  }
}

void checkSerial() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      serialBuf.trim();
      if (serialBuf.length() > 0) handleIncomingLine(serialBuf);
      serialBuf = "";
    } else {
      serialBuf += c;
    }
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_YELLOW, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);

  lcd.begin(16, 2);
  showLcdTemp("Serverrum IoT", "Starter op...", 2000);

  dht.begin();
  SPI.begin();
  rfid.PCD_Init();

  rtcOk = rtc.begin();
  if (rtcOk && rtc.lostPower()) {
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  }

  setLeds(true, false, false);
  beep(1500, 100);
}

void loop() {
  checkSerial();
  checkRfid();
  checkKeypad();

  // Timeout på 2FA indtastning efter 15 sek.
  if ((scannedUid.length() > 0 || enteredPin.length() > 0) && millis() > accessModeUntil) {
    scannedUid = "";
    enteredPin = "";
    showLcdTemp("Timeout", "Proev igen", 1500);
  }

  if (millis() - lastTelemetryMs >= TELEMETRY_INTERVAL) {
    lastTelemetryMs = millis();
    sendTelemetry();
  }
}
