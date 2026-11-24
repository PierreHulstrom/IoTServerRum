# Pin-plan – Arduino Mega 2560

| Komponent | Arduino Mega 2560 Pins | Strøm / Noter |
| :--- | :--- | :--- |
| RC522 RFID | SS=53, SCK=52, MOSI=51, MISO=50, RST=49 | **KUN 3.3V** + GND |
| RTC DS3231 | SDA=20, SCL=21 | 5V + GND |
| LCD 1602 (16-pin) | RS=22, E=23, D4=24, D5=25, D6=26, D7=27 | VSS/RW/K=GND, VDD=5V, A=5V (220 Ohm), V0=Potentiometer |
| 4x4 Keypad | R1-R4=30,31,32,33 / C1-C4=34,35,36,37 | Direkte digitale pins |
| DHT22 | DATA=2 | 5V + GND |
| Lydsensor (analog) | A0=A0 | 5V + GND |
| LED Grøn / Gul / Rød | 40 / 41 / 42 | Via 220 Ohm modstand til GND |
| Passiv Buzzer | 44 | + til pin 44, - til GND |

## Nødvendige biblioteker i Arduino IDE (Library Manager)
1. `DHT sensor library` (Adafruit) + `Adafruit Unified Sensor`
2. `RTClib` (Adafruit)
3. `MFRC522` (GithubCommunity)
4. `Keypad` (Mark Stanley, Alexander Brevig)
5. `LiquidCrystal` (indbygget i Arduino IDE)
