# Serverrum IoT – Miljøovervågning, AI Anomaly Detection & Adgangskontrol

Sikkert og pålideligt IoT-system med tovejskommunikation mellem Edge (Arduino Mega 2560 + Raspberry Pi Bridge) og Azure Cloud (Docker).

## Arkitektur
- **Edge (`edge/`):**
  - `edge/arduino/`: Arduino Mega 2560 firmware & pin-plan (`WIRING.md`) til DHT22, lydsensor, RTC DS3231, RC522 RFID + 4x4 Keypad (2FA), LCD 1602, 3 LED'er og passiv buzzer.
  - `edge/raspberry_pi/`: Python Edge Bridge (`pi_agent.py`) med MQTTS (TLS 1.2+), LWT, heartbeat, lokal SQLite offline-buffer og `systemd` auto-start (`serverroom-bridge.service`).
- **MQTTS Broker (`mosquitto/`):** Eclipse Mosquitto over TLS 1.2+ (port `8883`), PBKDF2-SHA512 login og topic-baseret ACL (*least privilege*).
- **Database (`db/` + `scripts/backup_db.sh`):** MariaDB 11 (kun internt Docker-netværk) med 7 tabeller, automatisk GDPR-dataretention og daglig komprimeret backup.
- **Backend & Hybrid-AI (`backend/`):** Python FastAPI, `paho-mqtt`, 4-lags Hybrid-AI (ASHRAE TC 9.9 + robust Z-score + Isolation Forest + heltals-trendforudsigelse + flatline-sensordefekt), autonom AI-køling, brute-force beskyttelse (`429` på web-login + dør-alarm ved 3 afviste forsøg) samt live Operations Center dashboard.
- **Reverse Proxy (`caddy/`):** Caddy udelukkende over HTTPS (port `443`) med TLS + HSTS og sikkerhedsheadere (port `80` holdes lukket).

## Kvalitetssikring & Automatiserede Tests
Kør alle 28 enheds-, integrations- og sikkerhedstests i backend-containeren:
    docker exec serverroom-backend python -m unittest discover -s tests -v

Kør uafhængig statisk sikkerhedsscanning med Bandit:
    docker run --rm -v /opt/serverroom-iot:/src:ro python:3.11-slim sh -c "pip install -q bandit && bandit -r /src/backend /src/edge -x /src/backend/tests"

## Hurtig start (Server)
1. Kopiér `.env.example` til `.env` og udfyld stærke adgangskoder (`chmod 660 .env`).
2. Kopiér `mosquitto/config/acl.example` til `mosquitto/config/acl` og opret brugere med `mosquitto_passwd` (`chmod 600`, ejer `1883:1883`).
3. Placér TLS-certifikater (`fullchain.pem` og `privkey.pem`) i `mosquitto/certs/` (`chmod 600` på `privkey.pem`).
4. Start hele stakken med `docker compose up -d --build`.
