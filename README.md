# Serverrum IoT – Miljøovervågning, AI Anomaly Detection & Adgangskontrol

Sikkert IoT-system med tovejskommunikation mellem Edge (Raspberry Pi + Arduino) og Azure Cloud (Docker).

## Arkitektur
- **Edge (`edge/`):** Raspberry Pi (Python) + Arduino til miljøsensorer (temperatur, luftfugtighed, støj), fysisk adgangskontrol og aktuatorer.
- **MQTTS Broker (`mosquitto/`):** Eclipse Mosquitto over TLS 1.2+ (port `8883`), brugernavn/password (PBKDF2-SHA512) og topic-baseret ACL (*least privilege*).
- **Database (`db/`):** MariaDB 11 (kun internt i Docker-netværk) til målinger, AI-afvigelser, hashede adgangskort, adgangslog, driftstatus og auditlogs.
- **Backend & AI (`backend/`):** Python FastAPI, `paho-mqtt`, `scikit-learn` (Isolation Forest) og `numpy` (lineær trendforudsigelse) + sikret Operations Center web-dashboard.
- **Reverse Proxy (`caddy/`):** Caddy over ren HTTPS (port `443`) med TLS + HSTS-sikkerhedsheadere (port `80` holdes lukket).

## Mappestruktur
- `docker-compose.yml` – Samlet orkestrering af Mosquitto, MariaDB, Backend & Caddy
- `.env.example` – Skabelon til miljøvariabler (kopieres til `.env`)
- `db/init.sql` – MariaDB-skema (7 tabeller)
- `mosquitto/config/` – `mosquitto.conf` & `acl.example`
- `caddy/Caddyfile` – HTTPS reverse proxy (port 443 + HSTS)
- `backend/` – FastAPI API, MQTT-worker, AI-motor & Web-dashboard
- `edge/` – Raspberry Pi (Python) & Arduino kode

## Hurtig start (Server)
1. Kopiér `.env.example` til `.env` og udfyld stærke adgangskoder (`chmod 660 .env`).
2. Kopiér `mosquitto/config/acl.example` til `mosquitto/config/acl` og opret brugere med `mosquitto_passwd` (`chmod 600`, ejer `1883:1883`).
3. Placér TLS-certifikater (`fullchain.pem` og `privkey.pem`) i `mosquitto/certs/` (`chmod 600` på `privkey.pem`).
4. Start hele stakken med `docker compose up -d --build`.
