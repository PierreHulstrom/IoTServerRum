"""MQTT worker bridging Mosquitto broker, MariaDB, AI engine, Azure Email, and edge nodes.

Responsibilities:
  - Ingest sensor telemetry and run the 4+1-layer AI engine on every reading.
  - Execute 2-stage autonomous AI protection (latched alarm on breach; auto fan on/off).
  - Verify physical RFID/PIN access requests against SHA-256 hashes + brute-force alarm.
  - Monitor edge device liveness via LWT and a 60-second heartbeat watchdog.
  - Enforce GDPR data retention (hourly cleanup of old sensor readings and access logs).
"""

import hashlib
import json
import os
import threading
import time
from collections import defaultdict
import paho.mqtt.client as mqtt
from db import get_conn
from emailer import send_alert_async
from ai_engine import analyze_reading

# Internal Docker Mosquitto connection settings
MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_BACKEND_USER", "backend")
MQTT_PASS = os.getenv("MQTT_BACKEND_PASS", "")

# GDPR retention windows (days)
RETENTION_SENSOR_DAYS = int(os.getenv("RETENTION_SENSOR_DAYS", "30"))
RETENTION_ACCESS_DAYS = int(os.getenv("RETENTION_ACCESS_DAYS", "90"))

_client = None
_connected = False

# Autonomous AI autopilot state (toggleable live from the dashboard)
_auto_cooling_enabled = True
_last_auto_action_ts: dict[str, float] = {}
_active_env_alarm: dict[str, bool] = {}
_active_auto_fan: dict[str, bool] = {}

# Physical door brute-force tracker: 3 denied attempts within 60 seconds triggers alarm
_failed_access_attempts: dict[str, list[float]] = defaultdict(list)
DOOR_BRUTEFORCE_LIMIT = 3
DOOR_BRUTEFORCE_WINDOW_SEC = 60


def get_auto_cooling() -> bool:
    """Return True if autonomous AI cooling/alarm dispatch is currently enabled."""
    return _auto_cooling_enabled


def set_auto_cooling(enabled: bool) -> bool:
    """Toggle autonomous AI cooling/alarm dispatch on or off."""
    global _auto_cooling_enabled
    _auto_cooling_enabled = bool(enabled)
    return _auto_cooling_enabled


def hash_credential(raw_value: str) -> str:
    """Normalize and SHA-256 hash a physical RFID UID or 2FA UID:PIN credential."""
    return hashlib.sha256(raw_value.strip().encode("utf-8")).hexdigest()


def log_system(source: str, level: str, message: str, details: dict | None = None):
    """Write a structured audit/error event to system_logs without ever crashing the caller."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO system_logs (source, level, message, details) VALUES (%s, %s, %s, %s)",
                    (source, level, message, json.dumps(details or {})),
                )
    except Exception as e:
        print(f"[log_system error] {e}", flush=True)


def update_device_status(device_id: str, status: str, meta: dict | None = None):
    """Upsert an edge device's online/offline status and refresh its last_seen timestamp."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO device_status (device_id, status, last_seen, meta)
                VALUES (%s, %s, NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    last_seen = NOW(),
                    meta = COALESCE(VALUES(meta), meta)
                """,
                (device_id, status, json.dumps(meta) if meta is not None else None),
            )


def _handle_telemetry(device_id: str, payload: dict):
    """Store incoming telemetry, run AI anomaly detection, send alerts, and control cooling fan."""
    zone = str(payload.get("zone", "rack1"))
    temp = payload.get("temperature")
    hum = payload.get("humidity")
    noise = payload.get("noise_db")

    # Persist raw sensor reading in MariaDB
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sensor_readings (device_id, zone, temperature, humidity, noise_db)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (device_id, zone, temp, hum, noise),
            )

    update_device_status(device_id, "online", {"zone": zone})
    ai_res = analyze_reading(device_id, temp, hum, noise)

    # Always send critical email alert on ASHRAE breach (even if auto-cooling is disabled)
    if ai_res.get("threshold_breached"):
        send_alert_async(
            f"ashrae:{device_id}",
            f"Kritisk serverrumsalarm på {device_id}",
            f"ASHRAE-grænseværdi overskredet på {device_id}!\nTemp: {temp} C | Fugt: {hum} % | Støj: {noise} dB",
            severity="CRITICAL",
            cooldown_sec=300,
        )

    # 2-stage autonomous AI closed-loop control (separate 60s cooldowns for alarm vs. fan):
    # - alarm_test stays latched until manually disarmed (PIN 1984# or dashboard password)
    # - fan_auto starts cooling on overheat/prediction and auto-stops via fan_auto_off when < 27 C
    if _auto_cooling_enabled:
        now = time.time()
        if ai_res.get("threshold_breached"):
            alarm_key = f"{device_id}:alarm"
            if now - _last_auto_action_ts.get(alarm_key, 0) >= 60:
                _last_auto_action_ts[alarm_key] = now
                publish_command(
                    device_id,
                    "alarm_test",
                    {"reason": "ashrae_threshold_breached", "temp": temp, "hum": hum, "noise": noise},
                    issued_by="ai_autopilot",
                )

        if ai_res.get("critical_action_needed"):
            fan_key = f"{device_id}:fan"
            _active_auto_fan[device_id] = True
            if now - _last_auto_action_ts.get(fan_key, 0) >= 60:
                _last_auto_action_ts[fan_key] = now
                publish_command(
                    device_id,
                    "fan_auto",
                    {"reason": "ai_auto_protection", "temp": temp},
                    issued_by="ai_autopilot",
                )
        elif _active_auto_fan.get(device_id):
            _active_auto_fan[device_id] = False
            _last_auto_action_ts.pop(f"{device_id}:fan", None)
            publish_command(
                device_id,
                "fan_auto_off",
                {"reason": "temp_normalized", "temp": temp},
                issued_by="ai_autopilot",
            )


def _handle_status(device_id: str, raw_text: str):
    """Handle MQTT heartbeat or Last Will & Testament (LWT) offline notifications."""
    try:
        data = json.loads(raw_text)
        status = str(data.get("status", "online")).lower()
        meta = data
    except Exception:
        status = raw_text.strip().lower() or "offline"
        meta = {"raw": raw_text}

    update_device_status(device_id, status, meta)
    if status != "online":
        log_system("mqtt_worker", "ERROR", f"Enhed '{device_id}' gik OFFLINE (LWT/status)", meta)
        send_alert_async(
            f"offline:{device_id}",
            f"Edge-enhed '{device_id}' er OFFLINE",
            f"Enheden '{device_id}' har mistet forbindelsen til Azure MQTT (status: {status}). Tjek strøm eller netværk.",
            severity="ERROR",
            cooldown_sec=300,
        )


def _handle_access_request(payload: dict):
    """Verify a physical RFID/PIN request against SHA-256 hashes, log it, and detect brute-force."""
    device_id = str(payload.get("device_id", "pi1"))
    raw_cred = str(payload.get("credential", ""))
    cred_hash = hash_credential(raw_cred)

    granted = False
    owner_name = None
    reason = "Ukendt kort/kode"

    # Look up hashed credential and record the access attempt in access_logs
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT owner_name, role, is_active FROM access_cards WHERE credential_hash = %s",
                (cred_hash,),
            )
            card = cur.fetchone()
            if card and card["is_active"]:
                granted = True
                owner_name = card["owner_name"]
                reason = f"Godkendt ({card['role']})"
            elif card and not card["is_active"]:
                owner_name = card["owner_name"]
                reason = "Kort er deaktiveret"

            cur.execute(
                """
                INSERT INTO access_logs (device_id, credential_hash, owner_name, granted, reason)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (device_id, cred_hash[:16], owner_name, granted, reason),
            )

    # Publish authorization decision back to the edge node
    response = {
        "device_id": device_id,
        "granted": granted,
        "owner": owner_name,
        "reason": reason,
    }
    if _client:
        _client.publish("serverroom/access/response", json.dumps(response), qos=1)
    log_system(
        "access_control",
        "INFO" if granted else "WARNING",
        f"Adgang {'GODKENDT' if granted else 'AFVIST'} ved {device_id}: {owner_name or 'Ukendt'} ({reason})",
        {"device_id": device_id, "granted": granted},
    )

    # Physical door brute-force detection: 3 denied attempts in 60s -> siren + critical email
    now = time.time()
    if granted:
        _failed_access_attempts[device_id].clear()
    else:
        recent = [t for t in _failed_access_attempts[device_id] if now - t <= DOOR_BRUTEFORCE_WINDOW_SEC]
        recent.append(now)
        _failed_access_attempts[device_id] = recent
        if len(recent) >= DOOR_BRUTEFORCE_LIMIT:
            _failed_access_attempts[device_id].clear()
            log_system(
                "access_control",
                "ERROR",
                f"BRUTE-FORCE ALARM: {DOOR_BRUTEFORCE_LIMIT} afviste adgangsforsøg ved {device_id} inden for {DOOR_BRUTEFORCE_WINDOW_SEC}s!",
                {"device_id": device_id},
            )
            publish_command(
                device_id,
                "alarm_test",
                {"seconds": 5, "reason": "door_bruteforce"},
                issued_by="security_watchdog",
            )
            send_alert_async(
                f"door_bruteforce:{payload.get('device_id', 'ukendt')}",
                "Fysisk adgangsalarm: gentagne afviste forsøg",
                f"Der er registreret gentagne afviste RFID/PIN-forsøg ved døren ({payload.get('device_id', 'ukendt')}). Lokal alarm er udløst.",
                severity="CRITICAL",
                cooldown_sec=120,
            )


def _on_connect(client, userdata, flags, reason_code, properties):
    """Paho MQTT callback: subscribe to all serverroom/# topics once connected."""
    global _connected
    _connected = (reason_code == 0)
    print(f"[MQTT] Connected rc={reason_code}", flush=True)
    client.subscribe("serverroom/#", qos=1)
    log_system("mqtt_worker", "INFO", "Backend forbundet til Mosquitto MQTT-broker")


def _on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    """Paho MQTT callback: mark broker connection as offline."""
    global _connected
    _connected = False
    print(f"[MQTT] Disconnected rc={reason_code}", flush=True)


def _on_message(client, userdata, msg):
    """Route incoming MQTT topics to telemetry, status, access request, or door event handlers."""
    topic = msg.topic
    raw = msg.payload.decode("utf-8", errors="ignore")
    parts = topic.split("/")
    try:
        if len(parts) == 3 and parts[0] == "serverroom" and parts[2] == "telemetry":
            _handle_telemetry(parts[1], json.loads(raw))
        elif len(parts) == 3 and parts[0] == "serverroom" and parts[2] == "status":
            _handle_status(parts[1], raw)
        elif topic == "serverroom/access/request":
            _handle_access_request(json.loads(raw))
        elif topic == "serverroom/access/event":
            log_system("access_control", "INFO", f"Dørhændelse: {raw}")
    except Exception as e:
        log_system("mqtt_worker", "ERROR", f"Fejl ved behandling af {topic}: {e}", {"raw": raw[:200]})


def _heartbeat_watchdog():
    """Background thread: mark any device OFFLINE if no telemetry/heartbeat arrives for 60s."""
    while True:
        time.sleep(15)
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT device_id FROM device_status
                        WHERE status = 'online' AND last_seen < NOW() - INTERVAL 60 SECOND
                        """
                    )
                    stale = cur.fetchall()
                    for row in stale:
                        dev = row["device_id"]
                        cur.execute("UPDATE device_status SET status = 'offline' WHERE device_id = %s", (dev,))
                        log_system("watchdog", "ERROR", f"Timeout: ingen data fra '{dev}' i over 60 sek.")
        except Exception as e:
            print(f"[watchdog error] {e}", flush=True)


def run_gdpr_retention():
    """GDPR data minimization: delete sensor readings >30d and personal access logs >90d."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM sensor_readings WHERE time < NOW() - INTERVAL %s DAY",
                    (RETENTION_SENSOR_DAYS,),
                )
                del_s = cur.rowcount
                cur.execute(
                    "DELETE FROM access_logs WHERE time < NOW() - INTERVAL %s DAY",
                    (RETENTION_ACCESS_DAYS,),
                )
                del_a = cur.rowcount
        if del_s or del_a:
            log_system(
                "gdpr_retention",
                "INFO",
                f"GDPR-oprydning: slettede {del_s} målinger (>{RETENTION_SENSOR_DAYS}d) og {del_a} adgangslogs (>{RETENTION_ACCESS_DAYS}d)",
            )
    except Exception as e:
        print(f"[gdpr_retention error] {e}", flush=True)


def _retention_loop():
    """Background thread: run GDPR cleanup once every hour."""
    while True:
        time.sleep(3600)
        run_gdpr_retention()


def start_mqtt():
    """Initialize the Paho MQTT client and spawn watchdog + GDPR retention background threads."""
    global _client
    _client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="serverroom-backend")
    _client.username_pw_set(MQTT_USER, MQTT_PASS)
    _client.on_connect = _on_connect
    _client.on_disconnect = _on_disconnect
    _client.on_message = _on_message
    _client.reconnect_delay_set(min_delay=2, max_delay=30)
    _client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
    _client.loop_start()

    threading.Thread(target=_heartbeat_watchdog, daemon=True).start()
    threading.Thread(target=_retention_loop, daemon=True).start()


def mqtt_is_connected() -> bool:
    """Return True when the backend is connected to Mosquitto."""
    return _connected


def publish_command(device_id: str, command: str, payload: dict, issued_by: str):
    """Publish a command to serverroom/<device_id>/cmd and audit-log it in command_logs."""
    topic = f"serverroom/{device_id}/cmd"
    msg = {"command": command, "payload": payload, "issued_by": issued_by}
    if _client:
        _client.publish(topic, json.dumps(msg), qos=1)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO command_logs (device_id, issued_by, command, payload) VALUES (%s, %s, %s, %s)",
                (device_id, issued_by, command, json.dumps(payload)),
            )
    log_system("remote_control", "INFO", f"Kommando '{command}' sendt til {device_id} af {issued_by}", payload)
    return {"topic": topic, "sent": msg}
