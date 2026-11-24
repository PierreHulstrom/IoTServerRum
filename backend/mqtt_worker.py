import hashlib
import json
import os
import threading
import time
import paho.mqtt.client as mqtt
from db import get_conn
from ai_engine import analyze_reading

MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_BACKEND_USER", "backend")
MQTT_PASS = os.getenv("MQTT_BACKEND_PASS", "")

_client = None
_connected = False


def hash_credential(raw_value: str) -> str:
    return hashlib.sha256(raw_value.strip().encode("utf-8")).hexdigest()


def log_system(source: str, level: str, message: str, details: dict | None = None):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO system_logs (source, level, message, details) VALUES (%s, %s, %s, %s)",
                    (source, level, message, json.dumps(details or {})),
                )
    except Exception as e:
        print(f"[log_system error] {e}")


def update_device_status(device_id: str, status: str, meta: dict | None = None):
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
    zone = str(payload.get("zone", "rack1"))
    temp = payload.get("temperature")
    hum = payload.get("humidity")
    noise = payload.get("noise_db")

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
    analyze_reading(device_id, temp, hum, noise)


def _handle_status(device_id: str, raw_text: str):
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


def _handle_access_request(payload: dict):
    device_id = str(payload.get("device_id", "door1"))
    raw_cred = str(payload.get("credential", ""))
    cred_hash = hash_credential(raw_cred)

    granted = False
    owner_name = None
    reason = "Ukendt kort/kode"

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


def _on_connect(client, userdata, flags, reason_code, properties):
    global _connected
    _connected = (reason_code == 0)
    print(f"[MQTT] Connected rc={reason_code}")
    client.subscribe("serverroom/#", qos=1)
    log_system("mqtt_worker", "INFO", "Backend forbundet til Mosquitto MQTT-broker")


def _on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    global _connected
    _connected = False
    print(f"[MQTT] Disconnected rc={reason_code}")


def _on_message(client, userdata, msg):
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
            print(f"[watchdog error] {e}")


def start_mqtt():
    global _client
    _client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="serverroom-backend")
    _client.username_pw_set(MQTT_USER, MQTT_PASS)
    _client.on_connect = _on_connect
    _client.on_disconnect = _on_disconnect
    _client.on_message = _on_message
    _client.reconnect_delay_set(min_delay=2, max_delay=30)
    _client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
    _client.loop_start()

    t = threading.Thread(target=_heartbeat_watchdog, daemon=True)
    t.start()


def mqtt_is_connected() -> bool:
    return _connected


def publish_command(device_id: str, command: str, payload: dict, issued_by: str):
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
