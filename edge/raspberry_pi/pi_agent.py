import argparse
import glob
import json
import os
import random
import sqlite3
import ssl
import sys
import threading
import time
import paho.mqtt.client as mqtt


def load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


load_env()

MQTT_HOST = os.getenv("MQTT_HOST", "serverrum-iot-2026.swedencentral.cloudapp.azure.com")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USER = os.getenv("MQTT_USER", "pi-node")
MQTT_PASS = os.getenv("MQTT_PASS", "")
DEVICE_ID = os.getenv("DEVICE_ID", "pi1")
ZONE = os.getenv("ZONE", "rack1")
SERIAL_PORT = os.getenv("SERIAL_PORT", "auto")
SERIAL_BAUD = int(os.getenv("SERIAL_BAUD", "115200"))


class OfflineBuffer:
    """Lokal SQLite-kø så sensordata ikke tabes ved midlertidigt hotspot-udfald."""
    def __init__(self, db_path="offline_buffer.db"):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT, payload TEXT)"
        )
        self.conn.commit()

    def push(self, topic: str, payload: str):
        with self.lock:
            self.conn.execute("INSERT INTO queue (topic, payload) VALUES (?, ?)", (topic, payload))
            self.conn.commit()

    def pop_batch(self, limit=25):
        with self.lock:
            rows = self.conn.execute("SELECT id, topic, payload FROM queue ORDER BY id ASC LIMIT ?", (limit,)).fetchall()
            return rows

    def delete(self, row_id: int):
        with self.lock:
            self.conn.execute("DELETE FROM queue WHERE id = ?", (row_id,))
            self.conn.commit()


class PiBridge:
    def __init__(self, simulate=False, serial_port=SERIAL_PORT, baud=SERIAL_BAUD):
        self.simulate = simulate
        self.serial_port = serial_port
        self.baud = baud
        self.ser = None
        self.connected = False
        self.buffer = OfflineBuffer()
        self.sim_temp = 22.0
        self.sim_heating = False

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"edge-{DEVICE_ID}")
        self.client.username_pw_set(MQTT_USER, MQTT_PASS)
        self.client.tls_set_context(ssl.create_default_context())
        self.client.reconnect_delay_set(min_delay=2, max_delay=30)

        # Last Will & Testament (Delspørgsmål 3: automatisk nedbrudsregistrering)
        self.client.will_set(
            f"serverroom/{DEVICE_ID}/status",
            json.dumps({"status": "offline", "reason": "lwt_disconnect"}),
            qos=1,
            retain=True,
        )
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc, properties):
        self.connected = (rc == 0)
        print(f"[MQTTS] Forbundet til {MQTT_HOST}:{MQTT_PORT} (rc={rc})")
        if self.connected:
            client.subscribe(f"serverroom/{DEVICE_ID}/cmd", qos=1)
            client.subscribe("serverroom/access/response", qos=1)
            self._publish_now(
                f"serverroom/{DEVICE_ID}/status",
                {"status": "online", "bridge": "raspberry_pi", "mode": "simulate" if self.simulate else "serial"},
                retain=True,
            )
            self._flush_buffer()

    def _on_disconnect(self, client, userdata, flags, rc, properties):
        self.connected = False
        print(f"[MQTTS] Afbrudt (rc={rc}) – buffer aktiveret lokalt i SQLite")

    def _on_message(self, client, userdata, msg):
        raw = msg.payload.decode("utf-8", errors="ignore")
        print(f"[AZURE -> PI] Topic: {msg.topic} | Besked: {raw}", flush=True)
        try:
            data = json.loads(raw)
        except Exception:
            return

        if msg.topic == f"serverroom/{DEVICE_ID}/cmd":
            out = {"cmd": data.get("command")}
            self._send_to_arduino(out)
        elif msg.topic == "serverroom/access/response":
            out = {
                "type": "access_response",
                "granted": bool(data.get("granted")),
                "owner": data.get("owner") or "Ukendt",
                "reason": data.get("reason") or "",
            }
            self._send_to_arduino(out)

    def _send_to_arduino(self, obj: dict):
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        if self.ser and self.ser.is_open:
            self.ser.write(line.encode("utf-8"))
            self.ser.flush()
            print(f"[PI -> ARDUINO] {line.strip()}", flush=True)
        else:
            print(f"[SIMULERET ARDUINO] Udfører: {line.strip()}")

    def _publish_now(self, topic: str, payload_obj: dict, retain=False):
        payload = json.dumps(payload_obj)
        if self.connected:
            info = self.client.publish(topic, payload, qos=1, retain=retain)
            if info.rc == mqtt.MQTT_ERR_SUCCESS:
                return True
        self.buffer.push(topic, payload)
        print(f"[BUFFER] Gemt lokalt (offline): {topic}")
        return False

    def _flush_buffer(self):
        rows = self.buffer.pop_batch(50)
        if rows:
            print(f"[BUFFER] Sender {len(rows)} gemte beskeder til Azure...")
        for row_id, topic, payload in rows:
            if not self.connected:
                break
            info = self.client.publish(topic, payload, qos=1)
            if info.rc == mqtt.MQTT_ERR_SUCCESS:
                self.buffer.delete(row_id)

    def handle_arduino_message(self, data: dict):
        msg_type = data.get("type", "telemetry")
        if msg_type == "telemetry":
            payload = {
                "zone": data.get("zone", ZONE),
                "temperature": data.get("temperature"),
                "humidity": data.get("humidity"),
                "noise_db": data.get("noise_db"),
                "rtc": data.get("rtc"),
            }
            self._publish_now(f"serverroom/{DEVICE_ID}/telemetry", payload)
            print(f"[PI -> AZURE] Telemetry: {payload}")
        elif msg_type == "access_request":
            payload = {
                "device_id": DEVICE_ID,
                "credential": str(data.get("credential", "")),
                "method": data.get("method", "rfid_pin"),
                "rtc": data.get("rtc"),
            }
            self._publish_now("serverroom/access/request", payload)
            print(f"[PI -> AZURE] Adgangsforespørgsel sendt (metode={payload['method']})")
        elif msg_type == "access_event":
            self._publish_now("serverroom/access/event", data)
            print(f"[PI -> AZURE] Dørhændelse: {data}")

    def _heartbeat_loop(self):
        while True:
            time.sleep(20)
            if self.connected:
                self._publish_now(
                    f"serverroom/{DEVICE_ID}/status",
                    {"status": "online", "bridge": "raspberry_pi"},
                    retain=True,
                )
                self._flush_buffer()

    def _detect_serial_port(self):
        if self.serial_port and self.serial_port != "auto" and os.path.exists(self.serial_port):
            return self.serial_port
        candidates = sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
        return candidates[0] if candidates else None

    def _serial_loop(self):
        import serial
        while True:
            port = self._detect_serial_port()
            if not port:
                print("[SERIAL] Ingen Arduino/Elegoo USB-enhed fundet (/dev/ttyACM* eller /dev/ttyUSB*) – prøver igen om 5 sek...", flush=True)
                time.sleep(5)
                continue
            try:
                print(f"[SERIAL] Åbner {port} @ {self.baud} baud...", flush=True)
                self.ser = serial.Serial(port, self.baud, timeout=1)
                time.sleep(2)
                print("[SERIAL] Forbundet til Arduino!")
                while True:
                    raw = self.ser.readline().decode("utf-8", errors="ignore").strip()
                    if not raw:
                        continue
                    try:
                        self.handle_arduino_message(json.loads(raw))
                    except json.JSONDecodeError:
                        print(f"[ARDUINO LOG] {raw}")
            except Exception as e:
                print(f"[SERIAL] Fejl ({e}) – prøver igen om 5 sek...")
                time.sleep(5)

    def _sim_input_loop(self):
        print("\n[SIMULATOR-KOMMANDOER] Skriv i terminalen og tryk Enter:")
        print("  heat        -> Start temperaturstigning (tester AI-forudsigelse)")
        print("  cool        -> Normal temperatur igen")
        print("  spike       -> Send pludselig støj/temp-anomaly")
        print("  card 1234   -> Test adgangskontrol med kort/PIN '1234'\n")
        for line in sys.stdin:
            cmd = line.strip()
            if cmd == "heat":
                self.sim_heating = True
                print("[SIM] Temperaturstigning aktiveret!")
            elif cmd == "cool":
                self.sim_heating = False
                self.sim_temp = 22.0
                print("[SIM] Normal temperatur gendannet!")
            elif cmd == "spike":
                self.handle_arduino_message({
                    "type": "telemetry", "zone": ZONE,
                    "temperature": 29.8, "humidity": 46.0, "noise_db": 84.5
                })
            elif cmd.startswith("card "):
                cred = cmd.split(" ", 1)[1].strip()
                self.handle_arduino_message({"type": "access_request", "credential": cred, "method": "sim"})

    def _simulate_loop(self):
        threading.Thread(target=self._sim_input_loop, daemon=True).start()
        while True:
            if self.sim_heating:
                self.sim_temp = min(31.0, self.sim_temp + 0.45)
            else:
                self.sim_temp = 22.0 + random.uniform(-0.4, 0.4)
            self.handle_arduino_message({
                "type": "telemetry",
                "zone": ZONE,
                "temperature": round(self.sim_temp, 2),
                "humidity": round(45.0 + random.uniform(-1.5, 1.5), 2),
                "noise_db": round(52.0 + random.uniform(-2.0, 2.0), 2),
            })
            time.sleep(5)

    def run(self):
        if not MQTT_PASS:
            print("FEJL: MQTT_PASS mangler i .env!")
            sys.exit(1)
        self.client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=30)
        self.client.loop_start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

        try:
            if self.simulate:
                self._simulate_loop()
            else:
                self._serial_loop()
        except KeyboardInterrupt:
            print("\n[PI] Lukker ned...")
            self._publish_now(f"serverroom/{DEVICE_ID}/status", {"status": "offline", "reason": "graceful_stop"}, retain=True)
            time.sleep(0.5)
            self.client.loop_stop()
            self.client.disconnect()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Raspberry Pi Edge Bridge (Arduino <-> Azure MQTTS)")
    p.add_argument("--simulate", action="store_true", help="Kør uden Arduino med live simulerede målinger")
    p.add_argument("--serial", default=SERIAL_PORT, help="Serial port til Arduino (fx /dev/ttyACM0)")
    args = p.parse_args()
    PiBridge(simulate=args.simulate, serial_port=args.serial).run()
