import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from db import db_ping, get_conn
from mqtt_worker import (
    get_auto_cooling,
    hash_credential,
    log_system,
    mqtt_is_connected,
    publish_command,
    set_auto_cooling,
    start_mqtt,
)

DASHBOARD_USER = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS")
_RAW_SECRET = os.getenv("DASHBOARD_SECRET_KEY")
SECRET_KEY = _RAW_SECRET.encode("utf-8") if _RAW_SECRET else None
TOKEN_TTL_SEC = 12 * 3600

# Brute-force rate-limiter på web-login (5 fejlforsøg pr. IP inden for 5 min -> 429)
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 300
_login_failures: dict[str, list[float]] = defaultdict(list)


def get_server_metrics() -> dict:
    load_1m = 0.0
    try:
        load_1m = round(os.getloadavg()[0], 2)
    except Exception:
        pass

    mem_pct = 0.0
    try:
        info = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                k, v = line.split(":", 1)
                info[k.strip()] = int(v.strip().split()[0])
        total = info.get("MemTotal", 1)
        avail = info.get("MemAvailable", total)
        mem_pct = round(((total - avail) / total) * 100.0, 1)
    except Exception:
        pass

    disk_pct = 0.0
    try:
        u = shutil.disk_usage("/")
        disk_pct = round((u.used / u.total) * 100.0, 1)
    except Exception:
        pass

    uptime_str = "ukendt"
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            sec = int(float(f.read().split()[0]))
        days, rem = divmod(sec, 86400)
        hrs, rem = divmod(rem, 3600)
        mins = rem // 60
        uptime_str = f"{days}d {hrs}t {mins}m" if days else f"{hrs}t {mins}m"
    except Exception:
        pass

    return {
        "cpu_load": load_1m,
        "ram_pct": mem_pct,
        "disk_pct": disk_pct,
        "uptime": uptime_str,
    }


def create_token(username: str) -> str:
    if not SECRET_KEY:
        raise RuntimeError("DASHBOARD_SECRET_KEY mangler i .env")
    payload = json.dumps({"sub": username, "exp": int(time.time()) + TOKEN_TTL_SEC}).encode("utf-8")
    b64 = base64.urlsafe_b64encode(payload).decode("utf-8")
    sig = hmac.new(SECRET_KEY, b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_token(authorization: str | None = Header(default=None)) -> str:
    if not SECRET_KEY:
        raise HTTPException(status_code=500, detail="Server-konfigurationsfejl")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login påkrævet")
    token = authorization.split(" ", 1)[1].strip()
    try:
        b64, sig = token.split(".", 1)
        expected = hmac.new(SECRET_KEY, b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(status_code=401, detail="Ugyldigt token")
        data = json.loads(base64.urlsafe_b64decode(b64.encode("utf-8")).decode("utf-8"))
        if data.get("exp", 0) < time.time():
            raise HTTPException(status_code=401, detail="Session udløbet")
        return str(data.get("sub", "admin"))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Ugyldigt token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DASHBOARD_PASS or not SECRET_KEY:
        raise RuntimeError("DASHBOARD_PASS og DASHBOARD_SECRET_KEY SKAL være sat i .env!")
    start_mqtt()
    log_system("backend", "INFO", "FastAPI backend startet (hærdet konfiguration)")
    yield


app = FastAPI(title="Serverrum IoT Platform", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


class LoginReq(BaseModel):
    username: str
    password: str


class CommandReq(BaseModel):
    device_id: str = "pi1"
    command: str
    payload: dict = {}


class CardReq(BaseModel):
    owner_name: str
    role: str = "staff"
    credential: str


class AutoCoolingReq(BaseModel):
    enabled: bool


@app.get("/")
def serve_dashboard():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "db": db_ping(), "mqtt": mqtt_is_connected()}


@app.post("/api/login")
def login(req: LoginReq, request: Request):
    if not DASHBOARD_PASS or not SECRET_KEY:
        raise HTTPException(status_code=500, detail="Auth ikke konfigureret")

    client_ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"

    now = time.time()
    recent = [t for t in _login_failures[client_ip] if now - t <= LOGIN_WINDOW_SEC]
    _login_failures[client_ip] = recent
    if len(recent) >= LOGIN_MAX_ATTEMPTS:
        log_system("auth", "WARNING", f"Rate-limit blokerede login fra {client_ip} (429)")
        raise HTTPException(status_code=429, detail="For mange fejlede forsøg – prøv igen om 5 min")

    ok_user = secrets.compare_digest(req.username, DASHBOARD_USER)
    ok_pass = secrets.compare_digest(req.password, DASHBOARD_PASS)
    if not (ok_user and ok_pass):
        _login_failures[client_ip].append(now)
        log_system("auth", "WARNING", f"Fejlet login-forsøg for '{req.username}' fra {client_ip}")
        raise HTTPException(status_code=401, detail="Forkert brugernavn eller kodeord")

    _login_failures[client_ip].clear()
    log_system("auth", "INFO", f"Bruger '{req.username}' loggede ind på dashboard")
    return {"token": create_token(req.username), "username": req.username}


@app.get("/api/overview")
def overview(user: str = Depends(verify_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       device_id, zone, temperature, humidity, noise_db
                FROM sensor_readings
                ORDER BY id DESC LIMIT 60
                """
            )
            readings = list(reversed(cur.fetchall()))

            cur.execute(
                """
                SELECT device_id, status,
                       DATE_FORMAT(last_seen, '%Y-%m-%d %H:%i:%s') AS last_seen, meta
                FROM device_status ORDER BY device_id
                """
            )
            devices = cur.fetchall()

            cur.execute(
                """
                SELECT id, DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       device_id, anomaly_score, is_anomaly, predicted_critical_min, message
                FROM ai_anomalies ORDER BY id DESC LIMIT 15
                """
            )
            anomalies = cur.fetchall()

            cur.execute(
                """
                SELECT id, owner_name, role, is_active,
                       LEFT(credential_hash, 12) AS hash_preview,
                       DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
                FROM access_cards ORDER BY id DESC
                """
            )
            cards = cur.fetchall()

            cur.execute(
                """
                SELECT id, DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       device_id, owner_name, granted, reason
                FROM access_logs ORDER BY id DESC LIMIT 20
                """
            )
            access_logs = cur.fetchall()

            cur.execute(
                """
                SELECT id, DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       source, level, message
                FROM system_logs ORDER BY id DESC LIMIT 25
                """
            )
            system_logs = cur.fetchall()

            cur.execute(
                """
                SELECT id, DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       device_id, issued_by, command, payload
                FROM command_logs ORDER BY id DESC LIMIT 15
                """
            )
            commands = cur.fetchall()

    return {
        "health": {"db": db_ping(), "mqtt": mqtt_is_connected()},
        "server_metrics": get_server_metrics(),
        "settings": {"auto_cooling": get_auto_cooling()},
        "readings": readings,
        "devices": devices,
        "anomalies": anomalies,
        "cards": cards,
        "access_logs": access_logs,
        "system_logs": system_logs,
        "commands": commands,
    }


@app.post("/api/settings/auto-cooling")
def toggle_auto_cooling(req: AutoCoolingReq, user: str = Depends(verify_token)):
    state = set_auto_cooling(req.enabled)
    log_system("ai_autopilot", "INFO", f"Autonom AI-køling sat til {'TIL' if state else 'FRA'} af {user}")
    return {"auto_cooling": state}


@app.post("/api/command")
def send_command(req: CommandReq, user: str = Depends(verify_token)):
    return publish_command(req.device_id, req.command, req.payload, issued_by=user)


@app.post("/api/access/cards")
def add_card(req: CardReq, user: str = Depends(verify_token)):
    if len(req.credential.strip()) < 3:
        raise HTTPException(status_code=400, detail="Kort-UID/PIN skal være mindst 3 tegn")
    cred_hash = hash_credential(req.credential)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO access_cards (credential_hash, owner_name, role) VALUES (%s, %s, %s)",
                    (cred_hash, req.owner_name.strip(), req.role.strip()),
                )
    except Exception:
        raise HTTPException(status_code=409, detail="Kort/PIN findes allerede i systemet")
    log_system("access_control", "INFO", f"Nyt adgangskort oprettet til '{req.owner_name}' af {user}")
    return {"status": "created"}


@app.patch("/api/access/cards/{card_id}/toggle")
def toggle_card(card_id: int, user: str = Depends(verify_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE access_cards SET is_active = NOT is_active WHERE id = %s", (card_id,))
    log_system("access_control", "INFO", f"Status ændret på adgangskort #{card_id} af {user}")
    return {"status": "updated"}


@app.delete("/api/access/cards/{card_id}")
def delete_card(card_id: int, user: str = Depends(verify_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM access_cards WHERE id = %s", (card_id,))
    log_system("access_control", "WARNING", f"Adgangskort #{card_id} slettet af {user}")
    return {"status": "deleted"}
