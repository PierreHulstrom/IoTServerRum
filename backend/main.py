import base64
import csv
import io
import hashlib
import hmac
import json
import os
import shutil
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth_utils import (
    VALID_ROLES,
    authenticate_user,
    bootstrap_admin,
    upsert_user,
)
from db import db_ping, get_conn
from emailer import send_alert_async
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


def create_token(username: str, role: str = "admin") -> str:
    if not SECRET_KEY:
        raise RuntimeError("DASHBOARD_SECRET_KEY mangler i .env")
    payload = json.dumps(
        {"sub": username, "role": role, "exp": int(time.time()) + TOKEN_TTL_SEC}
    ).encode("utf-8")
    b64 = base64.urlsafe_b64encode(payload).decode("utf-8")
    sig = hmac.new(SECRET_KEY, b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def verify_session(authorization: str | None = Header(default=None)) -> dict:
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
        return {"username": str(data.get("sub", "admin")), "role": str(data.get("role", "admin"))}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Ugyldigt token")


def verify_token(authorization: str | None = Header(default=None)) -> str:
    return verify_session(authorization)["username"]


def require_role(*allowed_roles: str):
    def _dep(session: dict = Depends(verify_session)) -> dict:
        if session["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Manglende rettighed (rolle: {session['role']})")
        return session
    return _dep


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DASHBOARD_PASS or not SECRET_KEY:
        raise RuntimeError("DASHBOARD_PASS og DASHBOARD_SECRET_KEY SKAL være sat i .env!")
    bootstrap_admin(DASHBOARD_USER, DASHBOARD_PASS)
    start_mqtt()
    log_system("backend", "INFO", "FastAPI backend startet (PBKDF2 RBAC + hærdet konfiguration)")
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


class DisarmReq(BaseModel):
    device_id: str = "pi1"
    password: str


class UserCreateReq(BaseModel):
    username: str
    password: str
    role: str = "admin"


@app.get("/")
def serve_dashboard():
    return FileResponse("static/index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "db": db_ping(), "mqtt": mqtt_is_connected()}


@app.post("/api/login")
def login(req: LoginReq, request: Request):
    if not SECRET_KEY:
        raise HTTPException(status_code=500, detail="Auth ikke konfigureret")

    client_ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"

    rate_key = f"{client_ip}:{req.username.strip().lower()}"
    now = time.time()
    recent = [t for t in _login_failures[rate_key] if now - t <= LOGIN_WINDOW_SEC]
    _login_failures[rate_key] = recent
    if len(recent) >= LOGIN_MAX_ATTEMPTS:
        log_system("auth", "WARNING", f"Rate-limit blokerede '{req.username}' fra {client_ip} (429)")
        send_alert_async(
            f"login_429:{client_ip}:{req.username}",
            f"Web-login blokeret (429) for '{req.username}'",
            f"IP {client_ip} blev midlertidigt blokeret efter {LOGIN_MAX_ATTEMPTS} fejlede login-forsøg mod '{req.username}' på Dashboardet.",
            severity="WARNING",
            cooldown_sec=300,
        )
        raise HTTPException(status_code=429, detail="For mange fejlede forsøg – prøv igen om 5 min")

    user = authenticate_user(req.username, req.password)
    if not user:
        _login_failures[rate_key].append(now)
        log_system("auth", "WARNING", f"Fejlet login-forsøg for '{req.username}' fra {client_ip}")
        raise HTTPException(status_code=401, detail="Forkert brugernavn eller kodeord")

    _login_failures[rate_key].clear()
    log_system("auth", "INFO", f"Bruger '{user['username']}' ({user['role']}) loggede ind på dashboard")
    return {
        "token": create_token(user["username"], user["role"]),
        "username": user["username"],
        "role": user["role"],
    }


@app.get("/api/overview")
def overview(device_id: str | None = None, session: dict = Depends(verify_session)):
    dev_filter = device_id.strip() if device_id and device_id.strip() not in ("", "all") else None
    with get_conn() as conn:
        with conn.cursor() as cur:
            if dev_filter:
                cur.execute(
                    """
                    SELECT DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                           device_id, zone, temperature, humidity, noise_db
                    FROM sensor_readings
                    WHERE device_id = %s
                    ORDER BY id DESC LIMIT 60
                    """,
                    (dev_filter,),
                )
            else:
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

            users = []
            if session["role"] == "admin":
                cur.execute(
                    """
                    SELECT id, username, role, is_active,
                           DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
                    FROM dashboard_users ORDER BY id ASC
                    """
                )
                users = cur.fetchall()

    return {
        "current_user": session,
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
        "users": users,
    }


@app.post("/api/settings/auto-cooling")
def toggle_auto_cooling(req: AutoCoolingReq, session: dict = Depends(require_role("admin", "operator"))):
    state = set_auto_cooling(req.enabled)
    log_system("ai_autopilot", "INFO", f"Autonom AI-køling sat til {'TIL' if state else 'FRA'} af {session['username']}")
    return {"auto_cooling": state}


@app.post("/api/command")
def send_command(req: CommandReq, session: dict = Depends(require_role("admin", "operator"))):
    return publish_command(req.device_id, req.command, req.payload, issued_by=session["username"])


@app.post("/api/access/cards")
def add_card(req: CardReq, session: dict = Depends(require_role("admin", "operator"))):
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
    log_system("access_control", "INFO", f"Nyt adgangskort oprettet til '{req.owner_name}' af {session['username']}")
    return {"status": "created"}


@app.patch("/api/access/cards/{card_id}/toggle")
def toggle_card(card_id: int, session: dict = Depends(require_role("admin", "operator"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE access_cards SET is_active = NOT is_active WHERE id = %s", (card_id,))
    log_system("access_control", "INFO", f"Status ændret på adgangskort #{card_id} af {session['username']}")
    return {"status": "updated"}


@app.delete("/api/access/cards/{card_id}")
def delete_card(card_id: int, session: dict = Depends(require_role("admin", "operator"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM access_cards WHERE id = %s", (card_id,))
    log_system("access_control", "WARNING", f"Adgangskort #{card_id} slettet af {session['username']}")
    return {"status": "deleted"}


@app.post("/api/users")
def create_dashboard_user(req: UserCreateReq, session: dict = Depends(require_role("admin"))):
    if len(req.username.strip()) < 2 or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Brugernavn >= 2 tegn og kodeord >= 8 tegn")
    if req.role.strip().lower() not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Ugyldig rolle (brug admin, operator eller viewer)")
    upsert_user(req.username, req.password, role=req.role)
    log_system("auth", "INFO", f"Dashboard-bruger '{req.username.lower()}' ({req.role}) oprettet/opdateret af {session['username']}")
    return {"status": "saved"}


@app.patch("/api/users/{user_id}/toggle")
def toggle_dashboard_user(user_id: int, session: dict = Depends(require_role("admin"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM dashboard_users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Bruger ikke fundet")
            if row["username"] == session["username"]:
                raise HTTPException(status_code=400, detail="Du kan ikke spærre din egen bruger")
            cur.execute("UPDATE dashboard_users SET is_active = NOT is_active WHERE id = %s", (user_id,))
    log_system("auth", "WARNING", f"Status ændret på bruger '{row['username']}' af {session['username']}")
    return {"status": "updated"}


@app.delete("/api/users/{user_id}")
def delete_dashboard_user(user_id: int, session: dict = Depends(require_role("admin"))):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM dashboard_users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Bruger ikke fundet")
            if row["username"] == session["username"]:
                raise HTTPException(status_code=400, detail="Du kan ikke slette din egen bruger")
            cur.execute("DELETE FROM dashboard_users WHERE id = %s", (user_id,))
    log_system("auth", "WARNING", f"Bruger '{row['username']}' slettet af {session['username']}")
    return {"status": "deleted"}


@app.get("/api/export/sensors.csv")
def export_sensors_csv(device_id: str | None = None, session: dict = Depends(verify_session)):
    dev_filter = device_id.strip() if device_id and device_id.strip() not in ("", "all") else None
    with get_conn() as conn:
        with conn.cursor() as cur:
            if dev_filter:
                cur.execute(
                    """
                    SELECT DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                           device_id, zone, temperature, humidity, noise_db
                    FROM sensor_readings WHERE device_id = %s
                    ORDER BY id DESC LIMIT 5000
                    """,
                    (dev_filter,),
                )
            else:
                cur.execute(
                    """
                    SELECT DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                           device_id, zone, temperature, humidity, noise_db
                    FROM sensor_readings ORDER BY id DESC LIMIT 5000
                    """
                )
            rows = list(reversed(cur.fetchall()))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "device_id", "zone", "temperature", "humidity", "noise_db"])
    for r in rows:
        w.writerow([r["time"], r["device_id"], r["zone"], r["temperature"], r["humidity"], r["noise_db"]])
    log_system("export", "INFO", f"Sensordata CSV eksporteret ({len(rows)} rækker) af {session['username']}")
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=serverroom_sensors.csv"},
    )


@app.get("/api/export/anomalies.csv")
def export_anomalies_csv(session: dict = Depends(verify_session)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DATE_FORMAT(time, '%Y-%m-%d %H:%i:%s') AS time,
                       device_id, anomaly_score, is_anomaly, predicted_critical_min, message
                FROM ai_anomalies ORDER BY id DESC LIMIT 2000
                """
            )
            rows = list(reversed(cur.fetchall()))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "device_id", "anomaly_score", "is_anomaly", "predicted_critical_min", "message"])
    for r in rows:
        w.writerow([r["time"], r["device_id"], r["anomaly_score"], r["is_anomaly"], r["predicted_critical_min"], r["message"]])
    log_system("export", "INFO", f"AI-alarmer CSV eksporteret ({len(rows)} rækker) af {session['username']}")
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=serverroom_ai_anomalies.csv"},
    )


@app.post("/api/alarm/disarm")
def disarm_alarm(req: DisarmReq, session: dict = Depends(require_role("admin", "operator"))):
    verified = authenticate_user(session["username"], req.password)
    if not verified:
        log_system("auth", "WARNING", f"Fejlet alarm-afstilling (forkert kodeord) af '{session['username']}'")
        raise HTTPException(status_code=401, detail="Forkert kodeord – alarmen fortsætter")
    res = publish_command(
        req.device_id,
        "alarm_stop",
        {"disarmed_by": session["username"]},
        issued_by=session["username"],
    )
    log_system("security", "INFO", f"Alarm afstillet (step-up auth) på {req.device_id} af '{session['username']}'")
    return {"status": "disarmed", "detail": res}
