"""Dashboard user authentication & RBAC helpers (PBKDF2-HMAC-SHA256)."""

import hashlib
import hmac
import os
from db import get_conn

# OWASP-aligned PBKDF2 iteration count and allowed dashboard RBAC roles
PBKDF2_ITERS = 260_000
VALID_ROLES = ("admin", "operator", "viewer")


def hash_password(password: str) -> str:
    """Hash a plaintext password with a unique 16-byte random salt (PBKDF2-SHA256)."""
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERS).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt}${dk}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash using constant-time comparison."""
    try:
        algo, iters_s, salt_hex, expected_hex = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters_s)).hex()
        return hmac.compare_digest(dk, expected_hex)
    except Exception:
        return False


def ensure_users_table():
    """Create the dashboard_users table on startup if it does not already exist."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS dashboard_users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'operator',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


def upsert_user(username: str, password: str, role: str = "admin", is_active: bool = True):
    """Insert a new dashboard user or update password, role, and active status."""
    role = role.strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Ugyldig rolle: {role}")
    uname = username.strip().lower()
    pw_hash = hash_password(password)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dashboard_users (username, password_hash, role, is_active)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    password_hash = VALUES(password_hash),
                    role = VALUES(role),
                    is_active = VALUES(is_active)
                """,
                (uname, pw_hash, role, is_active),
            )


def bootstrap_admin(username: str, password: str):
    """Ensure the initial admin account from .env exists when the backend boots."""
    ensure_users_table()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM dashboard_users WHERE username = %s", (username.strip().lower(),))
            if not cur.fetchone():
                upsert_user(username, password, role="admin", is_active=True)


def authenticate_user(username: str, password: str) -> dict | None:
    """Validate login credentials and reject disabled accounts; returns user dict or None."""
    uname = username.strip().lower()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_hash, role, is_active FROM dashboard_users WHERE username = %s",
                (uname,),
            )
            row = cur.fetchone()
    if not row or not row["is_active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}
