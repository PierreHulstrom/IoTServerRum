"""Database connection helper for MariaDB (internal Docker network only)."""

import os
import pymysql
from pymysql.cursors import DictCursor


def get_conn():
    """Open a new autocommit MariaDB connection returning rows as Python dicts."""
    return pymysql.connect(
        host=os.getenv("DB_HOST", "mariadb"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("MARIADB_USER", "iot_admin"),
        password=os.getenv("MARIADB_PASSWORD", ""),
        database=os.getenv("MARIADB_DATABASE", "serverroom"),
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
    )


def db_ping() -> bool:
    """Quick liveness check used by /api/health and the dashboard status pill."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False
