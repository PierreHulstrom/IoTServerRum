"""CLI utility to create or update dashboard users directly inside the backend container."""

import sys
from auth_utils import ensure_users_table, upsert_user

if __name__ == "__main__":
    # Expects: python manage_users.py <username> <password> [admin|operator|viewer]
    if len(sys.argv) < 3:
        print("Brug: python manage_users.py <brugernavn> <kodeord> [admin|operator|viewer]")
        sys.exit(1)
    ensure_users_table()
    uname = sys.argv[1]
    pw = sys.argv[2]
    role = sys.argv[3] if len(sys.argv) > 3 else "admin"
    upsert_user(uname, pw, role=role)
    print(f"OK: bruger '{uname.lower()}' oprettet/opdateret med rolle '{role}'")
