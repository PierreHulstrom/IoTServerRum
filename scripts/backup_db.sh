#!/usr/bin/env bash
# Daily automated MariaDB backup script (scheduled via cron at 03:00, 14-day retention)
set -euo pipefail

BACKUP_DIR="/opt/serverroom-iot/backups"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +"%Y%m%d_%H%M%S")

# Dump database from inside the MariaDB container and compress with gzip
docker exec serverroom-db sh -c 'mariadb-dump -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"' \
  | gzip > "$BACKUP_DIR/serverroom_${STAMP}.sql.gz"

# Delete backup archives older than 14 days to keep disk usage bounded
find "$BACKUP_DIR" -name "serverroom_*.sql.gz" -mtime +14 -delete
echo "Backup OK: $BACKUP_DIR/serverroom_${STAMP}.sql.gz"
