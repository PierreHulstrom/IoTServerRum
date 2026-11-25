#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/opt/serverroom-iot/backups"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +"%Y%m%d_%H%M%S")
docker exec serverroom-db sh -c 'mariadb-dump -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"' \
  | gzip > "$BACKUP_DIR/serverroom_${STAMP}.sql.gz"
find "$BACKUP_DIR" -name "serverroom_*.sql.gz" -mtime +14 -delete
echo "Backup OK: $BACKUP_DIR/serverroom_${STAMP}.sql.gz"
