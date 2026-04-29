#!/usr/bin/env bash
# Build the seed test DB. Wipes and recreates `<arch>-<sha>.db` in the
# directory passed as $1 (defaults to ./test/dbs).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCHEMA="$HERE/../../indexer/schema.sql"
SEED="$HERE/seed.sql"

OUT_DIR="${1:-$HERE/dbs}"
mkdir -p "$OUT_DIR"

DB="$OUT_DIR/x86_64-deadbeefcafebabe1234567890abcdef00112233.db"
rm -f "$DB"

sqlite3 "$DB" < "$SCHEMA" >/dev/null
sqlite3 "$DB" < "$SEED" >/dev/null

echo "wrote $DB"
sqlite3 "$DB" "SELECT key,value FROM meta;"
