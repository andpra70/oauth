#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d node_modules ]]; then
  npm install
fi

# In sviluppo locale l'SMTP di Mailpit arriva dalla macchina remota tramite
# app/tunnel.sh. Le variabili già esportate dall'utente mantengono la priorità.
export MAIL_ENABLED="${MAIL_ENABLED:-true}"
export SMTP_HOST="${SMTP_HOST:-127.0.0.1}"
export SMTP_PORT="${SMTP_PORT:-1025}"
export SMTP_SECURE="${SMTP_SECURE:-false}"
export MAIL_FROM="${MAIL_FROM:-no-reply@localhost}"
export PASSWORD_RESET_PUBLIC_URL="${PASSWORD_RESET_PUBLIC_URL:-http://localhost:9000/oauth-server/reset-password}"

if ! (exec 3<>"/dev/tcp/${SMTP_HOST}/${SMTP_PORT}") 2>/dev/null; then
  printf 'Mailpit SMTP non raggiungibile su %s:%s. Avvia prima app/tunnel.sh.\n' "${SMTP_HOST}" "${SMTP_PORT}" >&2
  exit 1
fi
exec 3>&-
exec 3<&-

npm run ui:build
npm run dev:all
