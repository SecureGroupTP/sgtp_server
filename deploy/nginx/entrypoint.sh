#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${NGINX_SERVER_NAME:-localhost}"
UPSTREAM_HOST="${UPSTREAM_HOST:-sgtp_chat}"
UPSTREAM_PORT="${UPSTREAM_PORT:-8080}"

export NGINX_SERVER_NAME="$DOMAIN"
export UPSTREAM_HOST
export UPSTREAM_PORT

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ -f "${CERT_DIR}/fullchain.pem" ] && [ -f "${CERT_DIR}/privkey.pem" ]; then
  envsubst '${NGINX_SERVER_NAME} ${UPSTREAM_HOST} ${UPSTREAM_PORT}' \
    < /etc/nginx/templates/https.conf.template \
    > /etc/nginx/conf.d/default.conf
  echo "[nginx] using TLS cert from ${CERT_DIR}"
else
  envsubst '${NGINX_SERVER_NAME} ${UPSTREAM_HOST} ${UPSTREAM_PORT}' \
    < /etc/nginx/templates/http-only.conf.template \
    > /etc/nginx/conf.d/default.conf
  echo "[nginx] TLS cert not found, started in HTTP-only mode"
fi

exec nginx -g 'daemon off;'
