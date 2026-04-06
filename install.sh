#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Support both layouts:
# 1) repo root is current directory (contains .env.example, docker-compose.yml)
# 2) monorepo root with nested ./server directory.
if [[ -f "$ROOT_DIR/.env.example" && -f "$ROOT_DIR/docker-compose.yml" ]]; then
  SERVER_DIR="$ROOT_DIR"
elif [[ -f "$ROOT_DIR/server/.env.example" && -f "$ROOT_DIR/server/docker-compose.yml" ]]; then
  SERVER_DIR="$ROOT_DIR/server"
else
  SERVER_DIR="$ROOT_DIR"
fi

ENV_EXAMPLE="$SERVER_DIR/.env.example"
ENV_FILE="$SERVER_DIR/.env"

log() {
  printf '[install] %s\n' "$*"
}

fail() {
  printf '[install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Required command not found: $1"
  fi
}

get_env() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  grep -E "^${key}=" "$ENV_FILE" | tail -n1 | cut -d'=' -f2-
}

set_env() {
  local key="$1"
  local value="$2"

  if grep -qE "^${key}=" "$ENV_FILE"; then
    sed -i "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'
  fi
}

ensure_env_file() {
  [[ -f "$ENV_EXAMPLE" ]] || fail "Missing $ENV_EXAMPLE"

  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    log "Created $ENV_FILE from .env.example"
  else
    log "Using existing $ENV_FILE"
  fi

  local domain
  domain="$(get_env NGINX_SERVER_NAME)"
  if [[ -z "$domain" ]]; then
    set_env "NGINX_SERVER_NAME" "localhost"
    log "Set NGINX_SERVER_NAME=localhost"
  fi

  local admin_secret
  admin_secret="$(get_env ADMIN_JWT_SECRET)"
  if [[ -z "$admin_secret" ]]; then
    set_env "ADMIN_JWT_SECRET" "$(gen_token)"
    log "Generated ADMIN_JWT_SECRET"
  fi

  local bootstrap_file
  bootstrap_file="$(get_env ADMIN_BOOTSTRAP_FILE)"
  if [[ -z "$bootstrap_file" ]]; then
    set_env "ADMIN_BOOTSTRAP_FILE" "/tmp/admin_bootstrap_credentials.txt"
    log "Set ADMIN_BOOTSTRAP_FILE=/tmp/admin_bootstrap_credentials.txt"
  fi
}

ensure_certs() {
  local crt key host_crt host_key domain
  crt="$(get_env TLS_CERT_FILE)"
  key="$(get_env TLS_KEY_FILE)"
  domain="$(get_env NGINX_SERVER_NAME)"

  [[ -n "$crt" ]] || return 0
  [[ -n "$key" ]] || return 0

  if [[ "$crt" != /certs/* || "$key" != /certs/* ]]; then
    log "TLS paths are not in /certs/*, skipping auto certificate generation"
    return 0
  fi

  mkdir -p "$SERVER_DIR/certs" "$SERVER_DIR/certbot/www" "$SERVER_DIR/certbot/conf"

  host_crt="$SERVER_DIR/certs/${crt#/certs/}"
  host_key="$SERVER_DIR/certs/${key#/certs/}"

  if [[ -f "$host_crt" && -f "$host_key" ]]; then
    log "TLS certificate already exists: $host_crt"
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1; then
    log "openssl not found; disabling TLS ports"
    set_env "CHAT_TCP_TLS_PORT" "0"
    set_env "CHAT_HTTP_TLS_PORT" "0"
    set_env "CHAT_WS_TLS_PORT" "0"
    set_env "ADVERTISE_TCP_TLS_PORT" "0"
    set_env "ADVERTISE_HTTP_TLS_PORT" "0"
    set_env "ADVERTISE_WS_TLS_PORT" "0"
    return 0
  fi

  mkdir -p "$(dirname "$host_crt")" "$(dirname "$host_key")"

  log "Generating self-signed TLS certificate for CN=${domain:-localhost}"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -days 3650 \
    -keyout "$host_key" \
    -out "$host_crt" \
    -subj "/CN=${domain:-localhost}" >/dev/null 2>&1

  log "Generated certificate: $host_crt"
}

start_server() {
  cd "$SERVER_DIR"
  log "Starting SGTP server stack via docker compose"
  docker compose up -d --build
}

save_bootstrap_credentials() {
  cd "$SERVER_DIR"

  local service_name="sgtp_chat"
  local remote_file local_file
  remote_file="$(get_env ADMIN_BOOTSTRAP_FILE)"
  local_file="$ROOT_DIR/admin_bootstrap_credentials.txt"

  [[ -n "$remote_file" ]] || return 0

  # Give the service a moment to create bootstrap credentials on first run.
  sleep 2

  if docker compose ps --status running --services | grep -qx "$service_name"; then
    if docker compose exec -T "$service_name" sh -lc "test -f '$remote_file'" >/dev/null 2>&1; then
      docker compose exec -T "$service_name" sh -lc "cat '$remote_file'" > "$local_file" || true
      if [[ -s "$local_file" ]]; then
        chmod 600 "$local_file"
        log "Saved bootstrap admin credentials to $local_file"
      fi
    fi
  fi
}

print_summary() {
  local chat_port
  chat_port="$(get_env CHAT_TCP_PORT)"
  chat_port="${chat_port:-250}"

  cat <<MSG

[install] Done.

Useful commands:
  cd server && docker compose ps
  cd server && docker compose logs -f sgtp_chat

Server endpoints (default):
  SGTP TCP: ${chat_port}
  Admin API/UI (if HTTP enabled): /admin on CHAT_HTTP_PORT

If this was the first run, check bootstrap admin credentials in:
  $ROOT_DIR/admin_bootstrap_credentials.txt
MSG
}

main() {
  require_cmd docker
  docker compose version >/dev/null 2>&1 || fail "docker compose plugin is required"

  ensure_env_file
  ensure_certs
  start_server
  save_bootstrap_credentials
  print_summary
}

main "$@"
