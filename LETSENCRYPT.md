# Nginx + Let's Encrypt (Docker Compose)

This project now ships with `nginx` and `certbot` services in `docker-compose.yml`.

## 1) Prepare `.env`

Set these values:

- `NGINX_SERVER_NAME` - your public domain (for example `chat3.f0rg3t.su`)
- `LETSENCRYPT_EMAIL` - email for Let's Encrypt registration

The chat HTTP backend is internal (`CHAT_HTTP_PORT=8080`), and nginx publishes `80`/`443`.

## 2) Start stack (first run = HTTP only)

```bash
docker compose up -d --build
```

If cert files are missing, nginx starts in HTTP-only mode automatically.

## 3) Issue certificate

```bash
docker compose run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  -d "${NGINX_SERVER_NAME}" \
  --email "${LETSENCRYPT_EMAIL}" \
  --agree-tos --no-eff-email
```

## 4) Reload nginx with TLS config

```bash
docker compose restart nginx
```

After restart, nginx detects `./certbot/conf/live/<domain>/` and enables HTTPS.

## 5) Verify discovery

```bash
curl -vk "https://${NGINX_SERVER_NAME}/sgtp/discovery"
```

Raw discovery payload (25 bytes):

```bash
curl -vk "https://${NGINX_SERVER_NAME}/sgtp/discovery?format=raw" --output /tmp/discovery.bin
wc -c /tmp/discovery.bin
```

## Renew certificate

```bash
docker compose run --rm certbot renew
docker compose restart nginx
```

## Optional: same cert on TCP TLS (`:444`)

If `CHAT_TCP_TLS_PORT` is enabled (default `444`), the app reads certs from:

- `TLS_CERT_FILE=/certs/certificate.crt`
- `TLS_KEY_FILE=/certs/certificate.key`

To use the same Let's Encrypt certificate as nginx (`:443`), copy it after issue/renew:

```bash
LE_DIR="$(for d in ./certbot/conf/live/*; do [ -f "$d/fullchain.pem" ] && [ -f "$d/privkey.pem" ] && { echo "$d"; break; }; done)"
[ -n "$LE_DIR" ] || { echo "LE cert not found in ./certbot/conf/live"; exit 1; }
cp "$LE_DIR/fullchain.pem" ./certs/certificate.crt
cp "$LE_DIR/privkey.pem"  ./certs/certificate.key
chown 65532:65532 ./certs/certificate.crt ./certs/certificate.key
chmod 644 ./certs/certificate.crt
chmod 600 ./certs/certificate.key
docker compose up -d --build sgtp_chat
```

Tip: add a cron/systemd timer on the host to run renew periodically.
