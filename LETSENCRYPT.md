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

Tip: add a cron/systemd timer on the host to run renew periodically.
