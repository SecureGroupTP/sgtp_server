# SGTP Servers

This repo contains two server binaries:

- `sgtp-server`: SGTP relay (transparent frame forwarder) with an **embedded user directory** on the same port.

The user directory was previously a separate `sgtp-userdir` binary and service. It is now multiplexed directly into each relay server port — no extra port needed.

## Quick start (Docker Compose)

Requirements: Docker + Docker Compose.

Copy `.env` and adjust ports if needed, then:

```bash
docker compose up --build
```

Note: both local `go test` and Docker builds require downloading Go modules (e.g. `pgx`) from the internet on first run.

Services and default host ports (see `.env`):

- `sgtp_chat` → `250/tcp` — chat relay + userdir
- `sgtp_voice` → `251/tcp` — voice relay + userdir
- `userdir_db` → internal Postgres only (persisted via volume, `127.0.0.1:5432` on host)
- `flyway` → one-shot migration runner (required; applies `db/migrations/*.sql` before `sgtp_chat`)

## Installation and admin setup

### First run (minimal input)

From `server` directory run:

```bash
./install.sh
```

What it does automatically:

- Creates `.env` from `.env.example` if missing
- Fills required defaults (`NGINX_SERVER_NAME`, `ADMIN_JWT_SECRET`, `ADMIN_BOOTSTRAP_FILE`)
- Generates self-signed TLS certs in `./certs` if needed
- Starts Docker stack (`flyway` + `userdir_db` + `sgtp_chat` + nginx/certbot services)
- Saves bootstrap root credentials to `./admin_bootstrap_credentials.txt` (first launch only)

### Manual setup

```bash
cp .env.example .env
docker compose up -d --build
```

`flyway` migrations are applied automatically before `sgtp_chat` starts.

### Main `.env` settings you usually change

- `CHAT_TCP_PORT` — SGTP TCP port
- `CHAT_HTTP_PORT` — HTTP port (admin API/UI and HTTP transport)
- `CHAT_WS_PORT` — WebSocket port
- `NGINX_SERVER_NAME` — domain for nginx/certs (`localhost` for local setup)
- `ADMIN_JWT_SECRET` — required for stable admin auth tokens (set explicit value in production)
- `TLS_CERT_FILE` + `TLS_KEY_FILE` — cert/key paths inside container (`/certs/...` by default)

### How to enter admin panel

1. Open `http://<host>:<CHAT_HTTP_PORT>/admin` (default: `http://localhost:8080/admin`).
2. Read first root credentials from `./admin_bootstrap_credentials.txt`.
3. Login via API:

```bash
curl -sS http://localhost:8080/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login_name":"<BOOTSTRAP_ROOT_LOGIN>","password":"<BOOTSTRAP_ROOT_PASSWORD>"}'
```

Response contains:

- `access_token` (Bearer token for protected `/admin/*` endpoints)
- `refresh_token`
- user info

4. Change root password after first login:

```bash
curl -sS http://localhost:8080/admin/users/change-password \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H 'Content-Type: application/json' \
  -d '{"new_password":"<NEW_STRONG_PASSWORD>"}'
```

### Basic admin operations

- Create additional admin (root only): `POST /admin/users`
- Update access mode (`open|whitelist|password|key`): `PUT /admin/settings/access`
- Update limits (per IP / per public_key): `PUT /admin/limits`
- Add/remove bans: `POST /admin/bans`, `DELETE /admin/bans?id=<id>`
- Trigger/list backups: `POST /admin/backups/run`, `GET /admin/backups`
- View usage: `GET /admin/stats/usage`

### Apply config changes

- Network settings saved via `PUT /admin/settings/network` are persisted in DB.
- Apply them with graceful restart:

```bash
docker compose restart sgtp_chat
```

## User directory: connecting on a relay port

To speak the userdir protocol, the client connects to any relay port (chat or voice) and sends **exactly 32 zero bytes** as a routing prefix before the first userdir frame:

```
u8[32]  magic   // all 0x00 — signals userdir intent
...             // normal userdir frames follow
```

The relay reads the first 32 bytes of every new connection. If they are all zero the connection is handed off to the userdir handler. Otherwise the bytes are treated as the first 32 bytes of an SGTP header (RoomUUID + ReceiverUUID) and the relay session proceeds as normal. The two protocols are fully compatible — a relay frame can never start with 32 zero bytes because that would mean both RoomUUID and ReceiverUUID are the broadcast/zero address.

## Server env variables

Legacy mode (default; no discovery):

- `SERVER_PORT` — TCP port inside the container (default: `7777`)
- `SERVER_ADDR` — optional listen address (e.g. `0.0.0.0:7777`)
- `SHUTDOWN_TIMEOUT` — graceful shutdown timeout (default: `10s`)

- Multi-transport mode starts as soon as any of `TCP_PORT`, `TCP_TLS_PORT`, `HTTP_PORT`,
- `HTTP_TLS_PORT`, `WS_PORT`, or `WS_TLS_PORT` is non-zero.
- The HTTP discovery handler lives on every configured HTTP/WS listener. `GET
- /sgtp/discovery` (and `HEAD /sgtp/discovery`) returns JSON describing the enabled transports
- plus the base64/hex version of the legacy 25-byte payload; append `?format=raw` or
- `?format=binary` to receive the raw blob directly.
- The server also sends the 25-byte discovery header at the start of each raw TCP connection
- so legacy clients can continue to read the capabilities payload before the SGTP handshake.
- For convenience, `TCP_PORT` defaults to `SERVER_PORT` when `TCP_PORT` is unset.
- Per-transport ports (set to `0` to disable):
  - `TCP_PORT`
  - `TCP_TLS_PORT` — TLS-encrypted SGTP (requires `TLS_CERT_FILE` + `TLS_KEY_FILE`)
  - `HTTP_PORT`
  - `HTTP_TLS_PORT` — HTTPS / WS upgrades; reuses the same mux as `HTTP_PORT`
  - `WS_PORT`
  - `WS_TLS_PORT` — secure WebSocket port (can match `HTTP_TLS_PORT`)
- Optional discovery-only overrides (advertised to clients; listeners stay on `*_PORT`):
  - `ADVERTISE_TCP_PORT`
  - `ADVERTISE_TCP_TLS_PORT`
  - `ADVERTISE_HTTP_PORT`
  - `ADVERTISE_HTTP_TLS_PORT`
  - `ADVERTISE_WS_PORT`
  - `ADVERTISE_WS_TLS_PORT`
  - Useful behind reverse-proxy/NAT (for example: listen on `HTTP_PORT=8080`, advertise `ADVERTISE_HTTP_TLS_PORT=443` and `ADVERTISE_WS_TLS_PORT=443`).
- TLS certificate/key (required when any TLS port is non-zero):
  - `TLS_CERT_FILE`
  - `TLS_KEY_FILE`
HTTP and WS handlers share their muxes, so you can point `HTTP_PORT`/`WS_PORT` and the TLS equivalents at the same number to serve both protocols from a single listener.
  - `docker-compose` по умолчанию монтирует каталог `./certs` в контейнер как `/certs`, а переменные `TLS_CERT_FILE`/`TLS_KEY_FILE` в `.env` ссылаются на `/certs/certificate.crt` и `/certs/certificate.key`. Если ваши файлы имеют другие имена, поправьте переменные и гарантируйте, что папка доступна внутри контейнера.

- Optional bind host:
  - `BIND_HOST` — e.g. `0.0.0.0` (default: empty = all interfaces)
- HTTP transport tuning:
  - `HTTP_RECV_TIMEOUT` (default: `60s`)
  - `HTTP_SEND_MAX_BYTES` (default: `16777216` = 16 MiB)
  - `HTTP_SESSION_BUFFER_BYTES` (default: `4194304` = 4 MiB per direction)
  - `HTTP_SESSION_TTL` (default: `10m`)
  - `HTTP_SESSION_CLEANUP` (default: `1m`)

User directory (enabled when `PG_DSN` is set; both `sgtp_chat` and `sgtp_voice` set it):

- `PG_DSN` — Postgres DSN, e.g. `postgres://userdir:userdir@userdir_db:5432/userdir?sslmode=disable`
- `AVATAR_MAX_BYTES` — max avatar size (default: `33554432` = 32 MiB)
- `SEARCH_MAX_RESULTS` — hard cap for search responses (default: `20`)
- `SUBSCRIBE_MAX` — max pubkeys one connection may subscribe to at once (default: `500`)
- `CLEANUP_INTERVAL` — cleanup loop interval (default: `5m`; currently profiles are stored indefinitely)

Admin control plane (enabled when `PG_DSN` is set):

- `ADMIN_JWT_SECRET` — HMAC secret for admin access tokens (recommended to set explicitly)
- `ADMIN_ACCESS_TTL` — access token TTL (default: `15m`)
- `ADMIN_REFRESH_TTL` — refresh token TTL (default: `168h`)
- `ADMIN_BOOTSTRAP_FILE` — where bootstrap root credentials are written once (default: `./admin_bootstrap_credentials.txt`)

On first start (empty `admin_users`) server creates exactly one bootstrap root account with random 64-char login/password and writes it into `ADMIN_BOOTSTRAP_FILE`.
After first creation, bootstrap account is never auto-created again.

Admin HTTP API lives on the same HTTP/HTTPS listeners:

- `POST /admin/auth/login`
- `POST /admin/auth/refresh`
- `POST /admin/auth/logout`
- `GET/PUT /admin/settings/network` (apply by graceful restart/reload)
- `GET/PUT /admin/settings/access`
- `GET/POST/DELETE /admin/bans`
- `GET/PUT /admin/limits`
- `GET /admin/stats/usage`
- `GET /admin/stats/users`
- `POST /admin/backups/run`
- `GET /admin/backups`
- `GET /admin/users/list` (search/filter/sort users by ip/public_key/traffic/time)
- `GET /admin/users/info` (detailed info + remaining limits for a user key)
- `GET /admin/users/limit` (read custom per-user limits)
- `PUT /admin/users/limit` (set custom per-user limits)
- `GET /admin/rooms/list` (search/filter/sort rooms by traffic/time)
- `GET /admin/rooms/info` (detailed info + remaining limits for room)
- `GET /admin/rooms/limit`
- `PUT /admin/rooms/limit`
- `GET /admin/limits/global` (global request/traffic limits for all users)
- `PUT /admin/limits/global`

## Userdir wire protocol (binary, big-endian)

After sending the 32-byte zero magic (see above), all messages are framed as:

```
u32  frame_len         // number of bytes after this field
u8   msg_type
...  payload           // (frame_len - 1) bytes
```

If `frame_len` exceeds the configured maximum (derived from `AVATAR_MAX_BYTES`) the connection is closed.

### Message types

| Type | Direction | Name |
|------|-----------|------|
| `0x01` | → server | REGISTER / UPDATE |
| `0x02` | → server | SEARCH |
| `0x03` | → server | GET_PROFILE |
| `0x04` | → server | GET_META |
| `0x05` | → server | SUBSCRIBE |
| `0x06` | → server | UNSUBSCRIBE |
| `0x81` | ← server | OK |
| `0x82` | ← server | ERROR |
| `0x83` | ← server | SEARCH_RESULTS |
| `0x84` | ← server | PROFILE |
| `0x85` | ← server | META |
| `0x86` | ← server | NOTIFY (unsolicited push) |

---

### REGISTER / UPDATE (`0x01`)

Profile identity is the **public key** (`pubkey`). Sending REGISTER again with the same `pubkey` overwrites `username`, `fullname`, and `avatar` (upsert). Profiles are stored indefinitely.
`username` must be unique across all profiles when present (case-insensitive, e.g. `@Alice` = `@alice`); `NULL` username is allowed and may appear in multiple profiles.

Payload:

```
u8     version          // 1
u16    username_len
u8[]   username         // UTF-8; optional (username_len may be 0). If non-empty: ^@[A-Za-z0-9_]{1,32}$
u16    fullname_len
u8[]   fullname         // UTF-8
u8[32] pubkey           // Ed25519 public key
u32    avatar_len       // must be <= AVATAR_MAX_BYTES
u8[]   avatar
u8     sig_alg          // 1 = Ed25519
u8[64] signature
```

Signature covers: `msg_type (1 byte) || payload_without_last_64_bytes`.

On success: `OK (0x81)`.

---

### SEARCH (`0x02`)

Case-insensitive substring match on `username` and `fullname`.

Request payload:

```
u8   version            // 1
u16  query_len
u8[] query              // UTF-8; empty query returns 0 results
u16  limit              // clamped to SEARCH_MAX_RESULTS
```

Response `SEARCH_RESULTS (0x83)`:

```
u8   version            // 1
u16  count
// repeated count times:
u8[32] pubkey
u16    username_len
u8[]   username
u16    fullname_len
u8[]   fullname
u8[32] avatar_sha256
```

---

### GET_PROFILE (`0x03`)

Returns the full profile including avatar bytes.

Request payload:

```
u8     version          // 1
u8[32] pubkey
```

Response `PROFILE (0x84)`:

```
u8     version          // 1
u8[32] pubkey
u16    username_len
u8[]   username
u16    fullname_len
u8[]   fullname
u32    avatar_len
u8[]   avatar
u8[32] avatar_sha256
u64    updated_at       // Unix timestamp (seconds UTC)
```

---

### GET_META (`0x04`)

Lightweight lookup — returns identity fields and the last-update timestamp **without** sending avatar bytes. Use this to check whether a cached avatar is still current (compare `avatar_sha256`) before fetching the full profile.

Request payload (same format as GET_PROFILE):

```
u8     version          // 1
u8[32] pubkey
```

Response `META (0x85)`:

```
u8     version          // 1
u8[32] pubkey
u16    username_len
u8[]   username
u16    fullname_len
u8[]   fullname
u8[32] avatar_sha256
u64    updated_at       // Unix timestamp (seconds UTC)
```

---

### OK (`0x81`)

```
u16  msg_len
u8[] msg
```

### ERROR (`0x82`)

```
u16  code
u16  msg_len
u8[] msg
```

Error codes:

| Code | Meaning |
|------|---------|
| `0x0001` | bad request |
| `0x0002` | bad signature |
| `0x0003` | not found |
| `0x0004` | internal error |

---

### SUBSCRIBE (`0x05`)

Subscribes to profile-change notifications for a list of public keys. The connection stays open; the server will push a `NOTIFY` frame any time one of the subscribed profiles is updated via REGISTER.

Multiple SUBSCRIBE calls on the same connection are additive — they append to the existing subscription set. The server-side limit per connection is `SUBSCRIBE_MAX` (default: 500). Exceeding it returns an `ERROR`.

Request payload:

```
u8     version          // 1
u16    count            // number of pubkeys to subscribe to
u8[32] pubkey[]         // list of pubkeys (count entries)
```

Response: `OK (0x81)` or `ERROR (0x82)`.

---

### UNSUBSCRIBE (`0x06`)

Removes pubkeys from the subscription set. `count == 0` unsubscribes from all.

Request payload (same format as SUBSCRIBE):

```
u8     version          // 1
u16    count            // 0 = unsubscribe all
u8[32] pubkey[]         // list of pubkeys (count entries)
```

Response: `OK (0x81)`.

---

### NOTIFY (`0x86`) — server push

Sent by the server without a request whenever a subscribed profile is updated. The payload is identical to `META (0x85)`. The client should never send this type.

```
u8     version          // 1
u8[32] pubkey
u16    username_len
u8[]   username
u16    fullname_len
u8[]   fullname
u8[32] avatar_sha256
u64    updated_at       // Unix timestamp (seconds UTC)
```

The `avatar_sha256` field lets the client decide whether to fetch the full profile (avatar changed) or just update the displayed name/username (avatar unchanged).
