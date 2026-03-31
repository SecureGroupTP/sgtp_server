# SGTP Servers

This repo contains:

- `sgtp-server`: SGTP relay (transparent frame forwarder).
- `sgtp-userdir`: TCP user directory (username/fullname/pubkey/avatar) with Ed25519-signed updates and Postgres persistence.

## Quick start (Docker Compose)

Requirements: Docker + Docker Compose.

Start everything:

```bash
docker compose up --build
```

Note: both local `go test` and Docker builds require downloading Go modules (e.g. `pgx`) from the internet on first run.

Services and default host ports:

- `sgtp_chat` → `70/tcp`
- `sgtp_voice` → `77/tcp`
- `sgtp_userdir` → `7070/tcp`
- `userdir_db` → internal Postgres (persisted via volume)

### Userdir env (configured in `docker-compose.yml`)

- `SERVER_PORT`: TCP port to listen on inside container (default in compose: `7070`)
- `PG_DSN`: Postgres DSN, e.g. `postgres://userdir:userdir@userdir_db:5432/userdir?sslmode=disable`
- `PROFILE_TTL`: how long profiles are kept (default: `24h`)
- `AVATAR_MAX_BYTES`: max avatar size (default: `33554432` = 32 MiB)
- `SEARCH_MAX_RESULTS`: hard cap for search responses (default: `20`)
- `CLEANUP_INTERVAL`: how often expired rows are deleted (default: `5m`)
- `SHUTDOWN_TIMEOUT`: graceful shutdown timeout (default: `10s`)

## `sgtp-userdir` wire protocol (TCP, binary, big-endian)

All messages are framed as:

```
u32  frame_len         // number of bytes after this field
u8   msg_type
...  payload           // (frame_len - 1) bytes
```

If `frame_len` exceeds the configured maximum (derived from `AVATAR_MAX_BYTES`), the connection is closed.

### Message types

- `0x01` REGISTER / UPDATE (signed)
- `0x02` SEARCH
- `0x03` GET_PROFILE
- `0x81` OK (response)
- `0x82` ERROR (response)
- `0x83` SEARCH_RESULTS (response)
- `0x84` PROFILE (response)

### REGISTER / UPDATE (`msg_type = 0x01`)

Semantics:

- Profile identity is the **public key** (`pubkey`).
- Sending REGISTER again with the same `pubkey` overwrites `username`, `fullname`, and `avatar` (upsert).
- Stored rows expire after `PROFILE_TTL`.

Payload layout:

```
u8    version          // currently: 1
u16   username_len
u8[]  username         // UTF-8; must match: ^@[A-Za-z0-9_]{1,32}$
u16   fullname_len
u8[]  fullname         // UTF-8 (arbitrary string)
u8[32] pubkey          // Ed25519 public key (raw 32 bytes)
u32   avatar_len       // must be <= AVATAR_MAX_BYTES
u8[]  avatar           // raw bytes
u8    sig_alg          // currently: 1 (Ed25519)
u8[64] signature       // Ed25519 signature
```

Signature verification:

The server verifies Ed25519 over the following bytes:

```
signed = msg_type (1 byte) || payload_without_signature_bytes
payload_without_signature_bytes = payload[0 : len(payload)-64]
```

I.e. everything in the payload **including** `sig_alg`, but excluding the final `signature[64]`.

On success the server replies `OK`.

### SEARCH (`msg_type = 0x02`)

Case-insensitive substring search (no regex). The DB query is implemented via `position(lower(q) in lower(field)) > 0`.

Payload:

```
u8   version           // 1
u16  query_len
u8[] query             // UTF-8
u16  limit             // server clamps to <= SEARCH_MAX_RESULTS
```

Response `SEARCH_RESULTS (0x83)` payload:

```
u8   version           // 1
u16  count
repeat count times:
  u8[32] pubkey
  u16   username_len
  u8[]  username
  u16   fullname_len
  u8[]  fullname
  u8[32] avatar_sha256 // SHA-256 of avatar bytes (binary)
```

### GET_PROFILE (`msg_type = 0x03`)

Payload:

```
u8    version          // 1
u8[32] pubkey
```

Response `PROFILE (0x84)` payload:

```
u8    version          // 1
u8[32] pubkey
u16   username_len
u8[]  username
u16   fullname_len
u8[]  fullname
u32   avatar_len
u8[]  avatar
u8[32] avatar_sha256
```

### OK (`msg_type = 0x81`)

Payload:

```
u16 msg_len
u8[] msg
```

### ERROR (`msg_type = 0x82`)

Payload:

```
u16 code
u16 msg_len
u8[] msg
```

Error codes:

- `0x0001` bad request
- `0x0002` bad signature
- `0x0003` not found
- `0x0004` internal error
