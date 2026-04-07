-- V8: Create userdir_profiles table for API v1 user traffic/rate limit queries.
-- store_api_v1.go references userdir_profiles (public_key TEXT PK) while
-- store.go references the original user_profiles (pubkey bytea PK).

CREATE TABLE IF NOT EXISTS userdir_profiles (
    public_key           TEXT PRIMARY KEY DEFAULT '',
    username             TEXT,
    fullname             TEXT NOT NULL DEFAULT '',
    traffic_limit_bytes  BIGINT,
    traffic_limit_period TEXT,
    request_rate_limit   INT
);
