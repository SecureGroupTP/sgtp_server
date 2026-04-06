-- V7: Admin panel v2 — tables for new admin CRM spec
-- Adds: user_bans, ip_bans, room_bans, user_room_bans, invite_links, admin_panel_settings, trusted_ips

-- ══════════════════════════════════════════════════
-- Ban tables (history-preserving, each record = one ban event)
-- ══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS user_bans (
    id            BIGSERIAL    PRIMARY KEY,
    public_key    TEXT         NOT NULL,
    reason        TEXT,
    banned_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    unbanned_at   TIMESTAMPTZ,
    unbanned_reason TEXT,
    banned_by     TEXT         NOT NULL,
    unbanned_by   TEXT
);
CREATE INDEX idx_user_bans_pubkey ON user_bans (public_key);
CREATE INDEX idx_user_bans_active ON user_bans (public_key) WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now());

CREATE TABLE IF NOT EXISTS ip_bans (
    id            BIGSERIAL    PRIMARY KEY,
    ip_address    TEXT         NOT NULL,
    reason        TEXT,
    banned_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    unbanned_at   TIMESTAMPTZ,
    unbanned_reason TEXT,
    banned_by     TEXT         NOT NULL,
    unbanned_by   TEXT
);
CREATE INDEX idx_ip_bans_ip ON ip_bans (ip_address);
CREATE INDEX idx_ip_bans_active ON ip_bans (ip_address) WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now());

CREATE TABLE IF NOT EXISTS room_bans (
    id            BIGSERIAL    PRIMARY KEY,
    room_uuid     TEXT         NOT NULL,
    reason        TEXT,
    banned_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    unbanned_at   TIMESTAMPTZ,
    unbanned_reason TEXT,
    banned_by     TEXT         NOT NULL,
    unbanned_by   TEXT
);
CREATE INDEX idx_room_bans_uuid ON room_bans (room_uuid);
CREATE INDEX idx_room_bans_active ON room_bans (room_uuid) WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now());

CREATE TABLE IF NOT EXISTS user_room_bans (
    id            BIGSERIAL    PRIMARY KEY,
    public_key    TEXT         NOT NULL,
    room_uuid     TEXT         NOT NULL,
    reason        TEXT,
    banned_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    unbanned_at   TIMESTAMPTZ,
    unbanned_reason TEXT,
    banned_by     TEXT         NOT NULL,
    unbanned_by   TEXT
);
CREATE INDEX idx_user_room_bans_pk ON user_room_bans (public_key);
CREATE INDEX idx_user_room_bans_room ON user_room_bans (room_uuid);
CREATE INDEX idx_user_room_bans_active ON user_room_bans (public_key, room_uuid) WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now());

-- ══════════════════════════════════════════════════
-- Invite links
-- ══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS invite_links (
    id                 BIGSERIAL    PRIMARY KEY,
    token              TEXT         NOT NULL UNIQUE,
    generated_username TEXT         NOT NULL UNIQUE,
    status             TEXT         NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'used', 'revoked', 'expired')),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ  NOT NULL,
    used_at            TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_by         BIGINT       REFERENCES admin_users(id)
);
CREATE INDEX idx_invite_links_token ON invite_links (token);
CREATE INDEX idx_invite_links_status ON invite_links (status);

-- ══════════════════════════════════════════════════
-- Admin panel settings (key-value, applied without restart)
-- ══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS admin_panel_settings (
    key          TEXT         PRIMARY KEY,
    value_json   JSONB        NOT NULL DEFAULT '{}',
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Default settings
INSERT INTO admin_panel_settings (key, value_json) VALUES
    ('default_traffic_limit_bytes', '0'),
    ('default_traffic_limit_period', '"per_day"'),
    ('default_rate_limit_rps', '0'),
    ('online_timeout_seconds', '60'),
    ('chain_search_depth', '5'),
    ('stats_retention_days', '90'),
    ('audit_log_retention_days', '365'),
    ('ban_history_retention_days', '0'),
    ('admin_session_ttl_hours', '24'),
    ('invite_default_ttl_hours', '72'),
    ('ui_polling_interval_ms', '3000')
ON CONFLICT (key) DO NOTHING;

-- ══════════════════════════════════════════════════
-- Trusted IPs (excluded from chain detection)
-- ══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS trusted_ips (
    ip_address   TEXT         PRIMARY KEY,
    added_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    added_by     TEXT
);

-- ══════════════════════════════════════════════════
-- Extend client_activity with user profile fields (for API v1)
-- ══════════════════════════════════════════════════

-- Add user-level traffic/rate limits columns to userdir_profiles if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='userdir_profiles' AND column_name='traffic_limit_bytes') THEN
        ALTER TABLE userdir_profiles ADD COLUMN traffic_limit_bytes BIGINT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='userdir_profiles' AND column_name='traffic_limit_period') THEN
        ALTER TABLE userdir_profiles ADD COLUMN traffic_limit_period TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='userdir_profiles' AND column_name='request_rate_limit') THEN
        ALTER TABLE userdir_profiles ADD COLUMN request_rate_limit INT;
    END IF;
END $$;

-- ══════════════════════════════════════════════════
-- Extended audit log for new action types
-- ══════════════════════════════════════════════════

-- Add admin_ip column to audit_log if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='admin_ip') THEN
        ALTER TABLE audit_log ADD COLUMN admin_ip TEXT;
    END IF;
END $$;

-- ══════════════════════════════════════════════════
-- Backup settings table
-- ══════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS backup_settings (
    id                    INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    cron_expression       TEXT DEFAULT '0 3 * * *',
    retention_count       INT,
    retention_max_age_days INT,
    local_path            TEXT DEFAULT './backups',
    s3_endpoint           TEXT,
    s3_bucket             TEXT,
    s3_access_key         TEXT,
    s3_secret_key         TEXT,
    s3_prefix             TEXT,
    s3_region             TEXT,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO backup_settings (id) VALUES (1) ON CONFLICT DO NOTHING;
