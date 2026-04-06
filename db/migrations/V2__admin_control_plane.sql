CREATE TABLE IF NOT EXISTS admin_users (
  id bigserial PRIMARY KEY,
  login_name text NOT NULL UNIQUE,
  display_name text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('root','admin')),
  force_password_change boolean NOT NULL DEFAULT false,
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  refresh_token_hash bytea NOT NULL,
  user_agent text,
  remote_ip text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (refresh_token_hash)
);
CREATE INDEX IF NOT EXISTS admin_sessions_user_idx ON admin_sessions(user_id, expires_at DESC);

CREATE TABLE IF NOT EXISTS server_settings (
  key text PRIMARY KEY,
  value_json jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_policy (
  id smallint PRIMARY KEY DEFAULT 1,
  mode text NOT NULL CHECK (mode IN ('open','whitelist','password','key')),
  password_hash text,
  shared_key_hash bytea,
  whitelist_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (id = 1)
);
INSERT INTO access_policy (id, mode)
VALUES (1, 'open')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS ban_rules (
  id bigserial PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('username','public_key','ip')),
  value text NOT NULL,
  reason text NOT NULL DEFAULT '',
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by bigint REFERENCES admin_users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ban_rules_lookup_idx ON ban_rules(kind, value);
CREATE INDEX IF NOT EXISTS ban_rules_expires_idx ON ban_rules(expires_at);

CREATE TABLE IF NOT EXISTS usage_limits (
  id smallint PRIMARY KEY DEFAULT 1,
  per_ip_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  per_pubkey_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (id = 1)
);
INSERT INTO usage_limits (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS usage_counters (
  scope text NOT NULL CHECK (scope IN ('ip','public_key')),
  subject text NOT NULL,
  bucket text NOT NULL CHECK (bucket IN ('minute','hour','day','week','month')),
  bucket_start timestamptz NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  bytes_recv bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, subject, bucket, bucket_start)
);
CREATE INDEX IF NOT EXISTS usage_counters_subject_idx ON usage_counters(scope, subject, updated_at DESC);

CREATE TABLE IF NOT EXISTS usage_rollups (
  id bigserial PRIMARY KEY,
  scope text NOT NULL CHECK (scope IN ('ip','public_key')),
  subject text NOT NULL,
  window_name text NOT NULL CHECK (window_name IN ('minute','hour','day','week','month')),
  requests bigint NOT NULL,
  bytes_recv bigint NOT NULL,
  bytes_sent bigint NOT NULL,
  sampled_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS usage_rollups_idx ON usage_rollups(scope, subject, window_name, sampled_at DESC);

CREATE TABLE IF NOT EXISTS client_activity (
  id bigserial PRIMARY KEY,
  ip text NOT NULL,
  public_key text,
  first_use timestamptz NOT NULL,
  last_use timestamptz NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  bytes_recv bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  transport text NOT NULL DEFAULT 'tcp',
  last_status text NOT NULL DEFAULT 'ok',
  UNIQUE (ip, public_key)
);
CREATE INDEX IF NOT EXISTS client_activity_last_use_idx ON client_activity(last_use DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  actor_user_id bigint REFERENCES admin_users(id) ON DELETE SET NULL,
  action text NOT NULL,
  object_type text NOT NULL,
  object_id text,
  payload_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC);

CREATE TABLE IF NOT EXISTS backup_jobs (
  id bigserial PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('queued','running','success','failed')),
  output_path text,
  started_at timestamptz,
  finished_at timestamptz,
  error_message text,
  retention_days integer NOT NULL DEFAULT 7,
  created_by bigint REFERENCES admin_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO server_settings (key, value_json)
VALUES
  ('network', '{"tcp_port":7777,"tcp_tls_port":0,"http_port":0,"http_tls_port":0,"ws_port":0,"ws_tls_port":0}'::jsonb),
  ('cleanup', '{"username_inactive_days":90}'::jsonb),
  ('rooms', '{"max_participants":0}'::jsonb),
  ('backups', '{"enabled":false,"directory":"./backups","retention_days":7}'::jsonb)
ON CONFLICT (key) DO NOTHING;
