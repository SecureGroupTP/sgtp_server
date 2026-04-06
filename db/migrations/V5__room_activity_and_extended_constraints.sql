ALTER TABLE usage_counters
  DROP CONSTRAINT IF EXISTS usage_counters_scope_check;
ALTER TABLE usage_counters
  ADD CONSTRAINT usage_counters_scope_check
  CHECK (scope IN ('ip','public_key','global','room'));

ALTER TABLE usage_subject_limits
  DROP CONSTRAINT IF EXISTS usage_subject_limits_scope_check;
ALTER TABLE usage_subject_limits
  ADD CONSTRAINT usage_subject_limits_scope_check
  CHECK (scope IN ('ip','public_key','global','room'));

ALTER TABLE ban_rules
  DROP CONSTRAINT IF EXISTS ban_rules_kind_check;
ALTER TABLE ban_rules
  ADD CONSTRAINT ban_rules_kind_check
  CHECK (kind IN ('username','public_key','ip','room'));

CREATE TABLE IF NOT EXISTS room_activity (
  room_id text PRIMARY KEY,
  first_use timestamptz NOT NULL,
  last_use timestamptz NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  bytes_recv bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  current_members integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS room_activity_last_use_idx ON room_activity(last_use DESC);
CREATE INDEX IF NOT EXISTS room_activity_requests_idx ON room_activity(requests DESC);
