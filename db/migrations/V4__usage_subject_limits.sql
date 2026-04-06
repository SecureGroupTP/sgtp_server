CREATE TABLE IF NOT EXISTS usage_subject_limits (
  scope text NOT NULL CHECK (scope IN ('ip','public_key')),
  subject text NOT NULL,
  limits_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, subject)
);

CREATE INDEX IF NOT EXISTS usage_subject_limits_updated_idx ON usage_subject_limits(updated_at DESC);
