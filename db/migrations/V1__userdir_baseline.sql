CREATE TABLE IF NOT EXISTS user_profiles (
  pubkey bytea PRIMARY KEY,
  username text,
  fullname text NOT NULL,
  avatar bytea NOT NULL,
  avatar_sha256 bytea NOT NULL,
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT 'infinity'::timestamptz
);

ALTER TABLE user_profiles
  ALTER COLUMN username DROP NOT NULL;

UPDATE user_profiles
SET expires_at = 'infinity'::timestamptz
WHERE expires_at <> 'infinity'::timestamptz;

DROP INDEX IF EXISTS user_profiles_username_unique_not_null;

CREATE UNIQUE INDEX IF NOT EXISTS user_profiles_username_unique_not_null
ON user_profiles (lower(username))
WHERE username IS NOT NULL;

CREATE TABLE IF NOT EXISTS friend_requests (
  id bigserial PRIMARY KEY,
  requester bytea NOT NULL CHECK (octet_length(requester) = 32),
  recipient bytea NOT NULL CHECK (octet_length(recipient) = 32),
  status smallint NOT NULL CHECK (status IN (1,2,3)),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  responded_at timestamptz
);

CREATE INDEX IF NOT EXISTS friend_requests_requester_idx
ON friend_requests (requester, updated_at DESC);

CREATE INDEX IF NOT EXISTS friend_requests_recipient_idx
ON friend_requests (recipient, updated_at DESC);

CREATE TABLE IF NOT EXISTS dm_rooms (
  user_a bytea NOT NULL CHECK (octet_length(user_a) = 32),
  user_b bytea NOT NULL CHECK (octet_length(user_b) = 32),
  room_uuid bytea NOT NULL CHECK (octet_length(room_uuid) = 16),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_a, user_b),
  UNIQUE (room_uuid)
);
