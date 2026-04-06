CREATE TABLE IF NOT EXISTS room_user_activity (
  room_id text NOT NULL,
  ip text NOT NULL,
  public_key text NOT NULL DEFAULT '',
  first_use timestamptz NOT NULL,
  last_use timestamptz NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  bytes_recv bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (room_id, ip, public_key)
);

CREATE INDEX IF NOT EXISTS room_user_activity_room_idx ON room_user_activity(room_id, last_use DESC);
