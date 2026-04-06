CREATE TABLE IF NOT EXISTS client_activity_v3 (
  id bigserial PRIMARY KEY,
  ip text NOT NULL,
  public_key text NOT NULL DEFAULT '',
  first_use timestamptz NOT NULL,
  last_use timestamptz NOT NULL,
  requests bigint NOT NULL DEFAULT 0,
  bytes_recv bigint NOT NULL DEFAULT 0,
  bytes_sent bigint NOT NULL DEFAULT 0,
  transport text NOT NULL DEFAULT 'tcp',
  last_status text NOT NULL DEFAULT 'ok',
  UNIQUE (ip, public_key)
);

INSERT INTO client_activity_v3 (ip, public_key, first_use, last_use, requests, bytes_recv, bytes_sent, transport, last_status)
SELECT
  ip,
  COALESCE(public_key, ''),
  MIN(first_use),
  MAX(last_use),
  SUM(requests),
  SUM(bytes_recv),
  SUM(bytes_sent),
  MAX(transport),
  MAX(last_status)
FROM client_activity
GROUP BY ip, COALESCE(public_key, '')
ON CONFLICT (ip, public_key) DO UPDATE SET
  first_use = LEAST(client_activity_v3.first_use, EXCLUDED.first_use),
  last_use = GREATEST(client_activity_v3.last_use, EXCLUDED.last_use),
  requests = client_activity_v3.requests + EXCLUDED.requests,
  bytes_recv = client_activity_v3.bytes_recv + EXCLUDED.bytes_recv,
  bytes_sent = client_activity_v3.bytes_sent + EXCLUDED.bytes_sent,
  transport = EXCLUDED.transport,
  last_status = EXCLUDED.last_status;

DROP TABLE client_activity;
ALTER TABLE client_activity_v3 RENAME TO client_activity;

CREATE INDEX IF NOT EXISTS client_activity_last_use_idx ON client_activity(last_use DESC);
