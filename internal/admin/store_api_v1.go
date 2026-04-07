package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ════════════════════════════════════════════════════════════════════
// V7 Types — ban tables, invite links, settings, trusted IPs, backups
// ════════════════════════════════════════════════════════════════════

type UserBan struct {
	ID             int64      `json:"id"`
	PublicKey      string     `json:"public_key"`
	Reason         string     `json:"reason"`
	BannedAt       time.Time  `json:"banned_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	UnbannedAt     *time.Time `json:"unbanned_at,omitempty"`
	UnbannedReason string     `json:"unbanned_reason,omitempty"`
	BannedBy       string     `json:"banned_by"`
	UnbannedBy     string     `json:"unbanned_by,omitempty"`
}

type IPBan struct {
	ID             int64      `json:"id"`
	IPAddress      string     `json:"ip_address"`
	Reason         string     `json:"reason"`
	BannedAt       time.Time  `json:"banned_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	UnbannedAt     *time.Time `json:"unbanned_at,omitempty"`
	UnbannedReason string     `json:"unbanned_reason,omitempty"`
	BannedBy       string     `json:"banned_by"`
	UnbannedBy     string     `json:"unbanned_by,omitempty"`
}

type RoomBan struct {
	ID             int64      `json:"id"`
	RoomUUID       string     `json:"room_uuid"`
	Reason         string     `json:"reason"`
	BannedAt       time.Time  `json:"banned_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	UnbannedAt     *time.Time `json:"unbanned_at,omitempty"`
	UnbannedReason string     `json:"unbanned_reason,omitempty"`
	BannedBy       string     `json:"banned_by"`
	UnbannedBy     string     `json:"unbanned_by,omitempty"`
}

type UserRoomBan struct {
	ID             int64      `json:"id"`
	PublicKey      string     `json:"public_key"`
	RoomUUID       string     `json:"room_uuid"`
	Reason         string     `json:"reason"`
	BannedAt       time.Time  `json:"banned_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	UnbannedAt     *time.Time `json:"unbanned_at,omitempty"`
	UnbannedReason string     `json:"unbanned_reason,omitempty"`
	BannedBy       string     `json:"banned_by"`
	UnbannedBy     string     `json:"unbanned_by,omitempty"`
}

type InviteLink struct {
	ID                int64      `json:"id"`
	Token             string     `json:"token"`
	GeneratedUsername string     `json:"generated_username"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	UsedAt            *time.Time `json:"used_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	CreatedBy         *int64     `json:"created_by,omitempty"`
}

type TrustedIP struct {
	IPAddress string    `json:"ip_address"`
	AddedAt   time.Time `json:"added_at"`
	AddedBy   string    `json:"added_by,omitempty"`
}

type BackupSettings struct {
	ID                  int     `json:"id"`
	CronExpression      string  `json:"cron_expression"`
	RetentionCount      *int    `json:"retention_count,omitempty"`
	RetentionMaxAgeDays *int    `json:"retention_max_age_days,omitempty"`
	LocalPath           string  `json:"local_path"`
	S3Endpoint          *string `json:"s3_endpoint,omitempty"`
	S3Bucket            *string `json:"s3_bucket,omitempty"`
	S3AccessKey         *string `json:"s3_access_key,omitempty"`
	S3SecretKey         *string `json:"s3_secret_key,omitempty"`
	S3Prefix            *string `json:"s3_prefix,omitempty"`
	S3Region            *string `json:"s3_region,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type DashboardMetrics struct {
	TotalUsers       int64 `json:"total_users"`
	OnlineUsers      int64 `json:"online_users"`
	TotalRooms       int64 `json:"total_rooms"`
	ActiveRooms      int64 `json:"active_rooms"`
	TotalBans        int64 `json:"total_bans"`
	TotalRequests    int64 `json:"total_requests"`
	TotalBytesRecv   int64 `json:"total_bytes_recv"`
	TotalBytesSent   int64 `json:"total_bytes_sent"`
	ActiveAdmins     int64 `json:"active_admins"`
	PendingInvites   int64 `json:"pending_invites"`
}

// ════════════════════════════════════════════════════════════════════
// User Bans
// ════════════════════════════════════════════════════════════════════

func (s *Store) InsertUserBan(ctx context.Context, publicKey, reason, bannedBy string, expiresAt *time.Time) (*UserBan, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO user_bans (public_key, reason, banned_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, public_key, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
`, publicKey, reason, bannedBy, expiresAt)
	return scanUserBan(row)
}

func (s *Store) UnbanUser(ctx context.Context, publicKey, unbannedBy, unbannedReason string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE user_bans
SET unbanned_at = now(), unbanned_by = $2, unbanned_reason = $3
WHERE public_key = $1 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, publicKey, unbannedBy, unbannedReason)
	return err
}

func (s *Store) ListActiveUserBans(ctx context.Context, limit, offset int) ([]UserBan, int64, error) {
	limit, offset = clampPagination(limit, offset)
	var total int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM user_bans WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, public_key, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM user_bans
WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY banned_at DESC
LIMIT $1 OFFSET $2
`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanUserBans(rows)
	return out, total, err
}

func (s *Store) ListUserBansByPubKey(ctx context.Context, publicKey string) ([]UserBan, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, public_key, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM user_bans
WHERE public_key = $1
ORDER BY banned_at DESC
`, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserBans(rows)
}

func (s *Store) IsUserBanned(ctx context.Context, publicKey string) (bool, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM user_bans
WHERE public_key = $1 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, publicKey).Scan(&n)
	return n > 0, err
}

// ════════════════════════════════════════════════════════════════════
// IP Bans
// ════════════════════════════════════════════════════════════════════

func (s *Store) InsertIPBan(ctx context.Context, ipAddress, reason, bannedBy string, expiresAt *time.Time) (*IPBan, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO ip_bans (ip_address, reason, banned_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, ip_address, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
`, ipAddress, reason, bannedBy, expiresAt)
	return scanIPBan(row)
}

func (s *Store) UnbanIP(ctx context.Context, ipAddress, unbannedBy, unbannedReason string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE ip_bans
SET unbanned_at = now(), unbanned_by = $2, unbanned_reason = $3
WHERE ip_address = $1 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, ipAddress, unbannedBy, unbannedReason)
	return err
}

func (s *Store) ListActiveIPBans(ctx context.Context, limit, offset int) ([]IPBan, int64, error) {
	limit, offset = clampPagination(limit, offset)
	var total int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM ip_bans WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ip_address, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM ip_bans
WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY banned_at DESC
LIMIT $1 OFFSET $2
`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanIPBans(rows)
	return out, total, err
}

func (s *Store) ListIPBanHistory(ctx context.Context, ipAddress string) ([]IPBan, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ip_address, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM ip_bans
WHERE ip_address = $1
ORDER BY banned_at DESC
`, ipAddress)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIPBans(rows)
}

// ════════════════════════════════════════════════════════════════════
// Room Bans
// ════════════════════════════════════════════════════════════════════

func (s *Store) InsertRoomBan(ctx context.Context, roomUUID, reason, bannedBy string, expiresAt *time.Time) (*RoomBan, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO room_bans (room_uuid, reason, banned_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
`, roomUUID, reason, bannedBy, expiresAt)
	return scanRoomBan(row)
}

func (s *Store) UnbanRoom(ctx context.Context, roomUUID, unbannedBy, unbannedReason string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE room_bans
SET unbanned_at = now(), unbanned_by = $2, unbanned_reason = $3
WHERE room_uuid = $1 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, roomUUID, unbannedBy, unbannedReason)
	return err
}

func (s *Store) ListActiveRoomBans(ctx context.Context, limit, offset int) ([]RoomBan, int64, error) {
	limit, offset = clampPagination(limit, offset)
	var total int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM room_bans WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM room_bans
WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY banned_at DESC
LIMIT $1 OFFSET $2
`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanRoomBans(rows)
	return out, total, err
}

func (s *Store) ListRoomBansByUUID(ctx context.Context, roomUUID string) ([]RoomBan, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM room_bans
WHERE room_uuid = $1
ORDER BY banned_at DESC
`, roomUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoomBans(rows)
}

// ════════════════════════════════════════════════════════════════════
// User-Room Bans
// ════════════════════════════════════════════════════════════════════

func (s *Store) InsertUserRoomBan(ctx context.Context, publicKey, roomUUID, reason, bannedBy string, expiresAt *time.Time) (*UserRoomBan, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO user_room_bans (public_key, room_uuid, reason, banned_by, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, public_key, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
`, publicKey, roomUUID, reason, bannedBy, expiresAt)
	return scanUserRoomBan(row)
}

func (s *Store) UnbanUserFromRoom(ctx context.Context, publicKey, roomUUID, unbannedBy, unbannedReason string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE user_room_bans
SET unbanned_at = now(), unbanned_by = $3, unbanned_reason = $4
WHERE public_key = $1 AND room_uuid = $2 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, publicKey, roomUUID, unbannedBy, unbannedReason)
	return err
}

func (s *Store) ListUserRoomBansByPubKey(ctx context.Context, publicKey string) ([]UserRoomBan, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, public_key, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM user_room_bans
WHERE public_key = $1
ORDER BY banned_at DESC
`, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserRoomBans(rows)
}

func (s *Store) ListUserRoomBansByRoom(ctx context.Context, roomUUID string) ([]UserRoomBan, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, public_key, room_uuid, COALESCE(reason,''), banned_at, expires_at, unbanned_at, COALESCE(unbanned_reason,''), banned_by, COALESCE(unbanned_by,'')
FROM user_room_bans
WHERE room_uuid = $1
ORDER BY banned_at DESC
`, roomUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserRoomBans(rows)
}

// ════════════════════════════════════════════════════════════════════
// Invite Links
// ════════════════════════════════════════════════════════════════════

func (s *Store) CreateInviteLink(ctx context.Context, token, generatedUsername string, expiresAt time.Time, createdBy int64) (*InviteLink, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO invite_links (token, generated_username, status, expires_at, created_by)
VALUES ($1, $2, 'pending', $3, $4)
RETURNING id, token, generated_username, status, created_at, expires_at, used_at, revoked_at, created_by
`, token, generatedUsername, expiresAt, createdBy)
	return scanInviteLink(row)
}

func (s *Store) ListInviteLinks(ctx context.Context, limit, offset int) ([]InviteLink, int64, error) {
	limit, offset = clampPagination(limit, offset)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invite_links`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, token, generated_username, status, created_at, expires_at, used_at, revoked_at, created_by
FROM invite_links
ORDER BY created_at DESC
LIMIT $1 OFFSET $2
`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanInviteLinks(rows)
	return out, total, err
}

func (s *Store) GetInviteLinkByToken(ctx context.Context, token string) (*InviteLink, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, token, generated_username, status, created_at, expires_at, used_at, revoked_at, created_by
FROM invite_links
WHERE token = $1
`, token)
	return scanInviteLink(row)
}

func (s *Store) GetInviteLinkByID(ctx context.Context, id int64) (*InviteLink, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, token, generated_username, status, created_at, expires_at, used_at, revoked_at, created_by
FROM invite_links
WHERE id = $1
`, id)
	return scanInviteLink(row)
}

func (s *Store) RevokeInviteLink(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE invite_links SET status = 'revoked', revoked_at = now() WHERE id = $1 AND status = 'pending'
`, id)
	return err
}

func (s *Store) UseInviteLink(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE invite_links SET status = 'used', used_at = now()
WHERE token = $1 AND status = 'pending' AND expires_at > now()
`, token)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("invite link not found, expired, or already used")
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════
// Admin Panel Settings
// ════════════════════════════════════════════════════════════════════

func (s *Store) GetAllPanelSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value_json FROM admin_panel_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage)
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = json.RawMessage(v)
	}
	return out, rows.Err()
}

func (s *Store) GetPanelSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value_json FROM admin_panel_settings WHERE key = $1`, key).Scan(&v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(v), nil
}

func (s *Store) PutPanelSetting(ctx context.Context, key string, value json.RawMessage) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO admin_panel_settings (key, value_json, updated_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE SET value_json = EXCLUDED.value_json, updated_at = now()
`, key, []byte(value))
	return err
}

// ════════════════════════════════════════════════════════════════════
// Trusted IPs
// ════════════════════════════════════════════════════════════════════

func (s *Store) ListTrustedIPs(ctx context.Context) ([]TrustedIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ip_address, added_at, COALESCE(added_by,'') FROM trusted_ips ORDER BY added_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]TrustedIP, 0, 16)
	for rows.Next() {
		var t TrustedIP
		if err := rows.Scan(&t.IPAddress, &t.AddedAt, &t.AddedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) AddTrustedIP(ctx context.Context, ip, addedBy string) (*TrustedIP, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO trusted_ips (ip_address, added_by)
VALUES ($1, $2)
ON CONFLICT (ip_address) DO UPDATE SET added_by = EXCLUDED.added_by, added_at = now()
RETURNING ip_address, added_at, COALESCE(added_by,'')
`, ip, addedBy)
	var t TrustedIP
	if err := row.Scan(&t.IPAddress, &t.AddedAt, &t.AddedBy); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) DeleteTrustedIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM trusted_ips WHERE ip_address = $1`, ip)
	return err
}

// ════════════════════════════════════════════════════════════════════
// Backup Settings
// ════════════════════════════════════════════════════════════════════

func (s *Store) GetBackupSettings(ctx context.Context) (*BackupSettings, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, COALESCE(cron_expression,''), retention_count, retention_max_age_days,
       COALESCE(local_path,''), s3_endpoint, s3_bucket, s3_access_key, s3_secret_key, s3_prefix, s3_region, updated_at
FROM backup_settings WHERE id = 1
`)
	var bs BackupSettings
	if err := row.Scan(
		&bs.ID, &bs.CronExpression, &bs.RetentionCount, &bs.RetentionMaxAgeDays,
		&bs.LocalPath, &bs.S3Endpoint, &bs.S3Bucket, &bs.S3AccessKey, &bs.S3SecretKey, &bs.S3Prefix, &bs.S3Region, &bs.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &bs, nil
}

func (s *Store) PutBackupSettings(ctx context.Context, bs BackupSettings) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE backup_settings SET
  cron_expression = $1,
  retention_count = $2,
  retention_max_age_days = $3,
  local_path = $4,
  s3_endpoint = $5,
  s3_bucket = $6,
  s3_access_key = $7,
  s3_secret_key = $8,
  s3_prefix = $9,
  s3_region = $10,
  updated_at = now()
WHERE id = 1
`, bs.CronExpression, bs.RetentionCount, bs.RetentionMaxAgeDays,
		bs.LocalPath, bs.S3Endpoint, bs.S3Bucket, bs.S3AccessKey, bs.S3SecretKey, bs.S3Prefix, bs.S3Region)
	return err
}

func (s *Store) DeleteBackupJob(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM backup_jobs WHERE id = $1`, id)
	return err
}

// ════════════════════════════════════════════════════════════════════
// Dashboard Metrics
// ════════════════════════════════════════════════════════════════════

func (s *Store) GetDashboardMetrics(ctx context.Context) (*DashboardMetrics, error) {
	m := &DashboardMetrics{}

	// Total unique users (distinct public keys + IP-only users)
	_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT CASE
  WHEN COALESCE(public_key,'') <> '' THEN public_key
  ELSE CONCAT('ip:', ip)
END) FROM client_activity
`).Scan(&m.TotalUsers)

	// Online users (seen in last 5 minutes)
	_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT CASE
  WHEN COALESCE(public_key,'') <> '' THEN public_key
  ELSE CONCAT('ip:', ip)
END) FROM client_activity
WHERE last_use > now() - INTERVAL '5 minutes'
`).Scan(&m.OnlineUsers)

	// Total rooms
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM room_activity`).Scan(&m.TotalRooms)

	// Active rooms (had activity in last hour)
	_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM room_activity WHERE last_use > now() - INTERVAL '1 hour'
`).Scan(&m.ActiveRooms)

	// Active user bans
	_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM user_bans WHERE unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`).Scan(&m.TotalBans)

	// Aggregate totals
	_ = s.db.QueryRowContext(ctx, `
SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes_recv),0), COALESCE(SUM(bytes_sent),0)
FROM client_activity
`).Scan(&m.TotalRequests, &m.TotalBytesRecv, &m.TotalBytesSent)

	// Active admins (not disabled)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users WHERE disabled = false`).Scan(&m.ActiveAdmins)

	// Pending invites
	_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM invite_links WHERE status = 'pending' AND expires_at > now()
`).Scan(&m.PendingInvites)

	return m, nil
}

// GetDashboardChart returns time-series data for the given chart type.
// Supported chart types: requests, traffic, users, rooms.
func (s *Store) GetDashboardChart(ctx context.Context, chartType string, days int) ([]map[string]any, error) {
	if days <= 0 {
		days = 30
	}
	if days > 365 {
		days = 365
	}

	var q string
	switch chartType {
	case "requests":
		q = `
SELECT date_trunc('day', bucket_start)::date AS day, SUM(requests) AS value
FROM usage_counters
WHERE scope = 'global' AND subject = '*' AND bucket = 'day'
  AND bucket_start >= now() - make_interval(days => $1)
GROUP BY day ORDER BY day`
	case "traffic":
		q = `
SELECT date_trunc('day', bucket_start)::date AS day, SUM(bytes_recv + bytes_sent) AS value
FROM usage_counters
WHERE scope = 'global' AND subject = '*' AND bucket = 'day'
  AND bucket_start >= now() - make_interval(days => $1)
GROUP BY day ORDER BY day`
	case "users":
		q = `
SELECT date_trunc('day', first_use)::date AS day, COUNT(*) AS value
FROM client_activity
WHERE first_use >= now() - make_interval(days => $1)
GROUP BY day ORDER BY day`
	case "rooms":
		q = `
SELECT date_trunc('day', first_use)::date AS day, COUNT(*) AS value
FROM room_activity
WHERE first_use >= now() - make_interval(days => $1)
GROUP BY day ORDER BY day`
	default:
		return nil, fmt.Errorf("unknown chart type: %s", chartType)
	}

	rows, err := s.db.QueryContext(ctx, q, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, days)
	for rows.Next() {
		var day time.Time
		var value int64
		if err := rows.Scan(&day, &value); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"date":  day.Format("2006-01-02"),
			"value": value,
		})
	}
	return out, rows.Err()
}

// ════════════════════════════════════════════════════════════════════
// Active Admin Sessions
// ════════════════════════════════════════════════════════════════════

func (s *Store) ListActiveSessions(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT
  s.id,
  s.user_id,
  COALESCE(u.login_name,'') AS login_name,
  COALESCE(u.display_name,'') AS display_name,
  COALESCE(s.user_agent,'') AS user_agent,
  COALESCE(s.remote_ip,'') AS remote_ip,
  s.created_at,
  s.expires_at
FROM admin_sessions s
LEFT JOIN admin_users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL AND s.expires_at > now()
ORDER BY s.created_at DESC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var id, userID int64
		var login, display, ua, ip string
		var created, expires time.Time
		if err := rows.Scan(&id, &userID, &login, &display, &ua, &ip, &created, &expires); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":           id,
			"user_id":      userID,
			"login_name":   login,
			"display_name": display,
			"user_agent":   ua,
			"remote_ip":    ip,
			"created_at":   created,
			"expires_at":   expires,
		})
	}
	return out, rows.Err()
}

// ════════════════════════════════════════════════════════════════════
// Paginated Count helpers
// ════════════════════════════════════════════════════════════════════

func (s *Store) CountUsersDetailed(ctx context.Context, search, ipFilter, pubFilter string) (int64, error) {
	searchPat := likePattern(search)
	ipPat := likePattern(ipFilter)
	pubPat := likePattern(pubFilter)

	var total int64
	err := s.db.QueryRowContext(ctx, `
WITH grouped AS (
  SELECT
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END AS user_key,
    COALESCE(NULLIF(public_key,''), '') AS public_key,
    STRING_AGG(DISTINCT ip, ', ' ORDER BY ip) AS ips
  FROM client_activity
  GROUP BY
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END,
    COALESCE(NULLIF(public_key,''), '')
)
SELECT COUNT(*) FROM grouped
WHERE ($1 = '' OR user_key ILIKE $1 OR ips ILIKE $1)
  AND ($2 = '' OR ips ILIKE $2)
  AND ($3 = '' OR public_key ILIKE $3)
`, searchPat, ipPat, pubPat).Scan(&total)
	return total, err
}

func (s *Store) CountRoomsDetailed(ctx context.Context, search string) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM room_activity
WHERE ($1 = '' OR room_id ILIKE $1)
`, likePattern(search)).Scan(&total)
	return total, err
}

// ════════════════════════════════════════════════════════════════════
// Chain Detection (BFS over shared IPs)
// ════════════════════════════════════════════════════════════════════

// ChainDetect performs a BFS starting from a given public_key to find
// other public keys that share IP addresses. It returns a list of edges.
func (s *Store) ChainDetect(ctx context.Context, publicKey string, maxDepth int) ([]map[string]any, error) {
	if maxDepth <= 0 {
		maxDepth = 5
	}

	// Get trusted IPs to exclude
	trustedIPs, err := s.ListTrustedIPs(ctx)
	if err != nil {
		return nil, err
	}
	trustedSet := make(map[string]bool, len(trustedIPs))
	for _, t := range trustedIPs {
		trustedSet[t.IPAddress] = true
	}

	type edge struct {
		From     string `json:"from"`
		To       string `json:"to"`
		SharedIP string `json:"shared_ip"`
		Depth    int    `json:"depth"`
	}

	frontier := make([]string, 0, 8)
	visited := make(map[string]bool, 8)
	if strings.HasPrefix(publicKey, "ip:") {
		ip := strings.TrimPrefix(publicKey, "ip:")
		rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT public_key
FROM client_activity
WHERE ip = $1 AND COALESCE(public_key, '') <> ''
`, ip)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var pk string
			if err := rows.Scan(&pk); err != nil {
				rows.Close()
				return nil, err
			}
			if strings.TrimSpace(pk) == "" {
				continue
			}
			visited[pk] = true
			frontier = append(frontier, pk)
		}
		rows.Close()
		if rows.Err() != nil {
			return nil, rows.Err()
		}
	} else {
		visited[publicKey] = true
		frontier = append(frontier, publicKey)
	}
	if len(frontier) == 0 {
		return []map[string]any{}, nil
	}
	var edges []map[string]any

	for depth := 1; depth <= maxDepth && len(frontier) > 0; depth++ {
		placeholders := make([]string, len(frontier))
		args := make([]any, len(frontier))
		for i, pk := range frontier {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = pk
		}

		q := fmt.Sprintf(`
SELECT a.public_key AS from_pk, b.public_key AS to_pk, a.ip AS shared_ip
FROM client_activity a
JOIN client_activity b ON a.ip = b.ip AND a.public_key <> b.public_key
WHERE a.public_key IN (%s)
  AND COALESCE(a.public_key,'') <> ''
  AND COALESCE(b.public_key,'') <> ''
`, strings.Join(placeholders, ","))

		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}

		var nextFrontier []string
		for rows.Next() {
			var fromPK, toPK, sharedIP string
			if err := rows.Scan(&fromPK, &toPK, &sharedIP); err != nil {
				rows.Close()
				return nil, err
			}
			if trustedSet[sharedIP] {
				continue
			}
			edges = append(edges, map[string]any{
				"from":      fromPK,
				"to":        toPK,
				"shared_ip": sharedIP,
				"depth":     depth,
			})
			if !visited[toPK] {
				visited[toPK] = true
				nextFrontier = append(nextFrontier, toPK)
			}
		}
		rows.Close()
		if rows.Err() != nil {
			return nil, rows.Err()
		}
		frontier = nextFrontier
	}

	if edges == nil {
		edges = []map[string]any{}
	}
	return edges, nil
}

// ════════════════════════════════════════════════════════════════════
// User IPs and Rooms
// ════════════════════════════════════════════════════════════════════

func (s *Store) ListUserIPs(ctx context.Context, publicKey string) ([]map[string]any, error) {
	if strings.HasPrefix(publicKey, "ip:") {
		ip := strings.TrimPrefix(publicKey, "ip:")
		rows, err := s.db.QueryContext(ctx, `
SELECT ip, MIN(first_use) AS first_use, MAX(last_use) AS last_use,
       SUM(requests) AS requests, SUM(bytes_recv) AS bytes_recv, SUM(bytes_sent) AS bytes_sent,
       EXISTS(
         SELECT 1 FROM ip_bans b
         WHERE b.ip_address = $1
           AND b.unbanned_at IS NULL
           AND (b.expires_at IS NULL OR b.expires_at > now())
       ) AS is_banned
FROM client_activity
WHERE ip = $1
GROUP BY ip
ORDER BY MAX(last_use) DESC
`, ip)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make([]map[string]any, 0, 4)
		for rows.Next() {
			var ipRow string
			var first, last time.Time
			var req, br, bs int64
			var isBanned bool
			if err := rows.Scan(&ipRow, &first, &last, &req, &br, &bs, &isBanned); err != nil {
				return nil, err
			}
			out = append(out, map[string]any{
				"ip":         ipRow,
				"first_use":  first,
				"last_use":   last,
				"requests":   req,
				"bytes_recv": br,
				"bytes_sent": bs,
				"is_banned":  isBanned,
			})
		}
		return out, rows.Err()
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT ip, first_use, last_use, requests, bytes_recv, bytes_sent
FROM client_activity
WHERE public_key = $1
ORDER BY last_use DESC
`, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var ip string
		var first, last time.Time
		var req, br, bs int64
		if err := rows.Scan(&ip, &first, &last, &req, &br, &bs); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ip":         ip,
			"first_use":  first,
			"last_use":   last,
			"requests":   req,
			"bytes_recv": br,
			"bytes_sent": bs,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListUserRooms(ctx context.Context, publicKey string) ([]map[string]any, error) {
	if strings.HasPrefix(publicKey, "ip:") {
		ip := strings.TrimPrefix(publicKey, "ip:")
		rows, err := s.db.QueryContext(ctx, `
SELECT room_id,
       MIN(first_use) AS first_use,
       MAX(last_use) AS last_use,
       SUM(requests) AS requests,
       SUM(bytes_recv) AS bytes_recv,
       SUM(bytes_sent) AS bytes_sent
FROM room_user_activity
WHERE ip = $1
GROUP BY room_id
ORDER BY MAX(last_use) DESC
`, ip)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make([]map[string]any, 0, 16)
		for rows.Next() {
			var roomID string
			var first, last time.Time
			var req, br, bs int64
			if err := rows.Scan(&roomID, &first, &last, &req, &br, &bs); err != nil {
				return nil, err
			}
			out = append(out, map[string]any{
				"room_id":    roomID,
				"first_use":  first,
				"last_use":   last,
				"requests":   req,
				"bytes_recv": br,
				"bytes_sent": bs,
			})
		}
		return out, rows.Err()
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT room_id, first_use, last_use, requests, bytes_recv, bytes_sent
FROM room_user_activity
WHERE public_key = $1
ORDER BY last_use DESC
`, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var roomID string
		var first, last time.Time
		var req, br, bs int64
		if err := rows.Scan(&roomID, &first, &last, &req, &br, &bs); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"room_id":    roomID,
			"first_use":  first,
			"last_use":   last,
			"requests":   req,
			"bytes_recv": br,
			"bytes_sent": bs,
		})
	}
	return out, rows.Err()
}

// ListRoomParticipantsOnline returns participants in a room seen within the online timeout.
func (s *Store) ListRoomParticipantsOnline(ctx context.Context, roomUUID string, onlineTimeoutSec int) ([]map[string]any, error) {
	if onlineTimeoutSec <= 0 {
		onlineTimeoutSec = 60
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, COALESCE(public_key,''), last_use, requests, bytes_recv, bytes_sent
FROM room_user_activity
WHERE room_id = $1 AND last_use > now() - make_interval(secs => $2)
ORDER BY last_use DESC
`, roomUUID, onlineTimeoutSec)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var ip, pub string
		var last time.Time
		var req, br, bs int64
		if err := rows.Scan(&ip, &pub, &last, &req, &br, &bs); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ip":         ip,
			"public_key": pub,
			"last_use":   last,
			"requests":   req,
			"bytes_recv": br,
			"bytes_sent": bs,
		})
	}
	return out, rows.Err()
}

// ListRoomIPs returns distinct IPs seen in a given room.
func (s *Store) ListRoomIPs(ctx context.Context, roomUUID string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, MIN(first_use) AS first_use, MAX(last_use) AS last_use,
       SUM(requests) AS requests, SUM(bytes_recv) AS bytes_recv, SUM(bytes_sent) AS bytes_sent
FROM room_user_activity
WHERE room_id = $1
GROUP BY ip
ORDER BY MAX(last_use) DESC
`, roomUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, 16)
	for rows.Next() {
		var ip string
		var first, last time.Time
		var req, br, bs int64
		if err := rows.Scan(&ip, &first, &last, &req, &br, &bs); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ip":         ip,
			"first_use":  first,
			"last_use":   last,
			"requests":   req,
			"bytes_recv": br,
			"bytes_sent": bs,
		})
	}
	return out, rows.Err()
}

// ════════════════════════════════════════════════════════════════════
// Audit log — scoped by object
// ════════════════════════════════════════════════════════════════════

func (s *Store) ListAuditLog(ctx context.Context, objectType, objectID, actionLike string, limit, offset int) ([]map[string]any, int64, error) {
	limit, offset = clampPagination(limit, offset)

	var total int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM audit_log
WHERE ($1 = '' OR object_type = $1)
  AND ($2 = '' OR object_id = $2)
  AND ($3 = '' OR action ILIKE $3)
`, objectType, objectID, likePattern(actionLike)).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT
  l.id,
  l.actor_user_id,
  COALESCE(u.login_name, ''),
  COALESCE(u.display_name, ''),
  l.action,
  l.object_type,
  COALESCE(l.object_id, ''),
  l.payload_json,
  l.created_at
FROM audit_log l
LEFT JOIN admin_users u ON u.id = l.actor_user_id
WHERE ($1 = '' OR l.object_type = $1)
  AND ($2 = '' OR l.object_id = $2)
  AND ($3 = '' OR l.action ILIKE $3)
ORDER BY l.id DESC
LIMIT $4 OFFSET $5
`, objectType, objectID, likePattern(actionLike), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var id, actor sql.NullInt64
		var login, display, action, objType, objID string
		var payloadRaw []byte
		var created time.Time
		if err := rows.Scan(&id, &actor, &login, &display, &action, &objType, &objID, &payloadRaw, &created); err != nil {
			return nil, 0, err
		}
		var payload any = map[string]any{}
		if len(payloadRaw) > 0 {
			_ = json.Unmarshal(payloadRaw, &payload)
		}
		out = append(out, map[string]any{
			"id":            id.Int64,
			"actor_user_id": actor.Int64,
			"actor_login":   login,
			"actor_name":    display,
			"action":        action,
			"object_type":   objType,
			"object_id":     objID,
			"payload":       payload,
			"created_at":    created,
		})
	}
	return out, total, rows.Err()
}

// ════════════════════════════════════════════════════════════════════
// Bulk operations for bans
// ════════════════════════════════════════════════════════════════════

func (s *Store) BulkBanUsers(ctx context.Context, publicKeys []string, reason, bannedBy string, expiresAt *time.Time) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int64
	for _, pk := range publicKeys {
		pk = strings.TrimSpace(pk)
		if pk == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO user_bans (public_key, reason, banned_by, expires_at)
VALUES ($1, $2, $3, $4)
`, pk, reason, bannedBy, expiresAt)
		if err != nil {
			return 0, err
		}
		count++
	}
	return count, tx.Commit()
}

func (s *Store) BulkUnbanUsers(ctx context.Context, publicKeys []string, unbannedBy, unbannedReason string) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int64
	for _, pk := range publicKeys {
		pk = strings.TrimSpace(pk)
		if pk == "" {
			continue
		}
		res, err := tx.ExecContext(ctx, `
UPDATE user_bans SET unbanned_at = now(), unbanned_by = $2, unbanned_reason = $3
WHERE public_key = $1 AND unbanned_at IS NULL AND (expires_at IS NULL OR expires_at > now())
`, pk, unbannedBy, unbannedReason)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		count += n
	}
	return count, tx.Commit()
}

// ════════════════════════════════════════════════════════════════════
// User per-user traffic/rate limits (on userdir_profiles)
// ════════════════════════════════════════════════════════════════════

func (s *Store) GetUserTrafficLimits(ctx context.Context, publicKey string) (map[string]any, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT COALESCE(traffic_limit_bytes, 0), COALESCE(traffic_limit_period, ''), COALESCE(request_rate_limit, 0)
FROM userdir_profiles
WHERE public_key = $1
`, publicKey)
	var bytes int64
	var period string
	var rateLimit int
	if err := row.Scan(&bytes, &period, &rateLimit); err != nil {
		if err == sql.ErrNoRows {
			return map[string]any{
				"traffic_limit_bytes":  int64(0),
				"traffic_limit_period": "",
				"request_rate_limit":   0,
			}, nil
		}
		return nil, err
	}
	return map[string]any{
		"traffic_limit_bytes":  bytes,
		"traffic_limit_period": period,
		"request_rate_limit":   rateLimit,
	}, nil
}

func (s *Store) PutUserTrafficLimits(ctx context.Context, publicKey string, trafficBytes int64, period string, rateLimit int) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE userdir_profiles
SET traffic_limit_bytes = $2, traffic_limit_period = $3, request_rate_limit = $4
WHERE public_key = $1
`, publicKey, trafficBytes, period, rateLimit)
	return err
}

func (s *Store) DeleteUserTrafficLimits(ctx context.Context, publicKey string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE userdir_profiles
SET traffic_limit_bytes = NULL, traffic_limit_period = NULL, request_rate_limit = NULL
WHERE public_key = $1
`, publicKey)
	return err
}

// BulkPutUserTrafficLimits sets traffic limits for multiple users at once.
func (s *Store) BulkPutUserTrafficLimits(ctx context.Context, publicKeys []string, trafficBytes int64, period string, rateLimit int) (int64, error) {
	if len(publicKeys) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int64
	for _, pk := range publicKeys {
		pk = strings.TrimSpace(pk)
		if pk == "" {
			continue
		}
		res, err := tx.ExecContext(ctx, `
UPDATE userdir_profiles
SET traffic_limit_bytes = $2, traffic_limit_period = $3, request_rate_limit = $4
WHERE public_key = $1
`, pk, trafficBytes, period, rateLimit)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		count += n
	}
	return count, tx.Commit()
}

// ════════════════════════════════════════════════════════════════════
// Ban all users in a room
// ════════════════════════════════════════════════════════════════════

func (s *Store) BanAllUsersInRoom(ctx context.Context, roomUUID, reason, bannedBy string, expiresAt *time.Time) (int64, error) {
	// Get all distinct public keys in the room
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT public_key FROM room_user_activity
WHERE room_id = $1 AND COALESCE(public_key,'') <> ''
`, roomUUID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var pks []string
	for rows.Next() {
		var pk string
		if err := rows.Scan(&pk); err != nil {
			return 0, err
		}
		pks = append(pks, pk)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(pks) == 0 {
		return 0, nil
	}
	return s.BulkBanUsers(ctx, pks, reason, bannedBy, expiresAt)
}

// GetAdminUserByUsername returns an admin user by login_name.
func (s *Store) GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, login_name, display_name, role, force_password_change, disabled, created_at
FROM admin_users
WHERE login_name = $1
`, username)
	var u AdminUser
	var roleStr string
	if err := row.Scan(&u.ID, &u.LoginName, &u.DisplayName, &roleStr, &u.ForcePasswordChange, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.Role = UserRole(roleStr)
	return &u, nil
}

// ════════════════════════════════════════════════════════════════════
// Scan helpers
// ════════════════════════════════════════════════════════════════════

func clampPagination(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

type scannable interface {
	Scan(dest ...any) error
}

func scanUserBan(row scannable) (*UserBan, error) {
	var b UserBan
	if err := row.Scan(&b.ID, &b.PublicKey, &b.Reason, &b.BannedAt, &b.ExpiresAt,
		&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanUserBans(rows *sql.Rows) ([]UserBan, error) {
	out := make([]UserBan, 0, 16)
	for rows.Next() {
		var b UserBan
		if err := rows.Scan(&b.ID, &b.PublicKey, &b.Reason, &b.BannedAt, &b.ExpiresAt,
			&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanIPBan(row scannable) (*IPBan, error) {
	var b IPBan
	if err := row.Scan(&b.ID, &b.IPAddress, &b.Reason, &b.BannedAt, &b.ExpiresAt,
		&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanIPBans(rows *sql.Rows) ([]IPBan, error) {
	out := make([]IPBan, 0, 16)
	for rows.Next() {
		var b IPBan
		if err := rows.Scan(&b.ID, &b.IPAddress, &b.Reason, &b.BannedAt, &b.ExpiresAt,
			&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanRoomBan(row scannable) (*RoomBan, error) {
	var b RoomBan
	if err := row.Scan(&b.ID, &b.RoomUUID, &b.Reason, &b.BannedAt, &b.ExpiresAt,
		&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanRoomBans(rows *sql.Rows) ([]RoomBan, error) {
	out := make([]RoomBan, 0, 16)
	for rows.Next() {
		var b RoomBan
		if err := rows.Scan(&b.ID, &b.RoomUUID, &b.Reason, &b.BannedAt, &b.ExpiresAt,
			&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanUserRoomBan(row scannable) (*UserRoomBan, error) {
	var b UserRoomBan
	if err := row.Scan(&b.ID, &b.PublicKey, &b.RoomUUID, &b.Reason, &b.BannedAt, &b.ExpiresAt,
		&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
		return nil, err
	}
	return &b, nil
}

func scanUserRoomBans(rows *sql.Rows) ([]UserRoomBan, error) {
	out := make([]UserRoomBan, 0, 16)
	for rows.Next() {
		var b UserRoomBan
		if err := rows.Scan(&b.ID, &b.PublicKey, &b.RoomUUID, &b.Reason, &b.BannedAt, &b.ExpiresAt,
			&b.UnbannedAt, &b.UnbannedReason, &b.BannedBy, &b.UnbannedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanInviteLink(row scannable) (*InviteLink, error) {
	var inv InviteLink
	if err := row.Scan(&inv.ID, &inv.Token, &inv.GeneratedUsername, &inv.Status,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.UsedAt, &inv.RevokedAt, &inv.CreatedBy); err != nil {
		return nil, err
	}
	return &inv, nil
}

func scanInviteLinks(rows *sql.Rows) ([]InviteLink, error) {
	out := make([]InviteLink, 0, 16)
	for rows.Next() {
		var inv InviteLink
		if err := rows.Scan(&inv.ID, &inv.Token, &inv.GeneratedUsername, &inv.Status,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.UsedAt, &inv.RevokedAt, &inv.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}
