package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CountAdminUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&n)
	return n, err
}

func (s *Store) CreateAdminUser(ctx context.Context, loginName, displayName, passwordHash string, role UserRole, forcePasswordChange bool) (*AdminUser, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO admin_users (login_name, display_name, password_hash, role, force_password_change, disabled, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,false,now(),now())
RETURNING id, login_name, display_name, role, force_password_change, disabled, created_at
`, loginName, displayName, passwordHash, string(role), forcePasswordChange)
	var u AdminUser
	var roleStr string
	if err := row.Scan(&u.ID, &u.LoginName, &u.DisplayName, &roleStr, &u.ForcePasswordChange, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.Role = UserRole(roleStr)
	return &u, nil
}

func (s *Store) GetUserForLogin(ctx context.Context, loginName string) (*AdminUser, string, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, login_name, display_name, role, force_password_change, disabled, created_at, password_hash
FROM admin_users
WHERE login_name = $1
`, loginName)
	var u AdminUser
	var roleStr, hash string
	if err := row.Scan(&u.ID, &u.LoginName, &u.DisplayName, &roleStr, &u.ForcePasswordChange, &u.Disabled, &u.CreatedAt, &hash); err != nil {
		return nil, "", err
	}
	u.Role = UserRole(roleStr)
	return &u, hash, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*AdminUser, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, login_name, display_name, role, force_password_change, disabled, created_at
FROM admin_users
WHERE id = $1
`, id)
	var u AdminUser
	var roleStr string
	if err := row.Scan(&u.ID, &u.LoginName, &u.DisplayName, &roleStr, &u.ForcePasswordChange, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	u.Role = UserRole(roleStr)
	return &u, nil
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string, clearForce bool) error {
	if clearForce {
		_, err := s.db.ExecContext(ctx, `UPDATE admin_users SET password_hash=$2, force_password_change=false, updated_at=now() WHERE id=$1`, userID, passwordHash)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE admin_users SET password_hash=$2, updated_at=now() WHERE id=$1`, userID, passwordHash)
	return err
}

func (s *Store) InsertSession(ctx context.Context, userID int64, refreshToken string, userAgent, remoteIP string, expiresAt time.Time) error {
	h := sha256.Sum256([]byte(refreshToken))
	_, err := s.db.ExecContext(ctx, `
INSERT INTO admin_sessions (user_id, refresh_token_hash, user_agent, remote_ip, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,now())
`, userID, h[:], userAgent, remoteIP, expiresAt.UTC())
	return err
}

func (s *Store) ValidateSession(ctx context.Context, refreshToken string) (int64, error) {
	h := sha256.Sum256([]byte(refreshToken))
	var userID int64
	err := s.db.QueryRowContext(ctx, `
SELECT user_id
FROM admin_sessions
WHERE refresh_token_hash=$1 AND revoked_at IS NULL AND expires_at > now()
`, h[:]).Scan(&userID)
	return userID, err
}

func (s *Store) RevokeSession(ctx context.Context, refreshToken string) error {
	h := sha256.Sum256([]byte(refreshToken))
	_, err := s.db.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=now() WHERE refresh_token_hash=$1 AND revoked_at IS NULL`, h[:])
	return err
}

func (s *Store) GetAccessPolicy(ctx context.Context) (*AccessPolicy, error) {
	var mode string
	var whitelistRaw []byte
	row := s.db.QueryRowContext(ctx, `SELECT mode, whitelist_json FROM access_policy WHERE id=1`)
	if err := row.Scan(&mode, &whitelistRaw); err != nil {
		return nil, err
	}
	var wl []string
	if len(whitelistRaw) > 0 {
		_ = json.Unmarshal(whitelistRaw, &wl)
	}
	return &AccessPolicy{Mode: AccessMode(mode), Whitelist: wl}, nil
}

func (s *Store) PutAccessPolicy(ctx context.Context, p AccessPolicy) error {
	wl, err := json.Marshal(p.Whitelist)
	if err != nil {
		return err
	}
	var passHash any
	var keyHash any
	if p.Password != "" {
		h, err := HashPassword(p.Password)
		if err != nil {
			return err
		}
		passHash = h
	}
	if p.SharedKey != "" {
		h := sha256.Sum256([]byte(p.SharedKey))
		keyHash = h[:]
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE access_policy
SET mode=$1,
    password_hash=COALESCE($2, password_hash),
    shared_key_hash=COALESCE($3, shared_key_hash),
    whitelist_json=$4,
    updated_at=now()
WHERE id=1
`, string(p.Mode), passHash, keyHash, wl)
	return err
}

func (s *Store) ListBanRules(ctx context.Context) ([]BanRule, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, kind, value, reason, expires_at, created_at
FROM ban_rules
WHERE expires_at IS NULL OR expires_at > now()
ORDER BY created_at DESC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BanRule, 0, 16)
	for rows.Next() {
		var b BanRule
		if err := rows.Scan(&b.ID, &b.Kind, &b.Value, &b.Reason, &b.ExpiresAt, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) InsertBanRule(ctx context.Context, actorID int64, b BanRule) (*BanRule, error) {
	row := s.db.QueryRowContext(ctx, `
INSERT INTO ban_rules (kind, value, reason, expires_at, created_at, created_by)
VALUES ($1,$2,$3,$4,now(),$5)
RETURNING id, kind, value, reason, expires_at, created_at
`, b.Kind, b.Value, b.Reason, b.ExpiresAt, actorID)
	var out BanRule
	if err := row.Scan(&out.ID, &out.Kind, &out.Value, &out.Reason, &out.ExpiresAt, &out.CreatedAt); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) DeleteBanRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ban_rules WHERE id=$1`, id)
	return err
}

func (s *Store) GetUsageLimits(ctx context.Context) (*UsageLimits, error) {
	row := s.db.QueryRowContext(ctx, `SELECT per_ip_json, per_pubkey_json FROM usage_limits WHERE id=1`)
	var ipRaw, pkRaw []byte
	if err := row.Scan(&ipRaw, &pkRaw); err != nil {
		return nil, err
	}
	out := &UsageLimits{PerIP: map[string]int64{}, PerPubKey: map[string]int64{}}
	_ = json.Unmarshal(ipRaw, &out.PerIP)
	_ = json.Unmarshal(pkRaw, &out.PerPubKey)
	return out, nil
}

func (s *Store) PutUsageLimits(ctx context.Context, l UsageLimits) error {
	if l.PerIP == nil {
		l.PerIP = map[string]int64{}
	}
	if l.PerPubKey == nil {
		l.PerPubKey = map[string]int64{}
	}
	ipRaw, err := json.Marshal(l.PerIP)
	if err != nil {
		return err
	}
	pkRaw, err := json.Marshal(l.PerPubKey)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE usage_limits SET per_ip_json=$1, per_pubkey_json=$2, updated_at=now() WHERE id=1`, ipRaw, pkRaw)
	return err
}

func (s *Store) GetSubjectLimits(ctx context.Context, scope, subject string) (SubjectLimits, error) {
	row := s.db.QueryRowContext(ctx, `SELECT limits_json FROM usage_subject_limits WHERE scope=$1 AND subject=$2`, scope, subject)
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return SubjectLimits{}, nil
		}
		return nil, err
	}
	out := SubjectLimits{}
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func (s *Store) PutSubjectLimits(ctx context.Context, scope, subject string, limits SubjectLimits) error {
	if scope != "ip" && scope != "public_key" && scope != "room" && scope != "global" {
		return fmt.Errorf("invalid scope")
	}
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("subject is empty")
	}
	if limits == nil {
		limits = SubjectLimits{}
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_subject_limits (scope, subject, limits_json, updated_at)
VALUES ($1,$2,$3,now())
ON CONFLICT (scope, subject)
DO UPDATE SET limits_json=EXCLUDED.limits_json, updated_at=now()
	`, scope, subject, raw)
	return err
}

func (s *Store) GetGlobalLimits(ctx context.Context) (SubjectLimits, error) {
	return s.GetSubjectLimits(ctx, "global", "*")
}

func (s *Store) PutGlobalLimits(ctx context.Context, limits SubjectLimits) error {
	if limits == nil {
		limits = SubjectLimits{}
	}
	raw, err := json.Marshal(limits)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO usage_subject_limits (scope, subject, limits_json, updated_at)
VALUES ('global','*',$1,now())
ON CONFLICT (scope, subject)
DO UPDATE SET limits_json=EXCLUDED.limits_json, updated_at=now()
`, raw)
	return err
}

func (s *Store) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT value_json FROM server_settings WHERE key=$1`, key).Scan(&raw)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (s *Store) PutSetting(ctx context.Context, key string, value json.RawMessage) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO server_settings (key, value_json, updated_at)
VALUES ($1,$2,now())
ON CONFLICT (key) DO UPDATE SET value_json=EXCLUDED.value_json, updated_at=now()
`, key, value)
	return err
}

func (s *Store) InsertAudit(ctx context.Context, actorID int64, action, objectType, objectID string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO audit_log (actor_user_id, action, object_type, object_id, payload_json, created_at)
VALUES ($1,$2,$3,$4,$5,now())
`, actorID, action, objectType, objectID, raw)
	return err
}

func (s *Store) InsertBackupJob(ctx context.Context, actorID int64, retentionDays int) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO backup_jobs (status, retention_days, created_by, created_at)
VALUES ('queued',$1,$2,now())
RETURNING id
`, retentionDays, actorID).Scan(&id)
	return id, err
}

func (s *Store) MarkBackupRunning(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backup_jobs SET status='running', started_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) MarkBackupFinished(ctx context.Context, id int64, outputPath string, runErr error) error {
	if runErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE backup_jobs SET status='failed', finished_at=now(), error_message=$2 WHERE id=$1`, id, runErr.Error())
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE backup_jobs SET status='success', finished_at=now(), output_path=$2, error_message=NULL WHERE id=$1`, id, outputPath)
	return err
}

func (s *Store) ListBackupJobs(ctx context.Context, limit int) ([]BackupJob, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, status, output_path, started_at, finished_at, COALESCE(error_message,''), created_at
FROM backup_jobs
ORDER BY id DESC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]BackupJob, 0, limit)
	for rows.Next() {
		var b BackupJob
		if err := rows.Scan(&b.ID, &b.Status, &b.OutputPath, &b.StartedAt, &b.FinishedAt, &b.ErrorMessage, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) ListUsageTopByRequests(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT
  ip,
  COALESCE(public_key,'') AS public_key,
  MIN(first_use) AS first_use,
  MAX(last_use) AS last_use,
  SUM(requests) AS requests,
  SUM(bytes_recv) AS bytes_recv,
  SUM(bytes_sent) AS bytes_sent,
  MAX(transport) AS transport,
  MAX(last_status) AS last_status
FROM client_activity
GROUP BY ip, COALESCE(public_key,'')
ORDER BY SUM(requests) DESC, MAX(last_use) DESC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var ip, pub, transport, status string
		var first, last time.Time
		var req, br, bs int64
		if err := rows.Scan(&ip, &pub, &first, &last, &req, &br, &bs, &transport, &status); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ip":          ip,
			"public_key":  pub,
			"first_use":   first,
			"last_use":    last,
			"requests":    req,
			"bytes_recv":  br,
			"bytes_sent":  bs,
			"transport":   transport,
			"last_status": status,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListUsersTopByRequests(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT
  CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
       ELSE CONCAT('ip:', ip) END AS user_key,
  COALESCE(NULLIF(public_key,''), '') AS public_key,
  STRING_AGG(DISTINCT ip, ', ' ORDER BY ip) AS ips,
  MIN(first_use) AS first_use,
  MAX(last_use) AS last_use,
  SUM(requests) AS requests,
  SUM(bytes_recv) AS bytes_recv,
  SUM(bytes_sent) AS bytes_sent
FROM client_activity
GROUP BY
  CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
       ELSE CONCAT('ip:', ip) END,
  COALESCE(NULLIF(public_key,''), '')
ORDER BY SUM(requests) DESC, MAX(last_use) DESC
LIMIT $1
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var userKey, pub, ips string
		var first, last time.Time
		var req, br, bs int64
		if err := rows.Scan(&userKey, &pub, &ips, &first, &last, &req, &br, &bs); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"user_key":   userKey,
			"public_key": pub,
			"ips":        ips,
			"first_use":  first,
			"last_use":   last,
			"requests":   req,
			"bytes_recv": br,
			"bytes_sent": bs,
		})
	}
	return out, rows.Err()
}

func (s *Store) ListUsersDetailed(ctx context.Context, search, ipFilter, pubFilter, sortBy, sortOrder string, limit, offset int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	sortColumn := map[string]string{
		"requests":     "requests",
		"bytes_recv":   "bytes_recv",
		"bytes_sent":   "bytes_sent",
		"summary_data": "summary_data",
		"first_use":    "first_use",
		"last_use":     "last_use",
		"user_key":     "user_key",
	}[strings.ToLower(strings.TrimSpace(sortBy))]
	if sortColumn == "" {
		sortColumn = "requests"
	}
	order := "DESC"
	if strings.EqualFold(strings.TrimSpace(sortOrder), "asc") {
		order = "ASC"
	}

	q := fmt.Sprintf(`
WITH grouped AS (
  SELECT
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END AS user_key,
    COALESCE(NULLIF(public_key,''), '') AS public_key,
    STRING_AGG(DISTINCT ip, ', ' ORDER BY ip) AS ips,
    MIN(first_use) AS first_use,
    MAX(last_use) AS last_use,
    SUM(requests) AS requests,
    SUM(bytes_recv) AS bytes_recv,
    SUM(bytes_sent) AS bytes_sent,
    (SUM(bytes_recv) + SUM(bytes_sent)) AS summary_data
  FROM client_activity
  GROUP BY
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END,
    COALESCE(NULLIF(public_key,''), '')
)
SELECT user_key, public_key, ips, first_use, last_use, requests, bytes_recv, bytes_sent, summary_data
FROM grouped
WHERE ($1 = '' OR user_key ILIKE $1 OR ips ILIKE $1)
  AND ($2 = '' OR ips ILIKE $2)
  AND ($3 = '' OR public_key ILIKE $3)
ORDER BY %s %s, last_use DESC
LIMIT $4 OFFSET $5
`, sortColumn, order)

	searchPat := likePattern(search)
	ipPat := likePattern(ipFilter)
	pubPat := likePattern(pubFilter)

	rows, err := s.db.QueryContext(ctx, q, searchPat, ipPat, pubPat, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var userKey, pub, ips string
		var first, last time.Time
		var req, br, bs, sum int64
		if err := rows.Scan(&userKey, &pub, &ips, &first, &last, &req, &br, &bs, &sum); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"user_key":     userKey,
			"public_key":   pub,
			"ips":          ips,
			"first_use":    first,
			"last_use":     last,
			"requests":     req,
			"bytes_recv":   br,
			"bytes_sent":   bs,
			"summary_data": sum,
		})
	}
	return out, rows.Err()
}

func (s *Store) GetUserDetails(ctx context.Context, userKey string) (map[string]any, error) {
	q := `
WITH grouped AS (
  SELECT
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END AS user_key,
    COALESCE(NULLIF(public_key,''), '') AS public_key,
    STRING_AGG(DISTINCT ip, ', ' ORDER BY ip) AS ips,
    MIN(first_use) AS first_use,
    MAX(last_use) AS last_use,
    SUM(requests) AS requests,
    SUM(bytes_recv) AS bytes_recv,
    SUM(bytes_sent) AS bytes_sent,
    (SUM(bytes_recv) + SUM(bytes_sent)) AS summary_data
  FROM client_activity
  GROUP BY
    CASE WHEN COALESCE(public_key,'') <> '' THEN COALESCE(public_key,'')
         ELSE CONCAT('ip:', ip) END,
    COALESCE(NULLIF(public_key,''), '')
)
SELECT user_key, public_key, ips, first_use, last_use, requests, bytes_recv, bytes_sent, summary_data
FROM grouped
WHERE user_key = $1
LIMIT 1
`
	row := s.db.QueryRowContext(ctx, q, userKey)
	var out map[string]any
	{
		var k, pub, ips string
		var first, last time.Time
		var req, br, bs, sum int64
		if err := row.Scan(&k, &pub, &ips, &first, &last, &req, &br, &bs, &sum); err != nil {
			return nil, err
		}
		out = map[string]any{
			"user_key":     k,
			"public_key":   pub,
			"ips":          ips,
			"first_use":    first,
			"last_use":     last,
			"requests":     req,
			"bytes_recv":   br,
			"bytes_sent":   bs,
			"summary_data": sum,
		}
	}
	return out, nil
}

func (s *Store) UpsertRoomActivity(ctx context.Context, roomID string, req, bytesRecv, bytesSent int64, members int) error {
	if strings.TrimSpace(roomID) == "" {
		return nil
	}
	if members < 0 {
		members = 0
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO room_activity (room_id, first_use, last_use, requests, bytes_recv, bytes_sent, current_members, updated_at)
VALUES ($1,now(),now(),$2,$3,$4,$5,now())
ON CONFLICT (room_id)
DO UPDATE SET
  last_use=now(),
  requests=room_activity.requests + EXCLUDED.requests,
  bytes_recv=room_activity.bytes_recv + EXCLUDED.bytes_recv,
  bytes_sent=room_activity.bytes_sent + EXCLUDED.bytes_sent,
  current_members=EXCLUDED.current_members,
  updated_at=now()
`, roomID, req, bytesRecv, bytesSent, members)
	return err
}

func (s *Store) ListRoomsDetailed(ctx context.Context, search, sortBy, sortOrder string, limit, offset int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	sortColumn := map[string]string{
		"requests":     "requests",
		"bytes_recv":   "bytes_recv",
		"bytes_sent":   "bytes_sent",
		"summary_data": "summary_data",
		"first_use":    "first_use",
		"last_use":     "last_use",
		"room_id":      "room_id",
	}[strings.ToLower(strings.TrimSpace(sortBy))]
	if sortColumn == "" {
		sortColumn = "requests"
	}
	order := "DESC"
	if strings.EqualFold(strings.TrimSpace(sortOrder), "asc") {
		order = "ASC"
	}
	q := fmt.Sprintf(`
SELECT room_id, first_use, last_use, requests, bytes_recv, bytes_sent, (bytes_recv + bytes_sent) AS summary_data, current_members
FROM room_activity
WHERE ($1 = '' OR room_id ILIKE $1)
ORDER BY %s %s, last_use DESC
LIMIT $2 OFFSET $3
`, sortColumn, order)
	rows, err := s.db.QueryContext(ctx, q, likePattern(search), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var roomID string
		var first, last time.Time
		var req, br, bs, sum int64
		var members int
		if err := rows.Scan(&roomID, &first, &last, &req, &br, &bs, &sum, &members); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"room_id":         roomID,
			"first_use":       first,
			"last_use":        last,
			"requests":        req,
			"bytes_recv":      br,
			"bytes_sent":      bs,
			"summary_data":    sum,
			"current_members": members,
		})
	}
	return out, rows.Err()
}

func (s *Store) GetRoomDetails(ctx context.Context, roomID string) (map[string]any, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT room_id, first_use, last_use, requests, bytes_recv, bytes_sent, (bytes_recv + bytes_sent) AS summary_data, current_members
FROM room_activity
WHERE room_id = $1
LIMIT 1
`, roomID)
	var first, last time.Time
	var req, br, bs, sum int64
	var members int
	var outID string
	if err := row.Scan(&outID, &first, &last, &req, &br, &bs, &sum, &members); err != nil {
		return nil, err
	}
	return map[string]any{
		"room_id":         outID,
		"first_use":       first,
		"last_use":        last,
		"requests":        req,
		"bytes_recv":      br,
		"bytes_sent":      bs,
		"summary_data":    sum,
		"current_members": members,
	}, nil
}

func (s *Store) UpsertClientActivity(ctx context.Context, ip, pubkey string, req, bytesRecv, bytesSent int64, transport, status string) error {
	if ip == "" {
		return nil
	}
	if pubkey == "" {
		pubkey = ""
	}
	if transport == "" {
		transport = "tcp"
	}
	if status == "" {
		status = "ok"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO client_activity (ip, public_key, first_use, last_use, requests, bytes_recv, bytes_sent, transport, last_status)
VALUES ($1,$2,now(),now(),$3,$4,$5,$6,$7)
ON CONFLICT (ip, public_key)
DO UPDATE SET
  last_use=now(),
  requests=client_activity.requests + EXCLUDED.requests,
  bytes_recv=client_activity.bytes_recv + EXCLUDED.bytes_recv,
  bytes_sent=client_activity.bytes_sent + EXCLUDED.bytes_sent,
  transport=EXCLUDED.transport,
  last_status=EXCLUDED.last_status
`, ip, pubkey, req, bytesRecv, bytesSent, transport, status)
	return err
}

func (s *Store) IncrementUsageCounters(ctx context.Context, scope, subject string, req, bytesRecv, bytesSent int64, now time.Time) error {
	if scope == "" || subject == "" {
		return nil
	}
	windows := map[string]time.Time{
		"minute": now.UTC().Truncate(time.Minute),
		"hour":   now.UTC().Truncate(time.Hour),
		"day":    now.UTC().Truncate(24 * time.Hour),
		"week":   now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -int(now.UTC().Weekday())),
		"month":  time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC),
	}
	for bucket, start := range windows {
		_, err := s.db.ExecContext(ctx, `
INSERT INTO usage_counters (scope, subject, bucket, bucket_start, requests, bytes_recv, bytes_sent, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,now())
ON CONFLICT (scope, subject, bucket, bucket_start)
DO UPDATE SET
  requests=usage_counters.requests + EXCLUDED.requests,
  bytes_recv=usage_counters.bytes_recv + EXCLUDED.bytes_recv,
  bytes_sent=usage_counters.bytes_sent + EXCLUDED.bytes_sent,
  updated_at=now()
`, scope, subject, bucket, start, req, bytesRecv, bytesSent)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CurrentUsageBySubject(ctx context.Context, scope, subject string) (map[string]map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT bucket, requests, bytes_recv, bytes_sent
FROM usage_counters
WHERE scope=$1 AND subject=$2
  AND ((bucket='minute' AND bucket_start = date_trunc('minute', now()))
    OR (bucket='hour' AND bucket_start = date_trunc('hour', now()))
    OR (bucket='day' AND bucket_start = date_trunc('day', now()))
    OR (bucket='week' AND bucket_start = date_trunc('week', now()))
    OR (bucket='month' AND bucket_start = date_trunc('month', now())))
`, scope, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int64{}
	for rows.Next() {
		var bucket string
		var r, br, bs int64
		if err := rows.Scan(&bucket, &r, &br, &bs); err != nil {
			return nil, err
		}
		out[bucket] = map[string]int64{"requests": r, "bytes_recv": br, "bytes_sent": bs}
	}
	return out, rows.Err()
}

func (s *Store) IsBanned(ctx context.Context, kind, value string) (bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
SELECT id FROM ban_rules
WHERE kind=$1 AND value=$2 AND (expires_at IS NULL OR expires_at > now())
LIMIT 1
`, kind, value).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ValidateSharedKey(ctx context.Context, provided string) (bool, error) {
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT shared_key_hash FROM access_policy WHERE id=1`).Scan(&hash)
	if err != nil {
		return false, err
	}
	h := sha256.Sum256([]byte(provided))
	return hex.EncodeToString(h[:]) == hex.EncodeToString(hash), nil
}

func (s *Store) ValidatePasswordGate(ctx context.Context, provided string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM access_policy WHERE id=1`).Scan(&hash)
	if err != nil {
		return false, err
	}
	return CheckPassword(hash, provided)
}

func (s *Store) GetNetworkSettings(ctx context.Context) (json.RawMessage, error) {
	return s.GetSetting(ctx, "network")
}

func (s *Store) PutNetworkSettings(ctx context.Context, raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("network settings are empty")
	}
	return s.PutSetting(ctx, "network", raw)
}

func likePattern(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return "%" + v + "%"
}

func (s *Store) UsernameInactiveDays(ctx context.Context) (int, error) {
	raw, err := s.GetSetting(ctx, "cleanup")
	if err != nil {
		return 0, err
	}
	var cfg struct {
		UsernameInactiveDays int `json:"username_inactive_days"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, err
	}
	if cfg.UsernameInactiveDays <= 0 {
		cfg.UsernameInactiveDays = 90
	}
	return cfg.UsernameInactiveDays, nil
}

func (s *Store) CleanupInactiveUsernames(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		days = 90
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE user_profiles
SET username = NULL
WHERE username IS NOT NULL
  AND updated_at < now() - make_interval(days => $1)
`, days)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
