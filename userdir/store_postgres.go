package userdir

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

type Profile struct {
	PubKey       [32]byte
	Username     string
	FullName     string
	Avatar       []byte
	AvatarSHA256 [32]byte
	UpdatedAt    time.Time
}

func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	s := &Store{db: db}
	if err := s.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.InitSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) InitSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS user_profiles (
  pubkey bytea PRIMARY KEY,
  username text,
  fullname text NOT NULL,
  avatar bytea NOT NULL,
  avatar_sha256 bytea NOT NULL,
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

ALTER TABLE user_profiles
  ALTER COLUMN username DROP NOT NULL;

ALTER TABLE user_profiles
  ALTER COLUMN expires_at SET DEFAULT 'infinity'::timestamptz;

UPDATE user_profiles
SET expires_at = 'infinity'::timestamptz
WHERE expires_at <> 'infinity'::timestamptz;
`)
	return err
}

func (s *Store) UpsertProfile(ctx context.Context, pubkey [32]byte, username, fullname string, avatar []byte) error {
	now := time.Now().UTC()
	if avatar == nil {
		avatar = []byte{}
	}
	sha := sha256.Sum256(avatar)
	var usernameDB any
	if strings.TrimSpace(username) == "" {
		usernameDB = nil
	} else {
		usernameDB = username
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO user_profiles (pubkey, username, fullname, avatar, avatar_sha256, updated_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (pubkey) DO UPDATE SET
  username = EXCLUDED.username,
  fullname = EXCLUDED.fullname,
  avatar = EXCLUDED.avatar,
  avatar_sha256 = EXCLUDED.avatar_sha256,
  updated_at = EXCLUDED.updated_at,
  expires_at = EXCLUDED.expires_at
`, pubkey[:], usernameDB, fullname, avatar, sha[:], now, "infinity")
	return err
}

type SearchResult struct {
	PubKey       [32]byte
	Username     string
	FullName     string
	AvatarSHA256 [32]byte
}

func (s *Store) Search(ctx context.Context, q string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		return nil, nil
	}
	if strings.TrimSpace(q) == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT pubkey, COALESCE(username, ''), fullname, avatar_sha256
FROM user_profiles
WHERE (
    position(lower($1) in lower(username)) > 0
    OR position(lower($1) in lower(fullname)) > 0
  )
ORDER BY updated_at DESC
LIMIT $2
`, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SearchResult, 0, limit)
	for rows.Next() {
		var pub []byte
		var sha []byte
		var r SearchResult
		if err := rows.Scan(&pub, &r.Username, &r.FullName, &sha); err != nil {
			return nil, err
		}
		if len(pub) == 32 {
			copy(r.PubKey[:], pub)
		}
		if len(sha) == 32 {
			copy(r.AvatarSHA256[:], sha)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetByPubKey(ctx context.Context, pubkey [32]byte) (*Profile, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT COALESCE(username, ''), fullname, avatar, avatar_sha256, updated_at
FROM user_profiles
WHERE pubkey = $1
`, pubkey[:])

	var p Profile
	p.PubKey = pubkey
	var sha []byte
	if err := row.Scan(&p.Username, &p.FullName, &p.Avatar, &sha, &p.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(sha) == 32 {
		copy(p.AvatarSHA256[:], sha)
	}
	return &p, true, nil
}

func (s *Store) CleanupExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_profiles WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
