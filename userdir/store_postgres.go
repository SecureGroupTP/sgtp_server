package userdir

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

var ErrUsernameTaken = errors.New("username already taken")
var ErrFriendRequestNotFound = errors.New("friend request not found")

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
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "user_profiles_username_unique_not_null" {
			return ErrUsernameTaken
		}
	}
	return err
}

type SearchResult struct {
	PubKey       [32]byte
	Username     string
	FullName     string
	AvatarSHA256 [32]byte
}

const (
	friendStatusPending  byte = 1
	friendStatusAccepted byte = 2
	friendStatusRejected byte = 3

	friendStatusPendingOutgoing byte = 1
	friendStatusPendingIncoming byte = 2
	friendStatusFriend          byte = 3
	friendStatusRejectedView    byte = 4
)

type FriendStateSnapshot struct {
	PeerPubKey [32]byte
	Status     byte
	HasRoom    bool
	RoomUUID   [16]byte
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

func canonicalPair(a, b [32]byte) (x [32]byte, y [32]byte) {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a, b
	}
	return b, a
}

func (s *Store) CreateFriendRequest(ctx context.Context, requester, recipient [32]byte) (bool, error) {
	if requester == recipient {
		return false, fmt.Errorf("cannot friend self")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var status int
	err = tx.QueryRowContext(ctx, `
SELECT status
FROM friend_requests
WHERE requester = $1 AND recipient = $2
ORDER BY updated_at DESC, id DESC
LIMIT 1
`, requester[:], recipient[:]).Scan(&status)
	if err == nil {
		// Deduplicate only an already-open outgoing pending request.
		// Re-request after accepted/rejected is allowed by product flow.
		if status == int(friendStatusPending) {
			if err := tx.Commit(); err != nil {
				return false, err
			}
			return false, nil
		}
	} else if err != sql.ErrNoRows {
		return false, err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO friend_requests (requester, recipient, status, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())
`, requester[:], recipient[:], friendStatusPending)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) RespondFriendRequest(ctx context.Context, responder, requester [32]byte, accept bool) (byte, *[16]byte, error) {
	nextStatus := friendStatusRejected
	if accept {
		nextStatus = friendStatusAccepted
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var reqID int64
	err = tx.QueryRowContext(ctx, `
SELECT id
FROM friend_requests
WHERE requester = $1 AND recipient = $2 AND status = $3
ORDER BY updated_at DESC, id DESC
LIMIT 1
FOR UPDATE
`, requester[:], responder[:], friendStatusPending).Scan(&reqID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil, ErrFriendRequestNotFound
		}
		return 0, nil, err
	}

	_, err = tx.ExecContext(ctx, `
UPDATE friend_requests
SET status = $1, updated_at = now(), responded_at = now()
WHERE id = $2
`, nextStatus, reqID)
	if err != nil {
		return 0, nil, err
	}

	var room *[16]byte
	if accept {
		id, err := getOrCreateDMRoomTx(ctx, tx, requester, responder)
		if err != nil {
			return 0, nil, err
		}
		room = &id
	}

	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}

	if accept {
		return friendStatusFriend, room, nil
	}
	return friendStatusRejectedView, nil, nil
}

func getOrCreateDMRoomTx(ctx context.Context, tx *sql.Tx, a, b [32]byte) ([16]byte, error) {
	x, y := canonicalPair(a, b)

	var roomRaw []byte
	err := tx.QueryRowContext(ctx, `
SELECT room_uuid
FROM dm_rooms
WHERE user_a = $1 AND user_b = $2
`, x[:], y[:]).Scan(&roomRaw)
	if err == nil {
		if len(roomRaw) != 16 {
			return [16]byte{}, fmt.Errorf("invalid room uuid length")
		}
		var room [16]byte
		copy(room[:], roomRaw)
		return room, nil
	}
	if err != sql.ErrNoRows {
		return [16]byte{}, err
	}

	for i := 0; i < 8; i++ {
		room, err := randomUUID16()
		if err != nil {
			return [16]byte{}, err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO dm_rooms (user_a, user_b, room_uuid, created_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (user_a, user_b) DO NOTHING
`, x[:], y[:], room[:])
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				continue
			}
			return [16]byte{}, err
		}

		roomRaw = nil
		err = tx.QueryRowContext(ctx, `
SELECT room_uuid
FROM dm_rooms
WHERE user_a = $1 AND user_b = $2
`, x[:], y[:]).Scan(&roomRaw)
		if err != nil {
			return [16]byte{}, err
		}
		if len(roomRaw) != 16 {
			return [16]byte{}, fmt.Errorf("invalid room uuid length")
		}
		var out [16]byte
		copy(out[:], roomRaw)
		return out, nil
	}
	return [16]byte{}, fmt.Errorf("failed to allocate unique room uuid")
}

func randomUUID16() ([16]byte, error) {
	var out [16]byte
	if _, err := rand.Read(out[:]); err != nil {
		return [16]byte{}, err
	}
	out[6] = (out[6] & 0x0f) | 0x40
	out[8] = (out[8] & 0x3f) | 0x80
	return out, nil
}

func (s *Store) FriendSync(ctx context.Context, self [32]byte) ([]FriendStateSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH latest AS (
  SELECT DISTINCT ON (peer)
    peer,
    status,
    outgoing
  FROM (
    SELECT
      CASE WHEN requester = $1 THEN recipient ELSE requester END AS peer,
      status,
      (requester = $1) AS outgoing,
      updated_at,
      id
    FROM friend_requests
    WHERE requester = $1 OR recipient = $1
  ) t
  ORDER BY peer, updated_at DESC, id DESC
)
SELECT peer, status, outgoing
FROM latest
`, self[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FriendStateSnapshot
	for rows.Next() {
		var peerRaw []byte
		var dbStatus int
		var outgoing bool
		if err := rows.Scan(&peerRaw, &dbStatus, &outgoing); err != nil {
			return nil, err
		}
		if len(peerRaw) != 32 {
			continue
		}
		var peer [32]byte
		copy(peer[:], peerRaw)
		st := FriendStateSnapshot{PeerPubKey: peer}
		switch dbStatus {
		case int(friendStatusPending):
			if outgoing {
				st.Status = friendStatusPendingOutgoing
			} else {
				st.Status = friendStatusPendingIncoming
			}
		case int(friendStatusAccepted):
			st.Status = friendStatusFriend
			room, hasRoom, err := s.findDMRoom(ctx, self, peer)
			if err != nil {
				return nil, err
			}
			if hasRoom {
				st.HasRoom = true
				st.RoomUUID = room
			}
		case int(friendStatusRejected):
			st.Status = friendStatusRejectedView
		default:
			continue
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) findDMRoom(ctx context.Context, a, b [32]byte) ([16]byte, bool, error) {
	x, y := canonicalPair(a, b)
	var raw []byte
	err := s.db.QueryRowContext(ctx, `
SELECT room_uuid
FROM dm_rooms
WHERE user_a = $1 AND user_b = $2
`, x[:], y[:]).Scan(&raw)
	if err != nil {
		if err == sql.ErrNoRows {
			return [16]byte{}, false, nil
		}
		return [16]byte{}, false, err
	}
	if len(raw) != 16 {
		return [16]byte{}, false, fmt.Errorf("invalid room uuid length")
	}
	var room [16]byte
	copy(room[:], raw)
	return room, true, nil
}

func (s *Store) RemoveFriendRelation(ctx context.Context, a, b [32]byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
DELETE FROM friend_requests
WHERE (requester = $1 AND recipient = $2)
   OR (requester = $2 AND recipient = $1)
`, a[:], b[:])
	if err != nil {
		return err
	}

	x, y := canonicalPair(a, b)
	_, err = tx.ExecContext(ctx, `
DELETE FROM dm_rooms
WHERE user_a = $1 AND user_b = $2
`, x[:], y[:])
	if err != nil {
		return err
	}

	return tx.Commit()
}
