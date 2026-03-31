package userdir

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sync"
	"time"
)

var usernameRe = regexp.MustCompile(`^@[A-Za-z0-9_]{1,32}$`)

type Server struct {
	addr   string
	logger *log.Logger
	store  *Store

	avatarMaxBytes uint32
	searchMax      uint16
	cleanupEvery   time.Duration

	mu        sync.Mutex
	listener  net.Listener
	closeOnce sync.Once
	closing   chan struct{}
	wg        sync.WaitGroup
}

type Config struct {
	Addr           string
	Logger         *log.Logger
	Store          *Store
	AvatarMaxBytes uint32
	SearchMax      uint16
	CleanupEvery   time.Duration
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("userdir: Store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Addr == "" {
		cfg.Addr = ":7070"
	}
	if cfg.AvatarMaxBytes == 0 {
		cfg.AvatarMaxBytes = 32 * 1024 * 1024
	}
	if cfg.SearchMax == 0 {
		cfg.SearchMax = 20
	}
	if cfg.CleanupEvery <= 0 {
		cfg.CleanupEvery = 5 * time.Minute
	}

	return &Server{
		addr:           cfg.Addr,
		logger:         cfg.Logger,
		store:          cfg.Store,
		avatarMaxBytes: cfg.AvatarMaxBytes,
		searchMax:      cfg.SearchMax,
		cleanupEvery:   cfg.CleanupEvery,
		closing:        make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("userdir: listen %s: %w", s.addr, err)
	}
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return fmt.Errorf("userdir: Serve called more than once")
	}
	s.listener = ln
	s.mu.Unlock()

	s.logger.Printf("[userdir] listening on %s", ln.Addr().String())

	stopCtx := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.initiateClose()
		case <-stopCtx:
		}
	}()
	defer close(stopCtx)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupLoop(ctx)
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("userdir: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, nc)
		}()
	}
}

func (s *Server) initiateClose() {
	s.closeOnce.Do(func() {
		close(s.closing)
		s.mu.Lock()
		ln := s.listener
		s.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	})
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.initiateClose()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(s.cleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closing:
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = s.store.CleanupExpired(cctx)
			cancel()
		}
	}
}

// RunCleanupLoop runs the periodic expired-profile cleanup until ctx is done.
// Use this when the userdir server is embedded inside another server and its
// own TCP listener is not started.
func (s *Server) RunCleanupLoop(ctx context.Context) error {
	s.wg.Add(1)
	defer s.wg.Done()
	s.cleanupLoop(ctx)
	return nil
}

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	remote := nc.RemoteAddr().String()
	s.logger.Printf("[userdir] new connection from %s", remote)

	go func() {
		select {
		case <-ctx.Done():
			_ = nc.Close()
		case <-s.closing:
			_ = nc.Close()
		}
	}()

	s.ServeConn(ctx, nc, nc)
}

// ServeConn handles the userdir protocol over an already-established r/w pair.
// The caller must have already consumed the 32-byte zero-prefix magic (if any)
// before invoking this method — framing starts with the first userdir frame.
func (s *Server) ServeConn(ctx context.Context, r io.Reader, w io.Writer) {
	maxFrame := uint32(1) + 1 + 2 + 33 + 2 + 512 + 32 + 4 + s.avatarMaxBytes + 1 + 64

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closing:
			return
		default:
		}

		typ, payload, err := readFrame(r, maxFrame)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Printf("[userdir] read error: %v", err)
			return
		}

		switch typ {
		case msgRegister:
			if err := s.handleRegister(w, payload); err != nil {
				s.logger.Printf("[userdir] register error: %v", err)
			}
		case msgSearch:
			if err := s.handleSearch(w, payload); err != nil {
				s.logger.Printf("[userdir] search error: %v", err)
			}
		case msgGetProfile:
			if err := s.handleGetProfile(w, payload); err != nil {
				s.logger.Printf("[userdir] get_profile error: %v", err)
			}
		case msgGetMeta:
			if err := s.handleGetMeta(w, payload); err != nil {
				s.logger.Printf("[userdir] get_meta error: %v", err)
			}
		default:
			_ = writeError(w, errBadRequest, "unknown message type")
		}
	}
}

func (s *Server) handleRegister(w io.Writer, payload []byte) error {
	ver, username, fullname, pubkey, avatar, sigAlg, sig, signed, err := parseRegister(payload, s.avatarMaxBytes)
	if err != nil {
		_ = writeError(w, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		_ = writeError(w, errBadRequest, "unsupported version")
		return nil
	}
	if sigAlg != 1 {
		_ = writeError(w, errBadRequest, "unsupported signature algorithm")
		return nil
	}
	if !usernameRe.MatchString(username) {
		_ = writeError(w, errBadRequest, "invalid username format")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey[:]), signed, sig) {
		_ = writeError(w, errBadSig, "invalid signature")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.UpsertProfile(ctx, pubkey, username, fullname, avatar); err != nil {
		_ = writeError(w, errInternal, "storage error")
		return err
	}
	return writeOK(w, "OK")
}

func (s *Server) handleSearch(w io.Writer, payload []byte) error {
	ver, query, limit, err := parseSearch(payload)
	if err != nil {
		_ = writeError(w, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		return writeError(w, errBadRequest, "unsupported version")
	}
	if limit == 0 || limit > s.searchMax {
		limit = s.searchMax
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := s.store.Search(ctx, query, int(limit))
	if err != nil {
		_ = writeError(w, errInternal, "storage error")
		return err
	}
	return writeSearchResults(w, res)
}

func (s *Server) handleGetProfile(w io.Writer, payload []byte) error {
	ver, pubkey, err := parseGetProfile(payload)
	if err != nil {
		_ = writeError(w, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		return writeError(w, errBadRequest, "unsupported version")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		_ = writeError(w, errInternal, "storage error")
		return err
	}
	if !ok {
		return writeError(w, errNotFound, "not found")
	}
	return writeProfile(w, p)
}

// handleGetMeta handles msgGetMeta: returns username, fullname, avatar_sha256 and
// updated_at for a given public key — without sending the full avatar bytes.
func (s *Server) handleGetMeta(w io.Writer, payload []byte) error {
	ver, pubkey, err := parseGetMeta(payload)
	if err != nil {
		_ = writeError(w, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		return writeError(w, errBadRequest, "unsupported version")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		_ = writeError(w, errInternal, "storage error")
		return err
	}
	if !ok {
		return writeError(w, errNotFound, "not found")
	}
	return writeMetaResponse(w, p)
}

func parseRegister(payload []byte, avatarMax uint32) (ver byte, username, fullname string, pubkey [32]byte, avatar []byte, sigAlg byte, sig []byte, signed []byte, err error) {
	// payload:
	// [1B ver][2B ulen][ulen username][2B flen][flen fullname][32B pubkey][4B avatar_len][avatar][1B sig_alg][64B sig]
	if len(payload) < 1+2+2+32+4+1+64 {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("short register payload")
	}
	off := 0
	ver = payload[off]
	off++

	ulen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if ulen <= 0 || off+ulen > len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("invalid username length")
	}
	username = string(payload[off : off+ulen])
	off += ulen

	flen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if flen < 0 || off+flen > len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("invalid fullname length")
	}
	fullname = string(payload[off : off+flen])
	off += flen

	if off+32 > len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("missing pubkey")
	}
	copy(pubkey[:], payload[off:off+32])
	off += 32

	if off+4 > len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("missing avatar length")
	}
	alen := binary.BigEndian.Uint32(payload[off : off+4])
	off += 4
	if alen > avatarMax {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("avatar too large")
	}
	if off+int(alen) > len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("truncated avatar")
	}
	avatar = append([]byte(nil), payload[off:off+int(alen)]...)
	off += int(alen)

	if off+1+64 != len(payload) {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("invalid signature section")
	}
	sigAlg = payload[off]
	off++
	sig = append([]byte(nil), payload[off:off+64]...)

	// signed bytes = [type][payload_without_signature_bytes]
	signed = make([]byte, 1+(len(payload)-64))
	signed[0] = msgRegister
	copy(signed[1:], payload[:len(payload)-64])
	return ver, username, fullname, pubkey, avatar, sigAlg, sig, signed, nil
}

func parseSearch(payload []byte) (ver byte, query string, limit uint16, err error) {
	// payload: [1B ver][2B qlen][q][2B limit]
	if len(payload) < 1+2+2 {
		return 0, "", 0, fmt.Errorf("short search payload")
	}
	off := 0
	ver = payload[off]
	off++
	qlen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if qlen < 0 || off+qlen+2 != len(payload) {
		return 0, "", 0, fmt.Errorf("invalid search payload")
	}
	query = string(payload[off : off+qlen])
	off += qlen
	limit = binary.BigEndian.Uint16(payload[off : off+2])
	return ver, query, limit, nil
}

func parseGetProfile(payload []byte) (ver byte, pubkey [32]byte, err error) {
	// payload: [1B ver][32B pubkey]
	if len(payload) != 1+32 {
		return 0, [32]byte{}, fmt.Errorf("invalid get_profile payload")
	}
	ver = payload[0]
	copy(pubkey[:], payload[1:33])
	return ver, pubkey, nil
}

func writeSearchResults(w io.Writer, res []SearchResult) error {
	// payload: [1B ver][2B count] { [32B pubkey][2B ulen][u][2B flen][f][32B avatar_sha] }*
	if len(res) > 65535 {
		res = res[:65535]
	}
	var buf []byte
	buf = append(buf, 1)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(res)))
	buf = append(buf, tmp...)
	for _, r := range res {
		buf = append(buf, r.PubKey[:]...)

		ub := []byte(r.Username)
		fb := []byte(r.FullName)
		if len(ub) > 65535 {
			ub = ub[:65535]
		}
		if len(fb) > 65535 {
			fb = fb[:65535]
		}
		binary.BigEndian.PutUint16(tmp, uint16(len(ub)))
		buf = append(buf, tmp...)
		buf = append(buf, ub...)
		binary.BigEndian.PutUint16(tmp, uint16(len(fb)))
		buf = append(buf, tmp...)
		buf = append(buf, fb...)
		buf = append(buf, r.AvatarSHA256[:]...)
	}
	return writeFrame(w, msgResults, buf)
}

func writeProfile(w io.Writer, p *Profile) error {
	// payload: [1B ver][32B pubkey][2B ulen][u][2B flen][f][4B alen][avatar][32B avatar_sha][8B updated_at_unix_sec]
	var buf []byte
	buf = append(buf, 1)
	buf = append(buf, p.PubKey[:]...)
	tmp2 := make([]byte, 2)
	ub := []byte(p.Username)
	fb := []byte(p.FullName)
	binary.BigEndian.PutUint16(tmp2, uint16(len(ub)))
	buf = append(buf, tmp2...)
	buf = append(buf, ub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(fb)))
	buf = append(buf, tmp2...)
	buf = append(buf, fb...)

	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, uint32(len(p.Avatar)))
	buf = append(buf, tmp4...)
	buf = append(buf, p.Avatar...)
	buf = append(buf, p.AvatarSHA256[:]...)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UpdatedAt.Unix()))
	buf = append(buf, ts[:]...)

	return writeFrame(w, msgProfile, buf)
}
