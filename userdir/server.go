package userdir

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var usernameRe = regexp.MustCompile(`^@[A-Za-z0-9_]{1,32}$`)

// shortKey returns the first 4 bytes of a pubkey as a hex string for logs.
func shortKey(k [32]byte) string { return hex.EncodeToString(k[:4]) }

// msgTypeName returns a human-readable name for a message type byte.
func msgTypeName(t byte) string {
	switch t {
	case msgRegister:
		return "REGISTER"
	case msgSearch:
		return "SEARCH"
	case msgGetProfile:
		return "GET_PROFILE"
	case msgGetMeta:
		return "GET_META"
	case msgSubscribe:
		return "SUBSCRIBE"
	case msgUnsubscribe:
		return "UNSUBSCRIBE"
	case msgFriendReq:
		return "FRIEND_REQUEST"
	case msgFriendResp:
		return "FRIEND_RESPONSE"
	case msgFriendSync:
		return "FRIEND_SYNC"
	case msgOK:
		return "OK"
	case msgError:
		return "ERROR"
	case msgResults:
		return "SEARCH_RESULTS"
	case msgProfile:
		return "PROFILE"
	case msgMeta:
		return "META"
	case msgNotify:
		return "NOTIFY"
	case msgFState:
		return "FRIEND_STATE"
	case msgFNotify:
		return "FRIEND_NOTIFY"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", t)
	}
}

// ─── connSub ─────────────────────────────────────────────────────────────────

// connSub tracks the subscription state for a single open connection.
type connSub struct {
	id     string      // short random-ish id for logs (remote addr)
	sendCh chan []byte // outbound frames (responses + async notifies)

	mu   sync.Mutex
	keys map[[32]byte]struct{} // pubkeys this connection is subscribed to
}

func newConnSub(id string, sendBuf int) *connSub {
	return &connSub{
		id:     id,
		sendCh: make(chan []byte, sendBuf),
		keys:   make(map[[32]byte]struct{}),
	}
}

// subscribe adds pubkeys to the subscription set.
// Returns the slice of keys that were actually new, and whether the limit was hit.
func (c *connSub) subscribe(keys [][32]byte, max int) (added [][32]byte, limitReached bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		if _, already := c.keys[k]; already {
			continue
		}
		if max > 0 && len(c.keys) >= max {
			limitReached = true
			break
		}
		c.keys[k] = struct{}{}
		added = append(added, k)
	}
	return added, limitReached
}

// unsubscribe removes pubkeys from the subscription set.
func (c *connSub) unsubscribe(keys [][32]byte) [][32]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var removed [][32]byte
	for _, k := range keys {
		if _, ok := c.keys[k]; ok {
			delete(c.keys, k)
			removed = append(removed, k)
		}
	}
	return removed
}

// unsubscribeAll clears every key and returns the full list for cleanup.
func (c *connSub) unsubscribeAll() [][32]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([][32]byte, 0, len(c.keys))
	for k := range c.keys {
		keys = append(keys, k)
	}
	c.keys = make(map[[32]byte]struct{})
	return keys
}

// subCount returns the current subscription count (for logging).
func (c *connSub) subCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.keys)
}

// deliver tries to enqueue a pre-built frame. Drops silently if buffer is full.
func (c *connSub) deliver(frame []byte) bool {
	select {
	case c.sendCh <- frame:
		return true
	default:
		return false
	}
}

// ─── Server ──────────────────────────────────────────────────────────────────

type Server struct {
	addr   string
	logger *log.Logger
	store  *Store

	avatarMaxBytes uint32
	searchMax      uint16
	subscribeMax   int
	cleanupEvery   time.Duration

	subsMu sync.RWMutex
	subs   map[[32]byte]map[*connSub]struct{}

	mu        sync.Mutex
	listener  net.Listener
	closeOnce sync.Once
	closing   chan struct{}
	wg        sync.WaitGroup
}

const (
	friendEventRequestCreated byte = 1
	friendEventRequestAnswer  byte = 2
	friendEventDMReady        byte = 3
)

type Config struct {
	Addr           string
	Logger         *log.Logger
	Store          *Store
	AvatarMaxBytes uint32
	SearchMax      uint16
	// SubscribeMax is the maximum number of pubkeys one connection may subscribe
	// to at once. Default: 500. Set to -1 for no limit.
	SubscribeMax int
	CleanupEvery time.Duration
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
	if cfg.SubscribeMax == 0 {
		cfg.SubscribeMax = 500
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
		subscribeMax:   cfg.SubscribeMax,
		cleanupEvery:   cfg.CleanupEvery,
		subs:           make(map[[32]byte]map[*connSub]struct{}),
		closing:        make(chan struct{}),
	}, nil
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

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

	s.logger.Printf("[userdir] listening on %s (avatarMax=%d searchMax=%d subscribeMax=%d cleanupEvery=%s)",
		ln.Addr().String(), s.avatarMaxBytes, s.searchMax, s.subscribeMax, s.cleanupEvery)

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
		s.logger.Printf("[userdir] initiating shutdown")
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
		s.logger.Printf("[userdir] shutdown complete")
		return nil
	case <-ctx.Done():
		s.logger.Printf("[userdir] shutdown timed out")
		return ctx.Err()
	}
}

func (s *Server) cleanupLoop(ctx context.Context) {
	s.logger.Printf("[userdir] cleanup loop started (interval=%s)", s.cleanupEvery)
	t := time.NewTicker(s.cleanupEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("[userdir] cleanup loop stopped (ctx done)")
			return
		case <-s.closing:
			s.logger.Printf("[userdir] cleanup loop stopped (closing)")
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			n, err := s.store.CleanupExpired(cctx)
			cancel()
			if err != nil {
				s.logger.Printf("[userdir] cleanup error: %v", err)
			} else if n > 0 {
				s.logger.Printf("[userdir] cleanup: deleted %d expired profile(s)", n)
			}
		}
	}
}

// RunCleanupLoop runs the periodic expired-profile cleanup until ctx is done.
// Use this when the userdir server is embedded and its TCP listener is not started.
func (s *Server) RunCleanupLoop(ctx context.Context) error {
	s.wg.Add(1)
	defer s.wg.Done()
	s.cleanupLoop(ctx)
	return nil
}

// ─── Subscriber registry ─────────────────────────────────────────────────────

func (s *Server) registerSub(sub *connSub, keys [][32]byte) {
	if len(keys) == 0 {
		return
	}
	s.subsMu.Lock()
	for _, k := range keys {
		if s.subs[k] == nil {
			s.subs[k] = make(map[*connSub]struct{})
		}
		s.subs[k][sub] = struct{}{}
	}
	s.subsMu.Unlock()
}

func (s *Server) deregisterSub(sub *connSub, keys [][32]byte) {
	if len(keys) == 0 {
		return
	}
	s.subsMu.Lock()
	for _, k := range keys {
		delete(s.subs[k], sub)
		if len(s.subs[k]) == 0 {
			delete(s.subs, k)
		}
	}
	s.subsMu.Unlock()
}

func (s *Server) notifySubscribers(pubkey [32]byte, p *Profile) {
	s.subsMu.RLock()
	targets := make([]*connSub, 0, len(s.subs[pubkey]))
	for sub := range s.subs[pubkey] {
		targets = append(targets, sub)
	}
	s.subsMu.RUnlock()

	if len(targets) == 0 {
		s.logger.Printf("[userdir] notify pubkey=%s: no subscribers", shortKey(pubkey))
		return
	}

	frame, err := writeNotify(p)
	if err != nil {
		s.logger.Printf("[userdir] notify pubkey=%s: build frame error: %v", shortKey(pubkey), err)
		return
	}

	delivered, dropped := 0, 0
	for _, sub := range targets {
		if sub.deliver(frame) {
			delivered++
		} else {
			dropped++
		}
	}
	s.logger.Printf("[userdir] notify pubkey=%s: delivered=%d dropped=%d (slow consumers)",
		shortKey(pubkey), delivered, dropped)
}

// ─── Connection handling ─────────────────────────────────────────────────────

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	remote := nc.RemoteAddr().String()
	s.logger.Printf("[userdir] [%s] connected", remote)

	go func() {
		select {
		case <-ctx.Done():
			s.logger.Printf("[userdir] [%s] closing: ctx done", remote)
			_ = nc.Close()
		case <-s.closing:
			s.logger.Printf("[userdir] [%s] closing: server shutting down", remote)
			_ = nc.Close()
		}
	}()

	s.ServeConn(ctx, nc, nc)
	s.logger.Printf("[userdir] [%s] disconnected", remote)
}

// ServeConn handles the userdir protocol over an already-established r/w pair.
// The caller must have consumed the 32-byte zero-prefix magic before calling.
func (s *Server) ServeConn(ctx context.Context, r io.Reader, w io.Writer) {
	// Use the remote address when available, fall back to a generic label.
	connID := "inline"
	if nc, ok := r.(interface{ RemoteAddr() net.Addr }); ok {
		connID = nc.RemoteAddr().String()
	}

	s.logger.Printf("[userdir] [%s] ServeConn started (avatarMax=%d subscribeMax=%d)",
		connID, s.avatarMaxBytes, s.subscribeMax)

	sub := newConnSub(connID, 128)

	writeCtx, writeCancel := context.WithCancel(ctx)
	defer writeCancel()

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		s.logger.Printf("[userdir] [%s] write goroutine started", connID)
		for {
			select {
			case frame, ok := <-sub.sendCh:
				if !ok {
					s.logger.Printf("[userdir] [%s] write goroutine: sendCh closed, exiting", connID)
					return
				}
				if err := writeAll(w, frame); err != nil {
					s.logger.Printf("[userdir] [%s] write goroutine: write error: %v", connID, err)
					return
				}
			case <-writeCtx.Done():
				// Drain remaining frames before exit.
				s.logger.Printf("[userdir] [%s] write goroutine: ctx done, draining sendCh", connID)
				for {
					select {
					case frame, ok := <-sub.sendCh:
						if !ok {
							return
						}
						_ = writeAll(w, frame)
					default:
						return
					}
				}
			}
		}
	}()

	defer func() {
		keys := sub.unsubscribeAll()
		if len(keys) > 0 {
			s.logger.Printf("[userdir] [%s] cleanup: deregistering %d subscription(s)", connID, len(keys))
			s.deregisterSub(sub, keys)
		}
		writeCancel()
		close(sub.sendCh)
		<-writeDone
		s.logger.Printf("[userdir] [%s] ServeConn done", connID)
	}()

	maxFrame := uint32(1) + 1 + 2 + 33 + 2 + 512 + 32 + 4 + s.avatarMaxBytes + 1 + 64
	s.logger.Printf("[userdir] [%s] read loop started (maxFrame=%d)", connID, maxFrame)

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("[userdir] [%s] read loop: ctx done", connID)
			return
		case <-s.closing:
			s.logger.Printf("[userdir] [%s] read loop: server closing", connID)
			return
		default:
		}

		typ, payload, err := readFrame(r, maxFrame)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				s.logger.Printf("[userdir] [%s] read loop: connection closed (%v)", connID, err)
			} else {
				s.logger.Printf("[userdir] [%s] read loop: read error: %v", connID, err)
			}
			return
		}

		s.logger.Printf("[userdir] [%s] → recv type=0x%02x (%s) payloadLen=%d",
			connID, typ, msgTypeName(typ), len(payload))

		switch typ {
		case msgRegister:
			if err := s.handleRegister(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] REGISTER error: %v", connID, err)
			}
		case msgSearch:
			if err := s.handleSearch(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] SEARCH error: %v", connID, err)
			}
		case msgGetProfile:
			if err := s.handleGetProfile(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] GET_PROFILE error: %v", connID, err)
			}
		case msgGetMeta:
			if err := s.handleGetMeta(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] GET_META error: %v", connID, err)
			}
		case msgSubscribe:
			if err := s.handleSubscribe(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] SUBSCRIBE error: %v", connID, err)
			}
		case msgUnsubscribe:
			if err := s.handleUnsubscribe(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] UNSUBSCRIBE error: %v", connID, err)
			}
		case msgFriendReq:
			if err := s.handleFriendRequest(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] FRIEND_REQUEST error: %v", connID, err)
			}
		case msgFriendResp:
			if err := s.handleFriendResponse(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] FRIEND_RESPONSE error: %v", connID, err)
			}
		case msgFriendSync:
			if err := s.handleFriendSync(sub, payload); err != nil {
				s.logger.Printf("[userdir] [%s] FRIEND_SYNC error: %v", connID, err)
			}
		default:
			s.logger.Printf("[userdir] [%s] unknown message type 0x%02x — sending error", connID, typ)
			s.sendError(sub, errBadRequest, fmt.Sprintf("unknown message type 0x%02x", typ))
		}
	}
}

// writeAll writes all bytes of b to w, handling short writes.
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (s *Server) sendFrame(sub *connSub, typ byte, payload []byte) {
	n := uint32(1 + len(payload))
	frame := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], n)
	frame[4] = typ
	copy(frame[5:], payload)
	if !sub.deliver(frame) {
		s.logger.Printf("[userdir] [%s] ← DROPPED type=0x%02x (%s): sendCh full",
			sub.id, typ, msgTypeName(typ))
		return
	}
	s.logger.Printf("[userdir] [%s] ← send type=0x%02x (%s) payloadLen=%d",
		sub.id, typ, msgTypeName(typ), len(payload))
}

func (s *Server) sendOK(sub *connSub, msg string) {
	b := []byte(msg)
	p := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(p[0:2], uint16(len(b)))
	copy(p[2:], b)
	s.sendFrame(sub, msgOK, p)
}

func (s *Server) sendError(sub *connSub, code uint16, msg string) {
	s.logger.Printf("[userdir] [%s] ← ERROR code=0x%04x msg=%q", sub.id, code, msg)
	b := []byte(msg)
	p := make([]byte, 2+2+len(b))
	binary.BigEndian.PutUint16(p[0:2], code)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(b)))
	copy(p[4:], b)
	s.sendFrame(sub, msgError, p)
}

// ─── Request handlers ─────────────────────────────────────────────────────────

func (s *Server) handleRegister(sub *connSub, payload []byte) error {
	ver, username, fullname, pubkey, avatar, sigAlg, sig, signed, err := parseRegister(payload, s.avatarMaxBytes)
	if err != nil {
		s.logger.Printf("[userdir] [%s] REGISTER: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] REGISTER: ver=%d username=%q fullname=%q pubkey=%s avatarLen=%d sigAlg=%d",
		sub.id, ver, username, fullname, shortKey(pubkey), len(avatar), sigAlg)

	if ver != 1 {
		s.logger.Printf("[userdir] [%s] REGISTER: unsupported version %d", sub.id, ver)
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if sigAlg != 1 {
		s.logger.Printf("[userdir] [%s] REGISTER: unsupported sig_alg %d", sub.id, sigAlg)
		s.sendError(sub, errBadRequest, "unsupported signature algorithm")
		return nil
	}
	if username != "" && !usernameRe.MatchString(username) {
		s.logger.Printf("[userdir] [%s] REGISTER: invalid username format %q", sub.id, username)
		s.sendError(sub, errBadRequest, "invalid username format")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey[:]), signed, sig) {
		s.logger.Printf("[userdir] [%s] REGISTER: signature verification FAILED for pubkey=%s", sub.id, shortKey(pubkey))
		s.sendError(sub, errBadSig, "invalid signature")
		return nil
	}
	s.logger.Printf("[userdir] [%s] REGISTER: signature OK, upserting pubkey=%s", sub.id, shortKey(pubkey))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.UpsertProfile(ctx, pubkey, username, fullname, avatar); err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			s.logger.Printf("[userdir] [%s] REGISTER: username already taken %q", sub.id, username)
			s.sendError(sub, errBadRequest, "username already taken")
			return nil
		}
		s.logger.Printf("[userdir] [%s] REGISTER: upsert failed: %v", sub.id, err)
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	s.logger.Printf("[userdir] [%s] REGISTER: upsert OK pubkey=%s", sub.id, shortKey(pubkey))

	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		s.logger.Printf("[userdir] [%s] REGISTER: post-upsert fetch error (notify skipped): %v", sub.id, err)
	} else if ok {
		s.logger.Printf("[userdir] [%s] REGISTER: triggering notify for pubkey=%s", sub.id, shortKey(pubkey))
		go s.notifySubscribers(pubkey, p)
	}

	s.sendOK(sub, "OK")
	return nil
}

func (s *Server) handleSearch(sub *connSub, payload []byte) error {
	ver, query, limit, err := parseSearch(payload)
	if err != nil {
		s.logger.Printf("[userdir] [%s] SEARCH: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] SEARCH: ver=%d query=%q limit=%d", sub.id, ver, query, limit)

	if ver != 1 {
		s.logger.Printf("[userdir] [%s] SEARCH: unsupported version %d", sub.id, ver)
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if limit == 0 || limit > s.searchMax {
		s.logger.Printf("[userdir] [%s] SEARCH: clamping limit %d → %d", sub.id, limit, s.searchMax)
		limit = s.searchMax
	}
	if strings.TrimSpace(query) == "" {
		s.logger.Printf("[userdir] [%s] SEARCH: empty query -> 0 result(s)", sub.id)
		sub.deliver(buildSearchResultsFrame(nil))
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := s.store.Search(ctx, query, int(limit))
	if err != nil {
		s.logger.Printf("[userdir] [%s] SEARCH: db error: %v", sub.id, err)
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	s.logger.Printf("[userdir] [%s] SEARCH: query=%q → %d result(s)", sub.id, query, len(res))

	frame := buildSearchResultsFrame(res)
	sub.deliver(frame)
	return nil
}

func (s *Server) handleGetProfile(sub *connSub, payload []byte) error {
	ver, pubkey, err := parseGetProfile(payload)
	if err != nil {
		s.logger.Printf("[userdir] [%s] GET_PROFILE: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] GET_PROFILE: ver=%d pubkey=%s", sub.id, ver, shortKey(pubkey))

	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		s.logger.Printf("[userdir] [%s] GET_PROFILE: db error: %v", sub.id, err)
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	if !ok {
		s.logger.Printf("[userdir] [%s] GET_PROFILE: pubkey=%s not found", sub.id, shortKey(pubkey))
		s.sendError(sub, errNotFound, "not found")
		return nil
	}
	s.logger.Printf("[userdir] [%s] GET_PROFILE: pubkey=%s found username=%q avatarLen=%d updatedAt=%s",
		sub.id, shortKey(pubkey), p.Username, len(p.Avatar), p.UpdatedAt.Format(time.RFC3339))

	frame := buildProfileFrame(p)
	sub.deliver(frame)
	return nil
}

func (s *Server) handleGetMeta(sub *connSub, payload []byte) error {
	ver, pubkey, err := parseGetMeta(payload)
	if err != nil {
		s.logger.Printf("[userdir] [%s] GET_META: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] GET_META: ver=%d pubkey=%s", sub.id, ver, shortKey(pubkey))

	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		s.logger.Printf("[userdir] [%s] GET_META: db error: %v", sub.id, err)
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	if !ok {
		s.logger.Printf("[userdir] [%s] GET_META: pubkey=%s not found", sub.id, shortKey(pubkey))
		s.sendError(sub, errNotFound, "not found")
		return nil
	}
	s.logger.Printf("[userdir] [%s] GET_META: pubkey=%s found username=%q updatedAt=%s avatarSHA=%s",
		sub.id, shortKey(pubkey), p.Username, p.UpdatedAt.Format(time.RFC3339),
		hex.EncodeToString(p.AvatarSHA256[:4]))

	frame := buildMetaFrame(p)
	sub.deliver(frame)
	return nil
}

func (s *Server) handleSubscribe(sub *connSub, payload []byte) error {
	ver, pubkeys, err := parseSubscribe(payload)
	if err != nil {
		s.logger.Printf("[userdir] [%s] SUBSCRIBE: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] SUBSCRIBE: ver=%d count=%d currentSubs=%d",
		sub.id, ver, len(pubkeys), sub.subCount())

	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if len(pubkeys) == 0 {
		s.logger.Printf("[userdir] [%s] SUBSCRIBE: empty list, nothing to do", sub.id)
		s.sendOK(sub, "OK")
		return nil
	}

	max := s.subscribeMax
	if max < 0 {
		max = 0
	}

	added, limitReached := sub.subscribe(pubkeys, max)
	s.logger.Printf("[userdir] [%s] SUBSCRIBE: requested=%d added=%d limitReached=%v currentSubs=%d",
		sub.id, len(pubkeys), len(added), limitReached, sub.subCount())

	if limitReached {
		msg := fmt.Sprintf("subscribe limit reached (%d)", s.subscribeMax)
		s.logger.Printf("[userdir] [%s] SUBSCRIBE: %s", sub.id, msg)
		s.sendError(sub, errBadRequest, msg)
		return nil
	}

	s.registerSub(sub, added)

	if len(added) > 0 {
		keys := make([]string, 0, len(added))
		for _, k := range added {
			keys = append(keys, shortKey(k))
		}
		s.logger.Printf("[userdir] [%s] SUBSCRIBE: registered keys=%v", sub.id, keys)
	}

	s.sendOK(sub, "OK")
	return nil
}

func (s *Server) handleUnsubscribe(sub *connSub, payload []byte) error {
	ver, pubkeys, err := parseSubscribe(payload)
	if err != nil {
		s.logger.Printf("[userdir] [%s] UNSUBSCRIBE: parse failed: %v", sub.id, err)
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	s.logger.Printf("[userdir] [%s] UNSUBSCRIBE: ver=%d count=%d currentSubs=%d",
		sub.id, ver, len(pubkeys), sub.subCount())

	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	var removed [][32]byte
	if len(pubkeys) == 0 {
		s.logger.Printf("[userdir] [%s] UNSUBSCRIBE: unsubscribing from ALL", sub.id)
		removed = sub.unsubscribeAll()
	} else {
		removed = sub.unsubscribe(pubkeys)
	}
	s.deregisterSub(sub, removed)
	s.logger.Printf("[userdir] [%s] UNSUBSCRIBE: removed=%d remaining=%d", sub.id, len(removed), sub.subCount())

	s.sendOK(sub, "OK")
	return nil
}

func (s *Server) handleFriendRequest(sub *connSub, payload []byte) error {
	ver, requester, recipient, sigAlg, sig, signed, err := parseFriendRequest(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if sigAlg != 1 {
		s.sendError(sub, errBadRequest, "unsupported signature algorithm")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(requester[:]), signed, sig) {
		s.sendError(sub, errBadSig, "invalid signature")
		return nil
	}
	if requester == recipient {
		s.sendError(sub, errBadRequest, "cannot friend self")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	created, err := s.store.CreateFriendRequest(ctx, requester, recipient)
	if err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	s.sendOK(sub, "OK")
	if !created {
		return nil
	}

	// Notify recipient they have an incoming pending request.
	s.notifyFriend(recipient, friendEventRequestCreated, friendStatusPendingIncoming, requester, nil)
	// Notify requester too so UI can mark outgoing pending immediately.
	s.notifyFriend(requester, friendEventRequestCreated, friendStatusPendingOutgoing, recipient, nil)
	return nil
}

func (s *Server) handleFriendResponse(sub *connSub, payload []byte) error {
	ver, responder, requester, answer, sigAlg, sig, signed, err := parseFriendResponse(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if sigAlg != 1 {
		s.sendError(sub, errBadRequest, "unsupported signature algorithm")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(responder[:]), signed, sig) {
		s.sendError(sub, errBadSig, "invalid signature")
		return nil
	}

	accept := false
	switch answer {
	case 1:
		accept = true
	case 2:
		accept = false
	default:
		s.sendError(sub, errBadRequest, "invalid answer")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, room, err := s.store.RespondFriendRequest(ctx, responder, requester, accept)
	if err != nil {
		if errors.Is(err, ErrFriendRequestNotFound) {
			s.sendError(sub, errNotFound, "friend request not found")
			return nil
		}
		s.sendError(sub, errInternal, "storage error")
		return err
	}

	s.sendOK(sub, "OK")
	s.notifyFriend(requester, friendEventRequestAnswer, status, responder, room)
	s.notifyFriend(responder, friendEventRequestAnswer, status, requester, room)
	if room != nil {
		s.notifyFriend(requester, friendEventDMReady, friendStatusFriend, responder, room)
		s.notifyFriend(responder, friendEventDMReady, friendStatusFriend, requester, room)
	}
	return nil
}

func (s *Server) handleFriendSync(sub *connSub, payload []byte) error {
	ver, self, sigAlg, sig, signed, err := parseFriendSync(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if sigAlg != 1 {
		s.sendError(sub, errBadRequest, "unsupported signature algorithm")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(self[:]), signed, sig) {
		s.sendError(sub, errBadSig, "invalid signature")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := s.store.FriendSync(ctx, self)
	if err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	frame := writeFriendSnapshot(snapshot)
	sub.deliver(frame)
	return nil
}

func (s *Server) notifyFriend(target [32]byte, eventType byte, status byte, actor [32]byte, room *[16]byte) {
	s.subsMu.RLock()
	targets := make([]*connSub, 0, len(s.subs[target]))
	for sub := range s.subs[target] {
		targets = append(targets, sub)
	}
	s.subsMu.RUnlock()

	if len(targets) == 0 {
		s.logger.Printf("[userdir] friend notify target=%s event=%d: no subscribers",
			shortKey(target), eventType)
		return
	}
	frame := writeFriendNotify(eventType, status, actor, room)
	delivered, dropped := 0, 0
	for _, sub := range targets {
		if sub.deliver(frame) {
			delivered++
		} else {
			dropped++
		}
	}
	s.logger.Printf("[userdir] friend notify target=%s event=%d status=%d actor=%s delivered=%d dropped=%d",
		shortKey(target), eventType, status, shortKey(actor), delivered, dropped)
}

// ─── Frame builders ──────────────────────────────────────────────────────────

func buildSearchResultsFrame(res []SearchResult) []byte {
	if len(res) > 65535 {
		res = res[:65535]
	}
	var payload []byte
	payload = append(payload, 1)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(res)))
	payload = append(payload, tmp...)
	for _, r := range res {
		payload = append(payload, r.PubKey[:]...)
		ub := []byte(r.Username)
		fb := []byte(r.FullName)
		if len(ub) > 65535 {
			ub = ub[:65535]
		}
		if len(fb) > 65535 {
			fb = fb[:65535]
		}
		binary.BigEndian.PutUint16(tmp, uint16(len(ub)))
		payload = append(payload, tmp...)
		payload = append(payload, ub...)
		binary.BigEndian.PutUint16(tmp, uint16(len(fb)))
		payload = append(payload, tmp...)
		payload = append(payload, fb...)
		payload = append(payload, r.AvatarSHA256[:]...)
	}
	return buildFrame(msgResults, payload)
}

func buildProfileFrame(p *Profile) []byte {
	var payload []byte
	payload = append(payload, 1)
	payload = append(payload, p.PubKey[:]...)
	tmp2 := make([]byte, 2)
	ub := []byte(p.Username)
	fb := []byte(p.FullName)
	binary.BigEndian.PutUint16(tmp2, uint16(len(ub)))
	payload = append(payload, tmp2...)
	payload = append(payload, ub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(fb)))
	payload = append(payload, tmp2...)
	payload = append(payload, fb...)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, uint32(len(p.Avatar)))
	payload = append(payload, tmp4...)
	payload = append(payload, p.Avatar...)
	payload = append(payload, p.AvatarSHA256[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UpdatedAt.Unix()))
	payload = append(payload, ts[:]...)
	return buildFrame(msgProfile, payload)
}

func buildMetaFrame(p *Profile) []byte {
	var payload []byte
	payload = append(payload, 1)
	payload = append(payload, p.PubKey[:]...)
	tmp2 := make([]byte, 2)
	ub := []byte(p.Username)
	fb := []byte(p.FullName)
	binary.BigEndian.PutUint16(tmp2, uint16(len(ub)))
	payload = append(payload, tmp2...)
	payload = append(payload, ub...)
	binary.BigEndian.PutUint16(tmp2, uint16(len(fb)))
	payload = append(payload, tmp2...)
	payload = append(payload, fb...)
	payload = append(payload, p.AvatarSHA256[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(p.UpdatedAt.Unix()))
	payload = append(payload, ts[:]...)
	return buildFrame(msgMeta, payload)
}

func buildFrame(typ byte, payload []byte) []byte {
	frame := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(1+len(payload)))
	frame[4] = typ
	copy(frame[5:], payload)
	return frame
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

func parseRegister(payload []byte, avatarMax uint32) (ver byte, username, fullname string, pubkey [32]byte, avatar []byte, sigAlg byte, sig []byte, signed []byte, err error) {
	if len(payload) < 1+2+2+32+4+1+64 {
		return 0, "", "", [32]byte{}, nil, 0, nil, nil, fmt.Errorf("short register payload")
	}
	off := 0
	ver = payload[off]
	off++

	ulen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if off+ulen > len(payload) {
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

	signed = make([]byte, 1+(len(payload)-64))
	signed[0] = msgRegister
	copy(signed[1:], payload[:len(payload)-64])
	return ver, username, fullname, pubkey, avatar, sigAlg, sig, signed, nil
}

func parseSearch(payload []byte) (ver byte, query string, limit uint16, err error) {
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
	if len(payload) != 1+32 {
		return 0, [32]byte{}, fmt.Errorf("invalid get_profile payload")
	}
	ver = payload[0]
	copy(pubkey[:], payload[1:33])
	return ver, pubkey, nil
}
