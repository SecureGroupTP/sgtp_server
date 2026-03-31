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

// ─── connSub ─────────────────────────────────────────────────────────────────

// connSub tracks the subscription state for a single open connection.
// It is created inside ServeConn and registered/deregistered in the subs map.
type connSub struct {
	sendCh chan []byte // outbound frames (responses + async notifies)

	mu   sync.Mutex
	keys map[[32]byte]struct{} // pubkeys this connection is subscribed to
}

func newConnSub(sendBuf int) *connSub {
	return &connSub{
		sendCh: make(chan []byte, sendBuf),
		keys:   make(map[[32]byte]struct{}),
	}
}

// subscribe adds pubkeys to the subscription set and returns how many were
// actually new (i.e. not already subscribed).
func (c *connSub) subscribe(keys [][32]byte, max int) (added int, limitReached bool) {
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
		added++
	}
	return added, limitReached
}

// unsubscribe removes pubkeys from the subscription set.
// Returns the slice of keys that were actually removed.
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

// deliver tries to enqueue a pre-built frame for delivery to the client.
// Drops silently if the send buffer is full (slow consumer).
func (c *connSub) deliver(frame []byte) {
	select {
	case c.sendCh <- frame:
	default:
	}
}

// ─── Server ──────────────────────────────────────────────────────────────────

type Server struct {
	addr   string
	logger *log.Logger
	store  *Store

	avatarMaxBytes uint32
	searchMax      uint16
	subscribeMax   int // max pubkeys per connection (0 = unlimited)
	cleanupEvery   time.Duration

	// subs maps pubkey → set of connSubs subscribed to it.
	subsMu sync.RWMutex
	subs   map[[32]byte]map[*connSub]struct{}

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

// notifySubscribers is called after a successful profile upsert.
// It builds a NOTIFY frame once and fans it out to every subscriber.
func (s *Server) notifySubscribers(pubkey [32]byte, p *Profile) {
	s.subsMu.RLock()
	targets := make([]*connSub, 0, len(s.subs[pubkey]))
	for sub := range s.subs[pubkey] {
		targets = append(targets, sub)
	}
	s.subsMu.RUnlock()

	if len(targets) == 0 {
		return
	}

	frame, err := writeNotify(p)
	if err != nil {
		s.logger.Printf("[userdir] notify: build frame: %v", err)
		return
	}

	for _, sub := range targets {
		sub.deliver(frame)
	}
	s.logger.Printf("[userdir] notify: pushed to %d subscriber(s) for pubkey %x", len(targets), pubkey[:4])
}

// ─── Connection handling ─────────────────────────────────────────────────────

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
//
// Read and write are separated: a background goroutine drains sendCh → w so
// that server-pushed NOTIFY frames can arrive independently of the read loop.
func (s *Server) ServeConn(ctx context.Context, r io.Reader, w io.Writer) {
	sub := newConnSub(128)

	// Write goroutine: drains sub.sendCh → w.
	writeCtx, writeCancel := context.WithCancel(ctx)
	defer writeCancel()

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for {
			select {
			case frame, ok := <-sub.sendCh:
				if !ok {
					return
				}
				if err := writeAll(w, frame); err != nil {
					return
				}
			case <-writeCtx.Done():
				// Drain any remaining frames before exit.
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
		// Unregister all subscriptions for this connection.
		keys := sub.unsubscribeAll()
		s.deregisterSub(sub, keys)
		// Signal write goroutine to stop, then wait.
		writeCancel()
		close(sub.sendCh)
		<-writeDone
	}()

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
			if err := s.handleRegister(sub, payload); err != nil {
				s.logger.Printf("[userdir] register error: %v", err)
			}
		case msgSearch:
			if err := s.handleSearch(sub, payload); err != nil {
				s.logger.Printf("[userdir] search error: %v", err)
			}
		case msgGetProfile:
			if err := s.handleGetProfile(sub, payload); err != nil {
				s.logger.Printf("[userdir] get_profile error: %v", err)
			}
		case msgGetMeta:
			if err := s.handleGetMeta(sub, payload); err != nil {
				s.logger.Printf("[userdir] get_meta error: %v", err)
			}
		case msgSubscribe:
			if err := s.handleSubscribe(sub, payload); err != nil {
				s.logger.Printf("[userdir] subscribe error: %v", err)
			}
		case msgUnsubscribe:
			if err := s.handleUnsubscribe(sub, payload); err != nil {
				s.logger.Printf("[userdir] unsubscribe error: %v", err)
			}
		default:
			s.sendError(sub, errBadRequest, "unknown message type")
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

// sendFrame enqueues a pre-serialised frame for delivery. Uses the connSub
// channel so the response goes through the same serialised write goroutine as
// async notifies, avoiding concurrent writes to w.
func (s *Server) sendFrame(sub *connSub, typ byte, payload []byte) {
	n := uint32(1 + len(payload))
	frame := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], n)
	frame[4] = typ
	copy(frame[5:], payload)
	sub.deliver(frame)
}

func (s *Server) sendOK(sub *connSub, msg string) {
	b := []byte(msg)
	p := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(p[0:2], uint16(len(b)))
	copy(p[2:], b)
	s.sendFrame(sub, msgOK, p)
}

func (s *Server) sendError(sub *connSub, code uint16, msg string) {
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
	if !usernameRe.MatchString(username) {
		s.sendError(sub, errBadRequest, "invalid username format")
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey[:]), signed, sig) {
		s.sendError(sub, errBadSig, "invalid signature")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.UpsertProfile(ctx, pubkey, username, fullname, avatar); err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}

	// Fetch the stored profile (with updated_at / avatar_sha256) for notifications.
	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err == nil && ok {
		go s.notifySubscribers(pubkey, p)
	}

	s.sendOK(sub, "OK")
	return nil
}

func (s *Server) handleSearch(sub *connSub, payload []byte) error {
	ver, query, limit, err := parseSearch(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if limit == 0 || limit > s.searchMax {
		limit = s.searchMax
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := s.store.Search(ctx, query, int(limit))
	if err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}

	frame := buildSearchResultsFrame(res)
	sub.deliver(frame)
	return nil
}

func (s *Server) handleGetProfile(sub *connSub, payload []byte) error {
	ver, pubkey, err := parseGetProfile(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	if !ok {
		s.sendError(sub, errNotFound, "not found")
		return nil
	}

	frame := buildProfileFrame(p)
	sub.deliver(frame)
	return nil
}

func (s *Server) handleGetMeta(sub *connSub, payload []byte) error {
	ver, pubkey, err := parseGetMeta(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, ok, err := s.store.GetByPubKey(ctx, pubkey)
	if err != nil {
		s.sendError(sub, errInternal, "storage error")
		return err
	}
	if !ok {
		s.sendError(sub, errNotFound, "not found")
		return nil
	}

	frame := buildMetaFrame(p)
	sub.deliver(frame)
	return nil
}

// handleSubscribe adds pubkeys to the connection's subscription set.
func (s *Server) handleSubscribe(sub *connSub, payload []byte) error {
	ver, pubkeys, err := parseSubscribe(payload)
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}
	if len(pubkeys) == 0 {
		s.sendOK(sub, "OK")
		return nil
	}

	max := s.subscribeMax
	if max < 0 {
		max = 0 // 0 in subscribe() means unlimited
	}

	added, limitReached := sub.subscribe(pubkeys, max)
	if limitReached {
		s.sendError(sub, errBadRequest, fmt.Sprintf("subscribe limit reached (%d)", s.subscribeMax))
		return nil
	}

	// Register only the newly added keys in the server map.
	newKeys := make([][32]byte, 0, added)
	sub.mu.Lock()
	for _, k := range pubkeys {
		if _, ok := sub.keys[k]; ok {
			newKeys = append(newKeys, k)
			if len(newKeys) == added {
				break
			}
		}
	}
	sub.mu.Unlock()
	s.registerSub(sub, newKeys)

	s.sendOK(sub, "OK")
	return nil
}

// handleUnsubscribe removes pubkeys from the connection's subscription set.
// count == 0 means unsubscribe from everything.
func (s *Server) handleUnsubscribe(sub *connSub, payload []byte) error {
	ver, pubkeys, err := parseSubscribe(payload) // same wire format
	if err != nil {
		s.sendError(sub, errBadRequest, err.Error())
		return err
	}
	if ver != 1 {
		s.sendError(sub, errBadRequest, "unsupported version")
		return nil
	}

	var removed [][32]byte
	if len(pubkeys) == 0 {
		removed = sub.unsubscribeAll()
	} else {
		removed = sub.unsubscribe(pubkeys)
	}
	s.deregisterSub(sub, removed)

	s.sendOK(sub, "OK")
	return nil
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

// ─── Parsers (kept here to avoid splitting across files) ─────────────────────

func parseRegister(payload []byte, avatarMax uint32) (ver byte, username, fullname string, pubkey [32]byte, avatar []byte, sigAlg byte, sig []byte, signed []byte, err error) {
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
