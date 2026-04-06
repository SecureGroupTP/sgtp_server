// Package server implements a simple SGTP relay server.
//
// The relay server is a transparent byte forwarder. It reads complete SGTP
// frames from connected clients and routes them:
//
//   - receiver_uuid == BROADCAST_UUID → all clients in the room except the sender
//   - receiver_uuid != BROADCAST_UUID → unicast to that specific client
//
// When a new client connects and sends the intent frame, the server broadcasts
// that intent frame to existing room members so they learn a new peer has
// arrived and can initiate the PING handshake.
//
// The server does NOT decrypt, validate signatures, or maintain session state.
package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/SecureGroupTP/sgtp_server/protocol"
	"github.com/SecureGroupTP/sgtp_server/userdir"
)

type PolicyEngine interface {
	CheckIPAllowed(ctx context.Context, ip string) error
	CheckSubjectAllowed(ctx context.Context, scope, subject string) error
	RecordNetworkUsage(ctx context.Context, ip, pubkey string, requests, bytesRecv, bytesSent int64, transport, status string)
	RecordRoomUsage(ctx context.Context, roomID, ip, pubkey string, requests, bytesRecv, bytesSent int64, members int)
	GetMaxRoomParticipants(ctx context.Context) int
}

// ─── room ─────────────────────────────────────────────────────────────────────

type room struct {
	mu      sync.RWMutex
	clients map[[16]byte]*conn
}

func newRoom() *room {
	return &room{clients: make(map[[16]byte]*conn)}
}

func (r *room) add(c *conn) (replaced *conn) {
	r.mu.Lock()
	replaced = r.clients[c.uuid]
	r.clients[c.uuid] = c
	r.mu.Unlock()
	return replaced
}

func (r *room) remove(uuid [16]byte) {
	r.mu.Lock()
	delete(r.clients, uuid)
	r.mu.Unlock()
}

func (r *room) isEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients) == 0
}

func (r *room) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.clients)
}

// broadcast sends raw to all clients except the one with senderID.
func (r *room) broadcast(senderID [16]byte, raw []byte) {
	r.mu.RLock()
	targets := make([]*conn, 0, len(r.clients))
	for id, c := range r.clients {
		if id != senderID {
			targets = append(targets, c)
		}
	}
	r.mu.RUnlock()
	for _, c := range targets {
		c.send(raw)
	}
}

// unicast sends raw to the single client with receiverID.
func (r *room) unicast(receiverID [16]byte, raw []byte) {
	r.mu.RLock()
	c := r.clients[receiverID]
	r.mu.RUnlock()
	if c != nil {
		c.send(raw)
	}
}

// ─── conn ─────────────────────────────────────────────────────────────────────

type conn struct {
	uuid    [16]byte
	roomID  [16]byte
	netConn net.Conn

	logger *log.Logger
	connID string

	sendCh chan []byte

	sendTimeout time.Duration

	closeOnce sync.Once
	closed    chan struct{}
}

func newConn(uuid, roomID [16]byte, nc net.Conn, queue int, sendTimeout time.Duration, logger *log.Logger, connID string) *conn {
	if queue <= 0 {
		queue = 64
	}
	if sendTimeout <= 0 {
		sendTimeout = 250 * time.Millisecond
	}
	c := &conn{
		uuid:        uuid,
		roomID:      roomID,
		netConn:     nc,
		logger:      logger,
		connID:      connID,
		sendCh:      make(chan []byte, queue),
		sendTimeout: sendTimeout,
		closed:      make(chan struct{}),
	}
	go c.writeLoop()
	return c
}

func (c *conn) send(raw []byte) {
	b := append([]byte(nil), raw...)
	select {
	case c.sendCh <- b:
		if c.logger != nil {
			c.logger.Printf("[server] [%s] enqueue outbound bytes=%d queue_len=%d", c.connID, len(b), len(c.sendCh))
		}
		return
	case <-c.closed:
		if c.logger != nil {
			c.logger.Printf("[server] [%s] drop outbound bytes=%d reason=connection_closed", c.connID, len(b))
		}
		return
	default:
	}

	timer := time.NewTimer(c.sendTimeout)
	defer timer.Stop()

	select {
	case c.sendCh <- b:
		if c.logger != nil {
			c.logger.Printf("[server] [%s] enqueue outbound after wait bytes=%d queue_len=%d wait=%s", c.connID, len(b), len(c.sendCh), c.sendTimeout)
		}
	case <-c.closed:
		if c.logger != nil {
			c.logger.Printf("[server] [%s] drop outbound bytes=%d reason=connection_closed", c.connID, len(b))
		}
	case <-timer.C:
		// Slow consumer persisted long enough to block broadcasters.
		if c.logger != nil {
			c.logger.Printf("[server] [%s] queue full for %s (cap=%d) closing slow consumer", c.connID, c.sendTimeout, cap(c.sendCh))
		}
		c.Close()
	}
}

func (c *conn) Close() {
	c.closeOnce.Do(func() {
		if c.logger != nil {
			c.logger.Printf("[server] [%s] conn close", c.connID)
		}
		close(c.closed)
		_ = c.netConn.Close()
	})
}

func (c *conn) writeLoop() {
	for {
		select {
		case b := <-c.sendCh:
			if err := writeAll(c.netConn, b); err != nil {
				if c.logger != nil {
					c.logger.Printf("[server] [%s] write outbound failed bytes=%d err=%v", c.connID, len(b), err)
				}
				c.Close()
				return
			}
			if c.logger != nil {
				c.logger.Printf("[server] [%s] write outbound ok bytes=%d", c.connID, len(b))
			}
		case <-c.closed:
			if c.logger != nil {
				c.logger.Printf("[server] [%s] write loop exit: closed", c.connID)
			}
			return
		}
	}
}

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

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the SGTP relay server.
//
// Use ListenAndServe(ctx) to run it, and Shutdown(ctx) to stop it gracefully.
type Server struct {
	addr   string
	logger *log.Logger

	writeQueue  int
	sendTimeout time.Duration

	// userdirSrv is optional. When non-nil, connections whose first 32 bytes
	// are all zero are routed to the userdir handler instead of the relay.
	userdirSrv *userdir.Server
	policy     PolicyEngine

	roomsMu sync.RWMutex
	rooms   map[[16]byte]*room

	mu        sync.Mutex
	listener  net.Listener
	conns     map[*conn]struct{}
	closeOnce sync.Once
	closing   chan struct{}

	wg sync.WaitGroup
}

// New creates a Server that will listen on addr (e.g. ":7777").
// If logger is nil, log.Default() is used.
// ud is optional: when non-nil, connections prefixed with 32 zero bytes are
// transparently routed to the userdir handler on the same port.
func New(addr string, logger *log.Logger, ud *userdir.Server) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		addr:        addr,
		logger:      logger,
		writeQueue:  64,
		sendTimeout: 250 * time.Millisecond,
		userdirSrv:  ud,
		rooms:       make(map[[16]byte]*room),
		conns:       make(map[*conn]struct{}),
		closing:     make(chan struct{}),
	}
}

func (s *Server) SetPolicyEngine(policy PolicyEngine) {
	s.policy = policy
}

// ListenAndServe starts the TCP listener and blocks until it returns an error
// or ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sgtp: listen %s: %w", s.addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve runs the server on the provided listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return fmt.Errorf("sgtp: Serve called more than once")
	}
	s.listener = ln
	s.mu.Unlock()

	s.logger.Printf("[server] listening on %s", ln.Addr().String())

	stopCtx := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.initiateClose()
		case <-stopCtx:
		}
	}()
	defer close(stopCtx)

	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			if isTemporaryAcceptError(err) {
				s.logger.Printf("[server] transient accept error: %v", err)
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			return fmt.Errorf("sgtp: accept: %w", err)
		}

		s.ServeConnAsync(ctx, nc)
	}
}

// ServeConn handles an already-accepted connection and blocks until it exits.
// The connection is tracked so Shutdown() waits for it to fully exit.
func (s *Server) ServeConn(ctx context.Context, nc net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()
	s.handleConn(ctx, nc)
}

// ServeConnAsync is a convenience wrapper around ServeConn that runs the
// connection handler in its own goroutine.
func (s *Server) ServeConnAsync(ctx context.Context, nc net.Conn) {
	go s.ServeConn(ctx, nc)
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

		s.mu.Lock()
		conns := make([]*conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
}

// Shutdown stops accepting new connections, closes all active connections, and
// waits for connection goroutines to exit until ctx is done.
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

func (s *Server) trackConn(c *conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	total := len(s.conns)
	s.mu.Unlock()
	s.logger.Printf("[server] [%s] tracked active=%d", c.connID, total)
}

func (s *Server) untrackConn(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	total := len(s.conns)
	s.mu.Unlock()
	s.logger.Printf("[server] [%s] untracked active=%d", c.connID, total)
}

func (s *Server) getOrCreateRoom(roomID [16]byte) *room {
	s.roomsMu.Lock()
	r := s.rooms[roomID]
	if r == nil {
		r = newRoom()
		s.rooms[roomID] = r
	}
	s.roomsMu.Unlock()
	return r
}

// handleConn manages one TCP connection for its lifetime.
func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	done := make(chan struct{})
	defer close(done)
	remote := nc.RemoteAddr().String()
	ip := parseRemoteIP(remote)
	s.logger.Printf("[server] new connection from %s", remote)

	if s.policy != nil {
		if err := s.policy.CheckIPAllowed(ctx, ip); err != nil {
			s.logger.Printf("[server] deny connection remote=%s ip=%s reason=%v", remote, ip, err)
			return
		}
		s.policy.RecordNetworkUsage(ctx, ip, "", 1, 0, 0, "tcp", "connected")
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = nc.Close()
		case <-s.closing:
			_ = nc.Close()
		case <-done:
		}
	}()

	// ── Routing: read first 32 bytes (RoomUUID + ReceiverUUID) ───────────────
	// If both are the all-zero UUID the client is speaking the userdir protocol
	// (it sends a 32-byte zero magic prefix, then raw userdir frames).
	first32 := make([]byte, 32)
	if _, err := io.ReadFull(nc, first32); err != nil {
		s.logger.Printf("[server] %s: read routing bytes: %v", remote, err)
		return
	}
	s.logger.Printf("[server] %s: routing prefix read (32 bytes)", remote)

	if isAllZero(first32) {
		if s.userdirSrv != nil {
			s.logger.Printf("[server] %s: routing to userdir", remote)
			s.userdirSrv.ServeConn(ctx, nc, nc)
		} else {
			s.logger.Printf("[server] %s: userdir not configured, closing", remote)
		}
		return
	}

	// ── Read the connection-intent frame ─────────────────────────────────────
	// Format: [64-byte header][payload][64-byte signature].
	// We already have the first 32 bytes; read the remaining 32 to complete the header.
	hdrBuf := make([]byte, protocol.HeaderSize)
	copy(hdrBuf[0:32], first32)
	if _, err := io.ReadFull(nc, hdrBuf[32:]); err != nil {
		s.logger.Printf("[server] %s: read intent header: %v", remote, err)
		return
	}

	hdr, err := protocol.UnmarshalHeader(hdrBuf)
	if err != nil {
		s.logger.Printf("[server] %s: parse intent header: %v", remote, err)
		return
	}

	if hdr.PayloadLen > protocol.MaxPayloadLength {
		s.logger.Printf("[server] %s: intent payload_length %d too large — closing", remote, hdr.PayloadLen)
		return
	}

	tail := make([]byte, int(hdr.PayloadLen)+protocol.SignatureSize)
	if _, err := io.ReadFull(nc, tail); err != nil {
		s.logger.Printf("[server] %s: read intent tail: %v", remote, err)
		return
	}

	roomID := hdr.RoomUUID
	roomIDHex := hex.EncodeToString(roomID[:])
	senderID := hdr.SenderUUID
	intentRaw := append(append([]byte(nil), hdrBuf...), tail...)

	s.logger.Printf("[server] intent from uuid=%x room=%x", senderID[:4], roomID[:4])
	connID := fmt.Sprintf("%s uuid=%x room=%x", remote, senderID[:4], roomID[:4])

	// ── Register client in room ──────────────────────────────────────────────
	r := s.getOrCreateRoom(roomID)
	if s.policy != nil {
		if err := s.policy.CheckSubjectAllowed(ctx, "room", roomIDHex); err != nil {
			s.logger.Printf("[server] reject join room=%x ip=%s reason=%v", roomID[:4], ip, err)
			return
		}
		maxParticipants := s.policy.GetMaxRoomParticipants(ctx)
		if maxParticipants > 0 && r.count() >= maxParticipants {
			s.logger.Printf("[server] reject join room=%x ip=%s reason=room_full limit=%d", roomID[:4], ip, maxParticipants)
			return
		}
	}

	// Broadcast the intent frame to existing members BEFORE adding the new client.
	r.broadcast(senderID, intentRaw)
	s.logger.Printf("[server] intent broadcast to %d existing members", r.count())

	cn := newConn(senderID, roomID, nc, s.writeQueue, s.sendTimeout, s.logger, connID)
	s.trackConn(cn)
	defer func() {
		cn.Close()
		s.untrackConn(cn)
	}()

	if replaced := r.add(cn); replaced != nil && replaced != cn {
		replaced.Close()
	}
	if s.policy != nil {
		s.policy.RecordRoomUsage(ctx, roomIDHex, ip, "", 0, 0, 0, r.count())
	}
	s.logger.Printf("[server] uuid=%x joined room=%x (members now: %d)", senderID[:4], roomID[:4], r.count())

	// ── Forward loop ─────────────────────────────────────────────────────────
	trackedPubKey := ""
	defer func() {
		r.remove(senderID)
		if r.isEmpty() {
			s.roomsMu.Lock()
			delete(s.rooms, roomID)
			s.roomsMu.Unlock()
		}
		s.logger.Printf("[server] uuid=%x left room=%x (members now: %d)", senderID[:4], roomID[:4], r.count())
		if s.policy != nil {
			s.policy.RecordRoomUsage(ctx, roomIDHex, ip, trackedPubKey, 0, 0, 0, r.count())
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closing:
			return
		default:
		}

		raw, fhdr, err := readRawFrame(nc)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				s.logger.Printf("[server] [%s] read loop closed: %v", connID, err)
			} else {
				s.logger.Printf("[server] uuid=%x read error: %v", senderID[:4], err)
			}
			return
		}
		if s.policy != nil {
			if err := s.policy.CheckSubjectAllowed(ctx, "ip", ip); err != nil {
				s.logger.Printf("[server] deny frame remote=%s ip=%s reason=%v", remote, ip, err)
				return
			}
			if pk, ok := extractPubKeyFromFrame(raw, fhdr); ok {
				trackedPubKey = pk
			}
			if trackedPubKey != "" {
				if err := s.policy.CheckSubjectAllowed(ctx, "public_key", trackedPubKey); err != nil {
					s.logger.Printf("[server] deny frame remote=%s pubkey=%s reason=%v", remote, trackedPubKey[:8], err)
					return
				}
			}
			if err := s.policy.CheckSubjectAllowed(ctx, "room", roomIDHex); err != nil {
				s.logger.Printf("[server] deny frame remote=%s room=%s reason=%v", remote, roomIDHex[:8], err)
				return
			}
			s.policy.RecordNetworkUsage(ctx, ip, trackedPubKey, 1, int64(len(raw)), 0, "tcp", "frame_in")
			s.policy.RecordRoomUsage(ctx, roomIDHex, ip, trackedPubKey, 1, int64(len(raw)), 0, r.count())
		}

		s.logger.Printf("[server] relay type=0x%02x from=%x to=%x len=%d",
			uint16(fhdr.PacketType), senderID[:4], fhdr.ReceiverUUID[:4], len(raw))

		if fhdr.ReceiverUUID == protocol.BroadcastUUID {
			r.broadcast(senderID, raw)
		} else {
			r.unicast(fhdr.ReceiverUUID, raw)
		}
		if fhdr.PacketType == protocol.TypeMessage {
			if ackRaw, ok := buildMessageACKFrame(raw, fhdr, senderID); ok {
				cn.send(ackRaw)
			} else {
				s.logger.Printf("[server] [%s] skip MESSAGE_ACK: malformed MESSAGE payload_len=%d", connID, fhdr.PayloadLen)
			}
		}
		if s.policy != nil {
			s.policy.RecordNetworkUsage(ctx, ip, trackedPubKey, 0, 0, int64(len(raw)), "tcp", "frame_out")
			s.policy.RecordRoomUsage(ctx, roomIDHex, ip, trackedPubKey, 0, 0, int64(len(raw)), r.count())
		}
	}
}

func isTemporaryAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Temporary() {
		return true
	}
	return errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM)
}

// isAllZero reports whether every byte in b is 0x00.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func parseRemoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

// extractPubKeyFromFrame tries to recover sender Ed25519 pubkey from SGTP
// handshake packets (PING/PONG payload layout: 32 x25519 + 32 ed25519 + body).
func extractPubKeyFromFrame(raw []byte, hdr *protocol.Header) (string, bool) {
	if hdr == nil {
		return "", false
	}
	if hdr.PacketType != protocol.TypePing && hdr.PacketType != protocol.TypePong {
		return "", false
	}
	if len(raw) < protocol.HeaderSize+64 {
		return "", false
	}
	pub := raw[protocol.HeaderSize+32 : protocol.HeaderSize+64]
	return hex.EncodeToString(pub), true
}

// readRawFrame reads exactly one complete SGTP frame from r.
// It only inspects the header to find boundaries — it does not parse content.
func readRawFrame(r io.Reader) ([]byte, *protocol.Header, error) {
	hdrBuf := make([]byte, protocol.HeaderSize)
	if _, err := io.ReadFull(r, hdrBuf); err != nil {
		return nil, nil, err
	}

	payloadLen := binary.BigEndian.Uint32(hdrBuf[52:56])
	if payloadLen > protocol.MaxPayloadLength {
		return nil, nil, fmt.Errorf("sgtp: payload_length %d exceeds maximum", payloadLen)
	}

	rest := make([]byte, int(payloadLen)+protocol.SignatureSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, nil, err
	}

	hdr, err := protocol.UnmarshalHeader(hdrBuf)
	if err != nil {
		return nil, nil, err
	}

	raw := make([]byte, 0, len(hdrBuf)+len(rest))
	raw = append(raw, hdrBuf...)
	raw = append(raw, rest...)
	return raw, hdr, nil
}

// buildMessageACKFrame constructs a MESSAGE_ACK for the incoming MESSAGE frame.
// ACK payload layout: 16-byte MessageUUID copied from MESSAGE payload[0:16].
func buildMessageACKFrame(raw []byte, hdr *protocol.Header, receiverID [16]byte) ([]byte, bool) {
	if hdr == nil || hdr.PacketType != protocol.TypeMessage || len(raw) < protocol.HeaderSize+16 {
		return nil, false
	}

	var msgUUID [16]byte
	copy(msgUUID[:], raw[protocol.HeaderSize:protocol.HeaderSize+16])

	ackHdr := protocol.Header{
		RoomUUID:     hdr.RoomUUID,
		ReceiverUUID: receiverID,
		SenderUUID:   protocol.BroadcastUUID,
		Version:      protocol.ProtocolVersion,
		PacketType:   protocol.TypeMessageACK,
		PayloadLen:   16,
		Timestamp:    uint64(time.Now().UTC().UnixMilli()),
	}
	ackRaw := protocol.MarshalHeader(&ackHdr)
	ackRaw = append(ackRaw, msgUUID[:]...)
	ackRaw = append(ackRaw, make([]byte, protocol.SignatureSize)...)
	return ackRaw, true
}
