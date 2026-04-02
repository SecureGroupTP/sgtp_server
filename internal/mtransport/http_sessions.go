package mtransport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp_server/server"
)

type HTTPSessionManager struct {
	logger *log.Logger
	relay  *server.Server
	ctx    context.Context

	recvTimeout time.Duration
	sendMax     int64
	bufferBytes int

	ttl          time.Duration
	cleanupEvery time.Duration

	mu       sync.Mutex
	sessions map[[16]byte]*httpSession
	closed   bool
}

type httpSession struct {
	id       [16]byte
	serverNC net.Conn
	clientNC net.Conn

	lastUsed time.Time

	recvToken chan struct{}
}

type HTTPSessionConfig struct {
	Logger *log.Logger
	Relay  *server.Server
	Ctx    context.Context

	RecvTimeout  time.Duration
	SendMaxBytes int64
	BufferBytes  int

	TTL          time.Duration
	CleanupEvery time.Duration
}

func NewHTTPSessionManager(cfg HTTPSessionConfig) *HTTPSessionManager {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.RecvTimeout <= 0 {
		cfg.RecvTimeout = 60 * time.Second
	}
	if cfg.SendMaxBytes <= 0 {
		cfg.SendMaxBytes = 16 << 20
	}
	if cfg.BufferBytes <= 0 {
		cfg.BufferBytes = 4 << 20
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.CleanupEvery <= 0 {
		cfg.CleanupEvery = 1 * time.Minute
	}
	return &HTTPSessionManager{
		logger:       cfg.Logger,
		relay:        cfg.Relay,
		ctx:          cfg.Ctx,
		recvTimeout:  cfg.RecvTimeout,
		sendMax:      cfg.SendMaxBytes,
		bufferBytes:  cfg.BufferBytes,
		ttl:          cfg.TTL,
		cleanupEvery: cfg.CleanupEvery,
		sessions:     make(map[[16]byte]*httpSession),
	}
}

func (m *HTTPSessionManager) Start(ctx context.Context) {
	go m.cleanupLoop(ctx)
}

func (m *HTTPSessionManager) CloseAll() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	sessions := make([]*httpSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[[16]byte]*httpSession)
	m.mu.Unlock()
	m.logger.Printf("[http] close-all sessions=%d", len(sessions))

	for _, s := range sessions {
		_ = s.clientNC.Close()
		_ = s.serverNC.Close()
	}
}

func (m *HTTPSessionManager) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /sgtp/session", m.handleCreateSession)
	mux.HandleFunc("DELETE /sgtp/session", m.handleDeleteSession)
	mux.HandleFunc("POST /sgtp/send", m.handleSend)
	mux.HandleFunc("GET /sgtp/recv", m.handleRecv)
}

func (m *HTTPSessionManager) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	m.logger.Printf("[http] create-session request remote=%s", r.RemoteAddr)
	select {
	case <-m.ctx.Done():
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		m.logger.Printf("[http] create-session rejected remote=%s reason=server_shutting_down", r.RemoteAddr)
		return
	default:
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	serverNC, clientNC := newBufferedConnPair(m.bufferBytes)
	sess := &httpSession{
		id:        sid,
		serverNC:  serverNC,
		clientNC:  clientNC,
		lastUsed:  time.Now(),
		recvToken: make(chan struct{}, 1),
	}
	sess.recvToken <- struct{}{}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = serverNC.Close()
		_ = clientNC.Close()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		m.logger.Printf("[http] create-session rejected remote=%s reason=manager_closed", r.RemoteAddr)
		return
	}
	m.sessions[sid] = sess
	m.mu.Unlock()
	m.logger.Printf("[http] create-session ok remote=%s sid=%s", r.RemoteAddr, hex.EncodeToString(sid[:]))

	m.relay.ServeConnAsync(m.ctx, serverNC)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sid[:])
}

func (m *HTTPSessionManager) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	sid, ok := parseSID(r.URL.Query().Get("sid"))
	if !ok {
		http.Error(w, "bad sid", http.StatusBadRequest)
		m.logger.Printf("[http] delete-session bad sid remote=%s sid=%q", r.RemoteAddr, r.URL.Query().Get("sid"))
		return
	}
	m.logger.Printf("[http] delete-session remote=%s sid=%s", r.RemoteAddr, hex.EncodeToString(sid[:]))
	m.deleteSession(sid)
	w.WriteHeader(http.StatusNoContent)
}

func (m *HTTPSessionManager) handleSend(w http.ResponseWriter, r *http.Request) {
	sid, ok := parseSID(r.URL.Query().Get("sid"))
	if !ok {
		http.Error(w, "bad sid", http.StatusBadRequest)
		m.logger.Printf("[http] send bad sid remote=%s sid=%q", r.RemoteAddr, r.URL.Query().Get("sid"))
		return
	}
	sidHex := hex.EncodeToString(sid[:])
	m.logger.Printf("[http] send request remote=%s sid=%s", r.RemoteAddr, sidHex)

	sess := m.getSession(sid)
	if sess == nil {
		http.Error(w, "unknown sid", http.StatusNotFound)
		m.logger.Printf("[http] send unknown sid remote=%s sid=%s", r.RemoteAddr, sidHex)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, m.sendMax+1))
	if err != nil {
		m.deleteSession(sid)
		http.Error(w, "session closed", http.StatusGone)
		m.logger.Printf("[http] send read body failed remote=%s sid=%s err=%v", r.RemoteAddr, sidHex, err)
		return
	}
	if int64(len(body)) > m.sendMax {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		m.logger.Printf("[http] send payload too large remote=%s sid=%s bytes=%d max=%d", r.RemoteAddr, sidHex, len(body), m.sendMax)
		return
	}
	if _, err := sess.clientNC.Write(body); err != nil {
		if errors.Is(err, errBufferFull) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "receiver is slow; retry later", http.StatusTooManyRequests)
			m.logger.Printf("[http] send backpressure remote=%s sid=%s bytes=%d", r.RemoteAddr, sidHex, len(body))
			return
		}
		m.deleteSession(sid)
		http.Error(w, "session closed", http.StatusGone)
		m.logger.Printf("[http] send write failed remote=%s sid=%s err=%v", r.RemoteAddr, sidHex, err)
		return
	}
	m.logger.Printf("[http] send ok remote=%s sid=%s bytes=%d", r.RemoteAddr, sidHex, len(body))

	m.touch(sid)
	w.WriteHeader(http.StatusNoContent)
}

func (m *HTTPSessionManager) handleRecv(w http.ResponseWriter, r *http.Request) {
	sid, ok := parseSID(r.URL.Query().Get("sid"))
	if !ok {
		http.Error(w, "bad sid", http.StatusBadRequest)
		m.logger.Printf("[http] recv bad sid remote=%s sid=%q", r.RemoteAddr, r.URL.Query().Get("sid"))
		return
	}
	sidHex := hex.EncodeToString(sid[:])
	m.logger.Printf("[http] recv request remote=%s sid=%s", r.RemoteAddr, sidHex)

	sess := m.getSession(sid)
	if sess == nil {
		http.Error(w, "unknown sid", http.StatusNotFound)
		m.logger.Printf("[http] recv unknown sid remote=%s sid=%s", r.RemoteAddr, sidHex)
		return
	}

	select {
	case <-sess.recvToken:
		defer func() { sess.recvToken <- struct{}{} }()
	default:
		http.Error(w, "recv already active", http.StatusConflict)
		m.logger.Printf("[http] recv conflict remote=%s sid=%s", r.RemoteAddr, sidHex)
		return
	}

	if err := sess.clientNC.SetReadDeadline(time.Now().Add(m.recvTimeout)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		m.logger.Printf("[http] recv set deadline failed remote=%s sid=%s err=%v", r.RemoteAddr, sidHex, err)
		return
	}
	defer sess.clientNC.SetReadDeadline(time.Time{})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)

	buf := make([]byte, 32*1024)
	totalBytes := 0
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		n, err := sess.clientNC.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				m.logger.Printf("[http] recv client write aborted remote=%s sid=%s total=%d err=%v", r.RemoteAddr, sidHex, totalBytes, werr)
				return
			}
			if fl != nil {
				fl.Flush()
			}
			m.touch(sid)
			totalBytes += n
			m.logger.Printf("[http] recv chunk remote=%s sid=%s bytes=%d total=%d", r.RemoteAddr, sidHex, n, totalBytes)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				m.logger.Printf("[http] recv timeout remote=%s sid=%s total=%d timeout=%s", r.RemoteAddr, sidHex, totalBytes, m.recvTimeout)
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				m.deleteSession(sid)
				m.logger.Printf("[http] recv session closed remote=%s sid=%s total=%d", r.RemoteAddr, sidHex, totalBytes)
				return
			}
			m.logger.Printf("[http] recv read error remote=%s sid=%s total=%d err=%v", r.RemoteAddr, sidHex, totalBytes, err)
			return
		}
	}
}

func (m *HTTPSessionManager) getSession(id [16]byte) *httpSession {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	return s
}

func (m *HTTPSessionManager) deleteSession(id [16]byte) {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s != nil {
		m.logger.Printf("[http] delete-session sid=%s", hex.EncodeToString(id[:]))
		_ = s.clientNC.Close()
		_ = s.serverNC.Close()
	}
}

func (m *HTTPSessionManager) touch(id [16]byte) {
	m.mu.Lock()
	if s := m.sessions[id]; s != nil {
		s.lastUsed = time.Now()
	}
	m.mu.Unlock()
}

func (m *HTTPSessionManager) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(m.cleanupEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		now := time.Now()
		for id := range m.snapshotSessionIDs() {
			if m.deleteSessionIfExpired(id, now) {
				m.logger.Printf("[http] ttl-expired sid=%s ttl=%s", hex.EncodeToString(id[:]), m.ttl)
			}
		}
	}
}

func (m *HTTPSessionManager) snapshotSessionIDs() map[[16]byte]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make(map[[16]byte]struct{}, len(m.sessions))
	for id := range m.sessions {
		ids[id] = struct{}{}
	}
	return ids
}

func (m *HTTPSessionManager) deleteSessionIfExpired(id [16]byte, now time.Time) bool {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil || now.Sub(s.lastUsed) <= m.ttl {
		m.mu.Unlock()
		return false
	}
	delete(m.sessions, id)
	m.mu.Unlock()

	_ = s.clientNC.Close()
	_ = s.serverNC.Close()
	return true
}

func parseSID(hex32 string) ([16]byte, bool) {
	var out [16]byte
	if len(hex32) != 32 {
		return out, false
	}
	if strings.ContainsAny(hex32, " \t\r\n") {
		return out, false
	}
	b, err := hex.DecodeString(hex32)
	if err != nil || len(b) != 16 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}
