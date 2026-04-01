package mtransport

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp_server/server"
)

const tlsEnabled = false

type MultiServer struct {
	Logger *log.Logger
	Relay  *server.Server

	BindHost string

	DiscoveryPort uint16
	Ports         Ports

	HTTPRecvTimeout  time.Duration
	HTTPSendMax      int64
	HTTPBufferBytes  int
	HTTPSessionTTL   time.Duration
	HTTPCleanupEvery time.Duration

	mu          sync.Mutex
	discoveryLn net.Listener
	tcpLn       net.Listener
	httpLns     map[uint16]net.Listener
	httpSrvs    map[uint16]*http.Server
	httpSess    *HTTPSessionManager
}

func (m *MultiServer) Start(ctx context.Context) error {
	if m.Logger == nil {
		m.Logger = log.Default()
	}
	if m.Relay == nil {
		return fmt.Errorf("mtransport: Relay is required")
	}
	if !m.Ports.AnyEnabled() {
		return fmt.Errorf("mtransport: no transports enabled")
	}
	if !tlsEnabled && (m.Ports.TCPTLS != 0 || m.Ports.HTTPTLS != 0 || m.Ports.WSTLS != 0) {
		return fmt.Errorf("mtransport: TLS ports are set but TLS is disabled at build time")
	}

	m.httpLns = make(map[uint16]net.Listener)
	m.httpSrvs = make(map[uint16]*http.Server)

	// ── Discovery ───────────────────────────────────────────────────────────
	if m.DiscoveryPort != 0 {
		ln, err := net.Listen("tcp", m.listenAddr(m.DiscoveryPort))
		if err != nil {
			return fmt.Errorf("discovery listen: %w", err)
		}
		m.discoveryLn = ln
		resp := m.Ports.DiscoveryResponse()
		m.Logger.Printf("[discovery] listening on %s", ln.Addr().String())
		go m.serveDiscovery(ctx, ln, resp[:])
	}

	// ── TCP ─────────────────────────────────────────────────────────────────
	if m.Ports.TCP != 0 {
		ln, err := net.Listen("tcp", m.listenAddr(m.Ports.TCP))
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		m.tcpLn = ln
		m.Logger.Printf("[tcp] listening on %s", ln.Addr().String())
		go m.serveTCP(ctx, ln)
	}

	// ── HTTP / WS (plain) ───────────────────────────────────────────────────
	muxByPort := map[uint16]*http.ServeMux{}
	getMux := func(port uint16) *http.ServeMux {
		mux := muxByPort[port]
		if mux == nil {
			mux = http.NewServeMux()
			muxByPort[port] = mux
			mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})
		}
		return mux
	}

	if m.Ports.HTTP != 0 {
		m.httpSess = NewHTTPSessionManager(HTTPSessionConfig{
			Logger:       m.Logger,
			Relay:        m.Relay,
			Ctx:          ctx,
			RecvTimeout:  m.HTTPRecvTimeout,
			SendMaxBytes: m.HTTPSendMax,
			BufferBytes:  m.HTTPBufferBytes,
			TTL:          m.HTTPSessionTTL,
			CleanupEvery: m.HTTPCleanupEvery,
		})
		m.httpSess.Register(getMux(m.Ports.HTTP))
		m.httpSess.Start(ctx)
	}

	if m.Ports.WS != 0 {
		WSHandler{
			Logger: m.Logger,
			Relay:  m.Relay,
			Ctx:    ctx,
		}.Register(getMux(m.Ports.WS))
	}

	for port, mux := range muxByPort {
		ln, err := net.Listen("tcp", m.listenAddr(port))
		if err != nil {
			return fmt.Errorf("http/ws listen (%d): %w", port, err)
		}
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		m.httpLns[port] = ln
		m.httpSrvs[port] = srv
		m.Logger.Printf("[http] listening on %s", ln.Addr().String())
		go func(port uint16) {
			err := srv.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				m.Logger.Printf("[http] port=%d Serve error: %v", port, err)
			}
		}(port)
	}

	return nil
}

func (m *MultiServer) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	discoveryLn := m.discoveryLn
	tcpLn := m.tcpLn
	httpLns := m.httpLns
	httpSrvs := m.httpSrvs
	httpSess := m.httpSess
	m.discoveryLn = nil
	m.tcpLn = nil
	m.httpLns = nil
	m.httpSrvs = nil
	m.httpSess = nil
	m.mu.Unlock()

	if discoveryLn != nil {
		_ = discoveryLn.Close()
	}
	if tcpLn != nil {
		_ = tcpLn.Close()
	}
	for _, ln := range httpLns {
		_ = ln.Close()
	}
	for _, srv := range httpSrvs {
		_ = srv.Shutdown(ctx)
	}
	if httpSess != nil {
		httpSess.CloseAll()
	}
	return nil
}

func (m *MultiServer) listenAddr(port uint16) string {
	host := m.BindHost
	if host == "" {
		return fmt.Sprintf(":%d", port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (m *MultiServer) serveDiscovery(ctx context.Context, ln net.Listener, resp []byte) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			m.Logger.Printf("[discovery] accept error: %v", err)
			return
		}
		go func(c net.Conn) {
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = writeAll(c, resp)
			_ = c.Close()
		}(nc)
	}
}

func (m *MultiServer) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			m.Logger.Printf("[tcp] accept error: %v", err)
			return
		}
		m.Relay.ServeConnAsync(ctx, nc)
	}
}

func writeAll(w net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
