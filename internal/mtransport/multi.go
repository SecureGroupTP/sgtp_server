package mtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/SecureGroupTP/sgtp_server/server"
)

type MultiServer struct {
	Logger *log.Logger
	Relay  *server.Server

	BindHost  string
	TLSConfig *tls.Config

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
	tlsTCPLn    net.Listener
	httpLns     map[uint16]net.Listener
	httpSrvs    map[uint16]*http.Server
	tlsLns      map[uint16]net.Listener
	tlsSrvs     map[uint16]*http.Server
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
	if (m.Ports.TCPTLS != 0 || m.Ports.HTTPTLS != 0 || m.Ports.WSTLS != 0) && m.TLSConfig == nil {
		return fmt.Errorf("mtransport: TLS ports are set but TLS config is nil")
	}

	m.httpLns = make(map[uint16]net.Listener)
	m.httpSrvs = make(map[uint16]*http.Server)
	m.tlsLns = make(map[uint16]net.Listener)
	m.tlsSrvs = make(map[uint16]*http.Server)

	// Pre-compute the 25-byte discovery payload once; it is sent on both the
	// dedicated discovery port (if configured) AND the plain TCP relay port.
	// This lets clients use the TCP relay port for "Fetch server options"
	// without needing to know a separate discovery port.
	discoveryResp := m.Ports.DiscoveryResponse()

	// ── Discovery ───────────────────────────────────────────────────────────
	if m.DiscoveryPort != 0 {
		ln, err := net.Listen("tcp", m.listenAddr(m.DiscoveryPort))
		if err != nil {
			return fmt.Errorf("discovery listen: %w", err)
		}
		m.discoveryLn = ln
		m.Logger.Printf("[discovery] listening on %s", ln.Addr().String())
		go m.serveDiscovery(ctx, ln, discoveryResp[:])
	}

	// ── TCP ─────────────────────────────────────────────────────────────────
	if m.Ports.TCP != 0 {
		ln, err := net.Listen("tcp", m.listenAddr(m.Ports.TCP))
		if err != nil {
			return fmt.Errorf("tcp listen: %w", err)
		}
		m.tcpLn = ln
		m.Logger.Printf("[tcp] listening on %s", ln.Addr().String())
		go m.serveTCP(ctx, ln, discoveryResp[:])
	}

	// ── HTTP / WS (plain + TLS) ──────────────────────────────────────────────
	newMux := func() *http.ServeMux {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		return mux
	}

	muxByPort := map[uint16]*http.ServeMux{}
	tlsMuxByPort := map[uint16]*http.ServeMux{}
	getMux := func(port uint16) *http.ServeMux {
		mux := muxByPort[port]
		if mux == nil {
			mux = newMux()
			muxByPort[port] = mux
		}
		return mux
	}
	getTLSMux := func(port uint16) *http.ServeMux {
		mux := tlsMuxByPort[port]
		if mux == nil {
			mux = newMux()
			tlsMuxByPort[port] = mux
		}
		return mux
	}

	if m.Ports.HTTP != 0 || m.Ports.HTTPTLS != 0 {
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
		if m.Ports.HTTP != 0 {
			m.httpSess.Register(getMux(m.Ports.HTTP))
		}
		if m.Ports.HTTPTLS != 0 {
			m.httpSess.Register(getTLSMux(m.Ports.HTTPTLS))
		}
		m.httpSess.Start(ctx)
	}

	if m.Ports.WS != 0 {
		WSHandler{
			Logger: m.Logger,
			Relay:  m.Relay,
			Ctx:    ctx,
		}.Register(getMux(m.Ports.WS))
	}
	if m.Ports.WSTLS != 0 {
		WSHandler{
			Logger: m.Logger,
			Relay:  m.Relay,
			Ctx:    ctx,
		}.Register(getTLSMux(m.Ports.WSTLS))
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

	for port, mux := range tlsMuxByPort {
		ln, err := tls.Listen("tcp", m.listenAddr(port), m.TLSConfig)
		if err != nil {
			return fmt.Errorf("http/tls listen (%d): %w", port, err)
		}
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		m.tlsLns[port] = ln
		m.tlsSrvs[port] = srv
		m.Logger.Printf("[http tls] listening on %s", ln.Addr().String())
		go func(port uint16) {
			err := srv.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				m.Logger.Printf("[http tls] port=%d Serve error: %v", port, err)
			}
		}(port)
	}

	return nil
}

func (m *MultiServer) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	discoveryLn := m.discoveryLn
	tcpLn := m.tcpLn
	tlsTCPLn := m.tlsTCPLn
	httpLns := m.httpLns
	httpSrvs := m.httpSrvs
	tlsLns := m.tlsLns
	tlsSrvs := m.tlsSrvs
	httpSess := m.httpSess
	m.discoveryLn = nil
	m.tcpLn = nil
	m.tlsTCPLn = nil
	m.httpLns = nil
	m.httpSrvs = nil
	m.tlsLns = nil
	m.tlsSrvs = nil
	m.httpSess = nil
	m.mu.Unlock()

	if discoveryLn != nil {
		_ = discoveryLn.Close()
	}
	if tcpLn != nil {
		_ = tcpLn.Close()
	}
	if tlsTCPLn != nil {
		_ = tlsTCPLn.Close()
	}
	for _, ln := range httpLns {
		_ = ln.Close()
	}
	for _, ln := range tlsLns {
		_ = ln.Close()
	}
	for _, srv := range httpSrvs {
		_ = srv.Shutdown(ctx)
	}
	for _, srv := range tlsSrvs {
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
			continue // BUG FIX: was 'return' — caused the loop to stop on any transient error
		}
		go func(c net.Conn) {
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = writeAll(c, resp)
			_ = c.Close()
		}(nc)
	}
}

// serveTCP accepts raw TCP connections and sends the 25-byte discovery header
// immediately before handing each connection to the relay server.
//
// Sending the discovery payload upfront lets clients connect to the TCP relay
// port for "Fetch server options" without requiring a separate discovery port.
// Discovery clients (server_discovery.dart) read the 25 bytes and close.
// Relay clients (TcpSgtpTransport) read and discard those 25 bytes and then
// proceed with the normal SGTP relay handshake.
func (m *MultiServer) serveTCP(ctx context.Context, ln net.Listener, discoveryResp []byte) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			m.Logger.Printf("[tcp] accept error: %v", err)
			continue // BUG FIX: was 'return' — stopped accepting on transient errors
		}
		go func(c net.Conn) {
			// Send discovery bytes first so clients can detect transport options
			// without a dedicated discovery port.
			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := writeAll(c, discoveryResp); err != nil {
				m.Logger.Printf("[tcp] write discovery header: %v", err)
				_ = c.Close()
				return
			}
			_ = c.SetWriteDeadline(time.Time{})
			m.Relay.ServeConn(ctx, c)
		}(nc)
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
