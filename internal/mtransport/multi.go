package mtransport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	// Ports are local listen ports.
	Ports Ports
	// DiscoveryPorts, when non-nil, are advertised in discovery payloads instead
	// of local listen Ports. Useful behind reverse-proxy/NAT.
	DiscoveryPorts *Ports

	HTTPRecvTimeout  time.Duration
	HTTPSendMax      int64
	HTTPBufferBytes  int
	HTTPSessionTTL   time.Duration
	HTTPCleanupEvery time.Duration

	mu       sync.Mutex
	tcpLn    net.Listener
	tlsTCPLn net.Listener
	httpLns  map[uint16]net.Listener
	httpSrvs map[uint16]*http.Server
	tlsLns   map[uint16]net.Listener
	tlsSrvs  map[uint16]*http.Server
	httpSess *HTTPSessionManager
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

	// Pre-compute the 25-byte discovery payload once; it is used for both the
	// TCP relay handshake and the HTTP discovery responses so clients can fetch
	// transport options without a separate discovery port.
	discoveryPorts := m.Ports
	if m.DiscoveryPorts != nil {
		discoveryPorts = *m.DiscoveryPorts
	}
	discoveryResp := discoveryPorts.DiscoveryResponse()
	discoveryPayload := make([]byte, len(discoveryResp))
	copy(discoveryPayload, discoveryResp[:])
	discoveryHandler := newHTTPDiscoveryHandler(discoveryPayload, discoveryPorts)
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
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
	if m.Ports.TCPTLS != 0 {
		ln, err := tls.Listen("tcp", m.listenAddr(m.Ports.TCPTLS), m.TLSConfig)
		if err != nil {
			return fmt.Errorf("tcp tls listen: %w", err)
		}
		m.tlsTCPLn = ln
		m.Logger.Printf("[tcp tls] listening on %s", ln.Addr().String())
		go m.serveTCP(ctx, ln, discoveryResp[:])
	}

	// ── HTTP / WS (plain + TLS) ──────────────────────────────────────────────
	newMux := func() *http.ServeMux {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", healthHandler)
		mux.HandleFunc("GET /sgtp/discovery", discoveryHandler.ServeHTTP)
		mux.HandleFunc("HEAD /sgtp/discovery", discoveryHandler.ServeHTTP)
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
	tcpLn := m.tcpLn
	tlsTCPLn := m.tlsTCPLn
	httpLns := m.httpLns
	httpSrvs := m.httpSrvs
	tlsLns := m.tlsLns
	tlsSrvs := m.tlsSrvs
	httpSess := m.httpSess
	m.tcpLn = nil
	m.tlsTCPLn = nil
	m.httpLns = nil
	m.httpSrvs = nil
	m.tlsLns = nil
	m.tlsSrvs = nil
	m.httpSess = nil
	m.mu.Unlock()

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

type httpDiscoveryHandler struct {
	resp          []byte
	ports         Ports
	flags         int
	payloadHex    string
	payloadBase64 string
}

func newHTTPDiscoveryHandler(resp []byte, ports Ports) *httpDiscoveryHandler {
	dup := make([]byte, len(resp))
	copy(dup, resp)
	return &httpDiscoveryHandler{
		resp:          dup,
		ports:         ports,
		flags:         int(resp[0]),
		payloadHex:    hex.EncodeToString(resp),
		payloadBase64: base64.StdEncoding.EncodeToString(resp),
	}
}

func (h *httpDiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "raw" || format == "binary" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(h.resp)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}

	_ = json.NewEncoder(w).Encode(h.makePayload())
}

func (h *httpDiscoveryHandler) makePayload() discoveryResponseJSON {
	return discoveryResponseJSON{
		Flags: h.flags,
		Ports: discoveryPortsJSON{
			TCP:     h.ports.TCP,
			TCPTLS:  h.ports.TCPTLS,
			HTTP:    h.ports.HTTP,
			HTTPTLS: h.ports.HTTPTLS,
			WS:      h.ports.WS,
			WSTLS:   h.ports.WSTLS,
		},
		Enabled: discoveryEnabledJSON{
			TCP:     h.ports.TCP != 0,
			TCPTLS:  h.ports.TCPTLS != 0,
			HTTP:    h.ports.HTTP != 0,
			HTTPTLS: h.ports.HTTPTLS != 0,
			WS:      h.ports.WS != 0,
			WSTLS:   h.ports.WSTLS != 0,
		},
		Payload: discoveryPayloadJSON{
			Base64: h.payloadBase64,
			Hex:    h.payloadHex,
		},
	}
}

type discoveryResponseJSON struct {
	Flags   int                  `json:"flags"`
	Ports   discoveryPortsJSON   `json:"ports"`
	Enabled discoveryEnabledJSON `json:"enabled"`
	Payload discoveryPayloadJSON `json:"payload"`
}

type discoveryPortsJSON struct {
	TCP     uint16 `json:"tcp"`
	TCPTLS  uint16 `json:"tcp_tls"`
	HTTP    uint16 `json:"http"`
	HTTPTLS uint16 `json:"http_tls"`
	WS      uint16 `json:"ws"`
	WSTLS   uint16 `json:"ws_tls"`
}

type discoveryEnabledJSON struct {
	TCP     bool `json:"tcp"`
	TCPTLS  bool `json:"tcp_tls"`
	HTTP    bool `json:"http"`
	HTTPTLS bool `json:"http_tls"`
	WS      bool `json:"ws"`
	WSTLS   bool `json:"ws_tls"`
}

type discoveryPayloadJSON struct {
	Base64 string `json:"base64"`
	Hex    string `json:"hex"`
}
