// Command sgtp-server runs the SGTP relay server.
//
// When PG_DSN is set the server also embeds the userdir handler on the same
// port: connections whose first 32 bytes are all zero are transparently routed
// to the userdir protocol instead of the relay.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/SecureGroupTP/sgtp_server/internal/admin"
	"github.com/SecureGroupTP/sgtp_server/internal/mtransport"
	"github.com/SecureGroupTP/sgtp_server/server"
	"github.com/SecureGroupTP/sgtp_server/userdir"
)

func main() {
	shutdownTimeout, err := durationFromEnv("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		log.Fatalf("[server] invalid env: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ── Optional userdir (enabled when PG_DSN is set) ────────────────────────
	var ud *userdir.Server
	var adminSvc *admin.Service
	if dsn := os.Getenv("PG_DSN"); dsn != "" {
		avatarMax, err := uint32FromEnv("AVATAR_MAX_BYTES", 33554432)
		if err != nil {
			logger.Fatalf("[server] invalid AVATAR_MAX_BYTES: %v", err)
		}
		searchMax, err := uint16FromEnv("SEARCH_MAX_RESULTS", 20)
		if err != nil {
			logger.Fatalf("[server] invalid SEARCH_MAX_RESULTS: %v", err)
		}
		cleanupEvery, err := durationFromEnv("CLEANUP_INTERVAL", 5*time.Minute)
		if err != nil {
			logger.Fatalf("[server] invalid CLEANUP_INTERVAL: %v", err)
		}

		subscribeMax, err := int64FromEnv("SUBSCRIBE_MAX", 500)
		if err != nil {
			logger.Fatalf("[server] invalid SUBSCRIBE_MAX: %v", err)
		}

		store, err := userdir.OpenStore(ctx, dsn)
		if err != nil {
			logger.Fatalf("[server] userdir open store: %v", err)
		}
		defer store.Close()

		ud, err = userdir.NewServer(userdir.Config{
			Logger:         logger,
			Store:          store,
			AvatarMaxBytes: avatarMax,
			SearchMax:      searchMax,
			SubscribeMax:   int(subscribeMax),
			CleanupEvery:   cleanupEvery,
		})
		if err != nil {
			logger.Fatalf("[server] userdir init: %v", err)
		}
		// Run the userdir cleanup loop only (no separate TCP listener).
		go func() {
			_ = ud.RunCleanupLoop(ctx)
		}()

		logger.Printf("[server] userdir enabled (inline mux on same port)")

		adminStore, err := admin.OpenStore(ctx, dsn)
		if err != nil {
			logger.Fatalf("[server] admin open store: %v", err)
		}
		defer adminStore.Close()

		accessTTL, err := durationFromEnv("ADMIN_ACCESS_TTL", 15*time.Minute)
		if err != nil {
			logger.Fatalf("[server] invalid ADMIN_ACCESS_TTL: %v", err)
		}
		refreshTTL, err := durationFromEnv("ADMIN_REFRESH_TTL", 7*24*time.Hour)
		if err != nil {
			logger.Fatalf("[server] invalid ADMIN_REFRESH_TTL: %v", err)
		}
		adminSvc, err = admin.NewService(admin.Config{
			Store:            adminStore,
			Logger:           logger,
			JWTSecret:        []byte(os.Getenv("ADMIN_JWT_SECRET")),
			AccessTTL:        accessTTL,
			RefreshTTL:       refreshTTL,
			BootstrapOutFile: os.Getenv("ADMIN_BOOTSTRAP_FILE"),
			PGDSN:            dsn,
		})
		if err != nil {
			logger.Fatalf("[server] admin init: %v", err)
		}
		if err := adminSvc.EnsureBootstrapRoot(ctx); err != nil {
			logger.Fatalf("[server] admin bootstrap: %v", err)
		}
		go adminSvc.RunMaintenanceLoop(ctx, 1*time.Hour)
		logger.Printf("[server] admin control plane enabled")
	}

	ports, err := multiPortsFromEnv()
	if err != nil {
		logger.Fatalf("[server] invalid env: %v", err)
	}
	discoveryPorts, err := discoveryPortsFromEnv(ports)
	if err != nil {
		logger.Fatalf("[server] invalid env: %v", err)
	}
	useMulti := ports.AnyEnabled()

	if !useMulti {
		addr, err := listenAddrFromEnv()
		if err != nil {
			log.Fatalf("[server] invalid env: %v", err)
		}
		srv := server.New(addr, logger, ud)
		if adminSvc != nil {
			srv.SetPolicyEngine(adminSvc)
		}

		go func() {
			<-ctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()

		if err := srv.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
			logger.Fatalf("[server] exited with error: %v", err)
		}
		logger.Printf("[server] stopped")
		return
	}

	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	tlsConfig, err := newTLSConfig(tlsCertFile, tlsKeyFile)
	if err != nil {
		logger.Fatalf("[server] invalid TLS config: %v", err)
	}
	if tlsConfig != nil {
		logger.Printf("[server] TLS enabled (cert=%s key=%s)", tlsCertFile, tlsKeyFile)
	}

	httpRecvTimeout, err := durationFromEnv("HTTP_RECV_TIMEOUT", 60*time.Second)
	if err != nil {
		logger.Fatalf("[server] invalid HTTP_RECV_TIMEOUT: %v", err)
	}
	httpSendMax, err := int64FromEnv("HTTP_SEND_MAX_BYTES", 16<<20)
	if err != nil {
		logger.Fatalf("[server] invalid HTTP_SEND_MAX_BYTES: %v", err)
	}
	httpBuf, err := intFromEnv("HTTP_SESSION_BUFFER_BYTES", 4<<20)
	if err != nil {
		logger.Fatalf("[server] invalid HTTP_SESSION_BUFFER_BYTES: %v", err)
	}
	httpTTL, err := durationFromEnv("HTTP_SESSION_TTL", 10*time.Minute)
	if err != nil {
		logger.Fatalf("[server] invalid HTTP_SESSION_TTL: %v", err)
	}
	httpCleanup, err := durationFromEnv("HTTP_SESSION_CLEANUP", 1*time.Minute)
	if err != nil {
		logger.Fatalf("[server] invalid HTTP_SESSION_CLEANUP: %v", err)
	}

	relay := server.New("", logger, ud)
	if adminSvc != nil {
		relay.SetPolicyEngine(adminSvc)
	}
	ms := &mtransport.MultiServer{
		Logger:           logger,
		Relay:            relay,
		BindHost:         os.Getenv("BIND_HOST"),
		TLSConfig:        tlsConfig,
		Ports:            ports,
		DiscoveryPorts:   &discoveryPorts,
		HTTPRecvTimeout:  httpRecvTimeout,
		HTTPSendMax:      httpSendMax,
		HTTPBufferBytes:  httpBuf,
		HTTPSessionTTL:   httpTTL,
		HTTPCleanupEvery: httpCleanup,
	}
	if adminSvc != nil {
		adminHandler := admin.NewHTTPHandler(adminSvc)
		ms.ExtraRegistrars = append(ms.ExtraRegistrars, adminHandler.Register)
	}

	if err := ms.Start(ctx); err != nil {
		logger.Fatalf("[server] start: %v", err)
	}

	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = ms.Shutdown(sctx)
	_ = relay.Shutdown(sctx)
	logger.Printf("[server] stopped")
}

func listenAddrFromEnv() (string, error) {
	if v := os.Getenv("SERVER_ADDR"); v != "" {
		return v, nil
	}
	portStr := os.Getenv("SERVER_PORT")
	if portStr == "" {
		portStr = "7777"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("SERVER_PORT must be 1..65535, got %q", portStr)
	}
	return ":" + strconv.Itoa(port), nil
}

func multiPortsFromEnv() (mtransport.Ports, error) {
	// For convenience, TCP_PORT defaults to SERVER_PORT when unset.
	tcpPort, err := portFromEnvAllowZeroFallback("TCP_PORT", "SERVER_PORT", 7777)
	if err != nil {
		return mtransport.Ports{}, err
	}

	tcpTLSPort, err := portFromEnvAllowZero("TCP_TLS_PORT", 0)
	if err != nil {
		return mtransport.Ports{}, err
	}
	httpPort, err := portFromEnvAllowZero("HTTP_PORT", 0)
	if err != nil {
		return mtransport.Ports{}, err
	}
	httpTLSPort, err := portFromEnvAllowZero("HTTP_TLS_PORT", 0)
	if err != nil {
		return mtransport.Ports{}, err
	}
	wsPort, err := portFromEnvAllowZero("WS_PORT", 0)
	if err != nil {
		return mtransport.Ports{}, err
	}
	wsTLSPort, err := portFromEnvAllowZero("WS_TLS_PORT", 0)
	if err != nil {
		return mtransport.Ports{}, err
	}

	return mtransport.Ports{
		TCP:     tcpPort,
		TCPTLS:  tcpTLSPort,
		HTTP:    httpPort,
		HTTPTLS: httpTLSPort,
		WS:      wsPort,
		WSTLS:   wsTLSPort,
	}, nil
}

func discoveryPortsFromEnv(def mtransport.Ports) (mtransport.Ports, error) {
	out := def
	var err error

	if out.TCP, err = portOverrideFromEnv("ADVERTISE_TCP_PORT", out.TCP); err != nil {
		return mtransport.Ports{}, err
	}
	if out.TCPTLS, err = portOverrideFromEnv("ADVERTISE_TCP_TLS_PORT", out.TCPTLS); err != nil {
		return mtransport.Ports{}, err
	}
	if out.HTTP, err = portOverrideFromEnv("ADVERTISE_HTTP_PORT", out.HTTP); err != nil {
		return mtransport.Ports{}, err
	}
	if out.HTTPTLS, err = portOverrideFromEnv("ADVERTISE_HTTP_TLS_PORT", out.HTTPTLS); err != nil {
		return mtransport.Ports{}, err
	}
	if out.WS, err = portOverrideFromEnv("ADVERTISE_WS_PORT", out.WS); err != nil {
		return mtransport.Ports{}, err
	}
	if out.WSTLS, err = portOverrideFromEnv("ADVERTISE_WS_TLS_PORT", out.WSTLS); err != nil {
		return mtransport.Ports{}, err
	}

	return out, nil
}

func portOverrideFromEnv(key string, current uint16) (uint16, error) {
	v := os.Getenv(key)
	if v == "" {
		return current, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%s must be 0..65535, got %q", key, v)
	}
	return uint16(n), nil
}

func durationFromEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	return time.ParseDuration(v)
}

func newTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must both be set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func uint32FromEnv(key string, def uint32) (uint32, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return uint32(n), nil
}

func uint16FromEnv(key string, def uint16) (uint16, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return uint16(n), nil
}

func int64FromEnv(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func intFromEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func portFromEnvAllowZero(key string, def uint16) (uint16, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%s must be 0..65535, got %q", key, v)
	}
	return uint16(n), nil
}

func portFromEnvAllowZeroFallback(key, fallbackKey string, fallbackDef uint16) (uint16, error) {
	if v := os.Getenv(key); v != "" {
		return portFromEnvAllowZero(key, 0)
	}
	return portFromEnvAllowZero(fallbackKey, fallbackDef)
}
