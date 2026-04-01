// Command sgtp-server runs the SGTP relay server.
//
// When PG_DSN is set the server also embeds the userdir handler on the same
// port: connections whose first 32 bytes are all zero are transparently routed
// to the userdir protocol instead of the relay.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

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

	// If DISCOVERY_PORT is set, run in multi-transport mode. Otherwise keep the
	// legacy behavior (single raw TCP listener on SERVER_ADDR/SERVER_PORT).
	discoveryPort, err := portFromEnvAllowZero("DISCOVERY_PORT", 0)
	if err != nil {
		log.Fatalf("[server] invalid env: %v", err)
	}

	// ── Optional userdir (enabled when PG_DSN is set) ────────────────────────
	var ud *userdir.Server
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
	}

	if discoveryPort == 0 {
		addr, err := listenAddrFromEnv()
		if err != nil {
			log.Fatalf("[server] invalid env: %v", err)
		}
		srv := server.New(addr, logger, ud)

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

	ports, err := multiPortsFromEnv()
	if err != nil {
		logger.Fatalf("[server] invalid env: %v", err)
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
	ms := &mtransport.MultiServer{
		Logger:           logger,
		Relay:            relay,
		BindHost:         os.Getenv("BIND_HOST"),
		DiscoveryPort:    discoveryPort,
		Ports:            ports,
		HTTPRecvTimeout:  httpRecvTimeout,
		HTTPSendMax:      httpSendMax,
		HTTPBufferBytes:  httpBuf,
		HTTPSessionTTL:   httpTTL,
		HTTPCleanupEvery: httpCleanup,
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

func durationFromEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	return time.ParseDuration(v)
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
