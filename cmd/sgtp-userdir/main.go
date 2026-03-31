// Command sgtp-userdir runs the SGTP user directory server (TCP).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/SecureGroupTP/sgtp_server/userdir"
)

func main() {
	addr := ":" + getenv("SERVER_PORT", "7070")
	if _, err := strconv.Atoi(getenv("SERVER_PORT", "7070")); err != nil {
		log.Fatalf("[userdir] invalid SERVER_PORT: %v", err)
	}

	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		log.Fatalf("[userdir] PG_DSN is required")
	}

	ttl, err := time.ParseDuration(getenv("PROFILE_TTL", "24h"))
	if err != nil {
		log.Fatalf("[userdir] invalid PROFILE_TTL: %v", err)
	}
	avatarMax, err := strconv.ParseUint(getenv("AVATAR_MAX_BYTES", "33554432"), 10, 32)
	if err != nil {
		log.Fatalf("[userdir] invalid AVATAR_MAX_BYTES: %v", err)
	}
	searchMax, err := strconv.ParseUint(getenv("SEARCH_MAX_RESULTS", "20"), 10, 16)
	if err != nil {
		log.Fatalf("[userdir] invalid SEARCH_MAX_RESULTS: %v", err)
	}
	cleanupEvery, err := time.ParseDuration(getenv("CLEANUP_INTERVAL", "5m"))
	if err != nil {
		log.Fatalf("[userdir] invalid CLEANUP_INTERVAL: %v", err)
	}
	shutdownTimeout, err := time.ParseDuration(getenv("SHUTDOWN_TIMEOUT", "10s"))
	if err != nil {
		log.Fatalf("[userdir] invalid SHUTDOWN_TIMEOUT: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := userdir.OpenStore(ctx, dsn, ttl)
	if err != nil {
		logger.Fatalf("[userdir] open store: %v", err)
	}
	defer store.Close()

	srv, err := userdir.NewServer(userdir.Config{
		Addr:           addr,
		Logger:         logger,
		Store:          store,
		AvatarMaxBytes: uint32(avatarMax),
		SearchMax:      uint16(searchMax),
		CleanupEvery:   cleanupEvery,
	})
	if err != nil {
		logger.Fatalf("[userdir] init server: %v", err)
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if err := srv.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		logger.Fatalf("[userdir] exited with error: %v", err)
	}
	logger.Printf("[userdir] stopped")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
