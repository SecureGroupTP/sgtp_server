// Command sgtp-server runs the SGTP relay server.
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

	"github.com/SecureGroupTP/sgtp_server/server"
)

func main() {
	addr, err := listenAddrFromEnv()
	if err != nil {
		log.Fatalf("[server] invalid env: %v", err)
	}
	shutdownTimeout, err := durationFromEnv("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		log.Fatalf("[server] invalid env: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	srv := server.New(addr, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

func durationFromEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	return time.ParseDuration(v)
}
