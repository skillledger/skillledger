// Package main implements the skillledger-log transparency log personality binary.
// It embeds Tessera v1.0.2 with POSIX filesystem storage and serves HTTP endpoints
// for adding entries and reading tiles/checkpoints.
package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/mod/sumdb/note"

	"github.com/skillledger/skillledger-log/internal/personality"
)

func main() {
	// Configure structured logging with human-readable console output.
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Read configuration from environment variables.
	privateKey := os.Getenv("LOG_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatal().Msg("LOG_PRIVATE_KEY environment variable is required")
	}

	storageDir := os.Getenv("STORAGE_DIR")
	if storageDir == "" {
		storageDir = "/data/tlog"
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":2025"
	}

	authKey := os.Getenv("LOG_AUTH_KEY")

	// Create the note signer for checkpoint signing (Ed25519).
	signer, err := note.NewSigner(privateKey)
	if err != nil {
		log.Fatal().Err(err).Msg("creating note signer from LOG_PRIVATE_KEY")
	}

	// Create the personality with Tessera appender and POSIX storage.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, err := personality.New(ctx, signer, personality.WithStoragePath(storageDir))
	if err != nil {
		log.Fatal().Err(err).Str("storage", storageDir).Msg("creating personality")
	}

	// Set up HTTP routes.
	mux := http.NewServeMux()

	// POST /add -- accepts LogEntry JSON, validates, adds to Tessera log, returns index.
	addHandler := http.HandlerFunc(p.HandleAdd)
	if authKey != "" {
		mux.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(authKey)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			addHandler.ServeHTTP(w, r)
		})
	} else {
		log.Warn().Msg("LOG_AUTH_KEY not set -- /add endpoint is unauthenticated")
		mux.HandleFunc("POST /add", p.HandleAdd)
	}

	// GET /checkpoint, /tile/*, /entries/* -- serve Tessera's tile data as static files.
	// Tessera writes tiles, checkpoints, and entry bundles to the storage directory.
	fs := http.FileServer(http.Dir(p.StoragePath()))
	mux.Handle("GET /checkpoint", fs)
	mux.Handle("GET /tile/", fs)
	mux.Handle("GET /entries/", fs)

	// Create HTTP server with timeouts.
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine.
	go func() {
		log.Info().
			Str("addr", listenAddr).
			Str("storage", storageDir).
			Str("signer", signer.Name()).
			Msg("skillledger-log starting")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for SIGINT or SIGTERM for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Info().Str("signal", sig.String()).Msg("shutting down")

	// Graceful shutdown: stop accepting new requests, then shut down Tessera.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown error")
	}

	if err := p.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Tessera personality shutdown error")
	}

	// Cancel the root context to stop background goroutines.
	cancel()

	fmt.Fprintln(os.Stderr, "skillledger-log stopped")
}
