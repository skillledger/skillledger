package personality

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

// Personality wraps a Tessera appender with HTTP handlers for the SkillLedger
// transparency log. It manages entry validation, serialization, and the
// add endpoint, while Tessera handles all Merkle tree operations.
type Personality struct {
	storagePath        string
	batchMaxSize       uint
	batchMaxAge        time.Duration
	checkpointInterval time.Duration
	pushbackMax        uint
	signer             note.Signer
	appender           *tessera.Appender
	shutdown           func(ctx context.Context) error
	logger             zerolog.Logger
}

// Option configures a Personality.
type Option func(*Personality)

// WithStoragePath sets the POSIX filesystem path for Tessera storage.
// Default: "/data/tlog".
func WithStoragePath(path string) Option {
	return func(p *Personality) { p.storagePath = path }
}

// WithBatchSize sets the maximum number of entries per batch.
// Default: 256.
func WithBatchSize(size uint) Option {
	return func(p *Personality) { p.batchMaxSize = size }
}

// WithBatchMaxAge sets the maximum age of a batch before it is flushed.
// Default: 250ms.
func WithBatchMaxAge(d time.Duration) Option {
	return func(p *Personality) { p.batchMaxAge = d }
}

// WithCheckpointInterval sets how frequently checkpoints are published.
// Default: 10s.
func WithCheckpointInterval(d time.Duration) Option {
	return func(p *Personality) { p.checkpointInterval = d }
}

// WithPushbackMaxEntries sets the maximum number of outstanding (unintegrated)
// entries before the appender starts returning ErrPushback.
// Default: 4096.
func WithPushbackMaxEntries(n uint) Option {
	return func(p *Personality) { p.pushbackMax = n }
}

// New creates a Personality that embeds a Tessera appender with POSIX storage.
// The signer is used for checkpoint signing (Ed25519 via golang.org/x/mod/sumdb/note).
func New(ctx context.Context, signer note.Signer, opts ...Option) (*Personality, error) {
	p := &Personality{
		storagePath:        "/data/tlog",
		batchMaxSize:       256,
		batchMaxAge:        250 * time.Millisecond,
		checkpointInterval: 10 * time.Second,
		pushbackMax:        4096,
		signer:             signer,
		logger:             log.With().Str("component", "personality").Logger(),
	}
	for _, opt := range opts {
		opt(p)
	}

	// Create POSIX filesystem storage driver.
	driver, err := posix.New(ctx, posix.Config{Path: p.storagePath})
	if err != nil {
		return nil, fmt.Errorf("creating POSIX storage at %s: %w", p.storagePath, err)
	}

	// Configure appender options.
	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithBatching(p.batchMaxSize, p.batchMaxAge).
		WithCheckpointInterval(p.checkpointInterval).
		WithPushback(p.pushbackMax)

	// Create the Tessera appender. Returns appender, shutdown func, log reader, error.
	appender, shutdown, _, err := tessera.NewAppender(ctx, driver, appendOpts)
	if err != nil {
		return nil, fmt.Errorf("creating Tessera appender: %w", err)
	}

	p.appender = appender
	p.shutdown = shutdown

	return p, nil
}

// HandleAdd processes POST /add requests. It reads the request body as a JSON
// LogEntry, validates it, serializes it, and adds it to the Tessera log.
//
// Returns:
//   - 200 with the log index as the response body on success
//   - 400 if the request body is invalid JSON or fails validation
//   - 503 with Retry-After header if the appender is under backpressure
//   - 500 for other internal errors
func (p *Personality) HandleAdd(w http.ResponseWriter, r *http.Request) {
	const maxEntrySize = 16 * 1024 // 16 KB -- entries are small JSON
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEntrySize+1))
	if err != nil {
		p.logger.Error().Err(err).Msg("reading request body")
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxEntrySize {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var entry LogEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		p.logger.Warn().Err(err).Msg("invalid JSON in request body")
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// T-05-02: Validate entry format before adding to log.
	if err := ValidateEntry(&entry); err != nil {
		p.logger.Warn().Err(err).Str("artifact_id", entry.ArtifactID).Msg("entry validation failed")
		http.Error(w, fmt.Sprintf("validation error: %v", err), http.StatusBadRequest)
		return
	}

	// Serialize entry to deterministic JSON for the Merkle leaf.
	entryBytes, err := SerializeEntry(&entry)
	if err != nil {
		p.logger.Error().Err(err).Msg("serializing entry")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Add entry to the Tessera log. This returns a future.
	future := p.appender.Add(r.Context(), tessera.NewEntry(entryBytes))
	idx, err := future()
	if err != nil {
		// T-05-03: Handle backpressure by returning 503 with Retry-After.
		if errors.Is(err, tessera.ErrPushback) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "log is busy, retry later", http.StatusServiceUnavailable)
			return
		}
		p.logger.Error().Err(err).Msg("adding entry to log")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	p.logger.Info().
		Uint64("index", idx.Index).
		Bool("is_dup", idx.IsDup).
		Str("artifact_id", entry.ArtifactID).
		Msg("entry added to log")

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", idx.Index)
}

// Shutdown gracefully shuts down the Tessera appender, ensuring all pending
// entries are integrated and a final checkpoint is published.
func (p *Personality) Shutdown(ctx context.Context) error {
	if p.shutdown != nil {
		return p.shutdown(ctx)
	}
	return nil
}

// StoragePath returns the POSIX filesystem path used for Tessera storage.
// This is useful for setting up a file server to serve tiles and checkpoints.
func (p *Personality) StoragePath() string {
	return p.storagePath
}
