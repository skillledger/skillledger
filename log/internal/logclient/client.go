// Package logclient provides an HTTP-based client for querying and verifying
// the SkillLedger transparency log. It wraps Tessera's client library with
// convenience methods for checkpoint fetching, tile reading, entry submission,
// and proof verification.
package logclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// Client provides methods to interact with the SkillLedger transparency log
// personality over HTTP. It uses Tessera's HTTPFetcher for tile and checkpoint
// retrieval, ensuring compatibility with Tessera's proof building API.
type Client struct {
	logURL   string
	origin   string
	verifier note.Verifier
	http     *http.Client
	fetcher  *client.HTTPFetcher
	logger   zerolog.Logger
}

// Option configures a Client.
type Option func(*Client)

// WithLogURL sets the base URL of the log personality server.
// Default: "http://localhost:2025".
func WithLogURL(u string) Option {
	return func(c *Client) { c.logURL = u }
}

// WithHTTPClient sets the HTTP client used for requests.
// Default: http.DefaultClient.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithOrigin sets the expected log origin string for checkpoint verification.
// This must match the origin used by the log personality's signer.
func WithOrigin(origin string) Option {
	return func(c *Client) { c.origin = origin }
}

// WithLogger sets the zerolog logger for debug output.
func WithLogger(l zerolog.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// NewClient creates a new log client with the given checkpoint verifier and options.
// The verifier is used to validate checkpoint signatures (T-05-13: prevents fake log servers).
func NewClient(verifier note.Verifier, opts ...Option) (*Client, error) {
	c := &Client{
		logURL:   "http://localhost:2025",
		origin:   "",
		verifier: verifier,
		http:     http.DefaultClient,
		logger:   log.With().Str("component", "logclient").Logger(),
	}
	for _, opt := range opts {
		opt(c)
	}

	// If origin is not set, derive from verifier name.
	if c.origin == "" {
		c.origin = c.verifier.Name()
	}

	// Create Tessera HTTPFetcher for tile/checkpoint retrieval.
	u, err := url.Parse(c.logURL)
	if err != nil {
		return nil, fmt.Errorf("parsing log URL %q: %w", c.logURL, err)
	}
	fetcher, err := client.NewHTTPFetcher(u, c.http)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP fetcher: %w", err)
	}
	c.fetcher = fetcher

	return c, nil
}

// FetchCheckpoint retrieves the raw checkpoint bytes from the log server.
// The checkpoint is a signed note containing the log's tree head (origin, size, root hash).
func (c *Client) FetchCheckpoint(ctx context.Context) ([]byte, error) {
	c.logger.Debug().Str("url", c.logURL).Msg("fetching checkpoint")
	return c.fetcher.ReadCheckpoint(ctx)
}

// TileFetcher returns a function compatible with Tessera's TileFetcherFunc type.
// This is used by Tessera's ProofBuilder and LogStateTracker for building proofs.
func (c *Client) TileFetcher() client.TileFetcherFunc {
	return c.fetcher.ReadTile
}

// CheckpointFetcher returns a function compatible with Tessera's CheckpointFetcherFunc type.
// This is used by Tessera's LogStateTracker for tracking log state.
func (c *Client) CheckpointFetcher() client.CheckpointFetcherFunc {
	return c.fetcher.ReadCheckpoint
}

// Verifier returns the note.Verifier used for checkpoint signature verification.
func (c *Client) Verifier() note.Verifier {
	return c.verifier
}

// Origin returns the expected log origin string.
func (c *Client) Origin() string {
	return c.origin
}

// AddEntry submits a new entry (JSON-encoded LogEntry) to the log personality.
// Returns the log index assigned to the entry.
// Returns an error containing "busy" or "retry" if the log returns 503 (backpressure).
func (c *Client) AddEntry(ctx context.Context, entryJSON []byte) (uint64, error) {
	reqURL := strings.TrimRight(c.logURL, "/") + "/add"
	c.logger.Debug().Str("url", reqURL).Int("body_len", len(entryJSON)).Msg("adding entry")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(entryJSON)))
	if err != nil {
		return 0, fmt.Errorf("creating add request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("sending add request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading add response: %w", err)
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		return 0, fmt.Errorf("log busy, retry later (503): %s", string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("add entry failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	idx, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing index from response %q: %w", string(body), err)
	}

	c.logger.Debug().Uint64("index", idx).Msg("entry added")
	return idx, nil
}
