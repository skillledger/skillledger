package ioc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/skillledger/skillledger/internal/scanner"
)

// Entry represents a known-compromised artifact in the IOC database.
type Entry struct {
	SHA256      string `json:"sha256"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	ReportedAt  string `json:"reported_at"`
}

// Database stores IOC entries keyed by SHA-256 hash.
type Database struct {
	entries map[string]Entry
}

// Load creates a Database from the bundled IOC data (go:embed).
func Load() (*Database, error) {
	var entries []Entry
	if err := json.Unmarshal(bundledIOCData, &entries); err != nil {
		return nil, fmt.Errorf("parsing bundled IOC data: %w", err)
	}
	db := &Database{entries: make(map[string]Entry, len(entries))}
	for _, e := range entries {
		db.entries[e.SHA256] = e
	}
	return db, nil
}

// NewDatabase creates an empty Database. Useful for testing.
func NewDatabase() *Database {
	return &Database{entries: make(map[string]Entry)}
}

// AddEntry adds an IOC entry to the database.
func (d *Database) AddEntry(e Entry) {
	d.entries[e.SHA256] = e
}

// Match checks if a SHA-256 hash is in the IOC database.
// Returns the IOCMatchInfo (compatible with scanner.IOCChecker) and whether a match was found.
func (d *Database) Match(sha256 string) (*scanner.IOCMatchInfo, bool) {
	e, ok := d.entries[sha256]
	if !ok {
		return nil, false
	}
	return &scanner.IOCMatchInfo{
		SHA256:      e.SHA256,
		Description: e.Description,
		Severity:    e.Severity,
	}, true
}

// FetchUpdates fetches IOC data from apiURL and merges into the database.
// Timeout: 5 seconds. Response body capped at 1MB.
// Security: validates URL scheme (HTTPS only) and host against allowlist (CR-01).
func (d *Database) FetchUpdates(apiURL string) error {
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid IOC API URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("IOC API URL must use HTTPS, got %q", parsed.Scheme)
	}
	allowedHosts := []string{"api.skillledger.dev"}
	hostAllowed := false
	for _, h := range allowedHosts {
		if parsed.Hostname() == h {
			hostAllowed = true
			break
		}
	}
	if !hostAllowed {
		return fmt.Errorf("IOC API host %q not in allowlist", parsed.Hostname())
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("fetching IOC updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IOC API returned status %d", resp.StatusCode)
	}

	// Security: cap response body at 1MB (T-02-04)
	limited := io.LimitReader(resp.Body, 1<<20)
	var entries []Entry
	if err := json.NewDecoder(limited).Decode(&entries); err != nil {
		return fmt.Errorf("parsing IOC response: %w", err)
	}

	// Merge: new entries overwrite existing by SHA-256
	for _, e := range entries {
		d.entries[e.SHA256] = e
	}
	return nil
}

// Count returns the number of IOC entries in the database.
func (d *Database) Count() int {
	return len(d.entries)
}
