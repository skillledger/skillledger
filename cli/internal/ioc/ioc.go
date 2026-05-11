package ioc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/scanner"
	"github.com/skillledger/skillledger/internal/threatsync"
)

// Entry represents a known-compromised artifact in the IOC database.
type Entry struct {
	SHA256      string `json:"sha256"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	ReportedAt  string `json:"reported_at"`
}

// DomainEntry represents a known-malicious domain in the IOC database.
type DomainEntry struct {
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	ReportedAt  string `json:"reported_at"`
}

// Database stores IOC entries keyed by SHA-256 hash and domain IOC entries.
type Database struct {
	entries       map[string]Entry
	domainEntries []DomainEntry
}

// Load creates a Database from the bundled IOC data (go:embed).
func Load() (*Database, error) {
	var entries []Entry
	if err := json.Unmarshal(bundledIOCData, &entries); err != nil {
		return nil, fmt.Errorf("parsing bundled IOC data: %w", err)
	}
	db := &Database{entries: make(map[string]Entry, len(entries))}
	for _, e := range entries {
		db.entries[strings.ToLower(e.SHA256)] = e
	}

	// Load bundled domain IOC data (supplementary; warn but don't fail).
	var domainEntries []DomainEntry
	if err := json.Unmarshal(bundledDomainData, &domainEntries); err != nil {
		log.Warn().Err(err).Msg("parsing bundled domain IOC data")
	} else {
		db.domainEntries = domainEntries
	}

	return db, nil
}

// NewDatabase creates an empty Database. Useful for testing.
func NewDatabase() *Database {
	return &Database{entries: make(map[string]Entry)}
}

// AddEntry adds an IOC entry to the database.
func (d *Database) AddEntry(e Entry) {
	d.entries[strings.ToLower(e.SHA256)] = e
}

// AddDomainEntry adds a domain IOC entry to the database.
func (d *Database) AddDomainEntry(e DomainEntry) {
	d.domainEntries = append(d.domainEntries, e)
}

// MatchDomain checks if a hostname matches any domain IOC entry using suffix
// matching with dot boundary. For example, IOC "evil.com" matches "evil.com"
// and "sub.evil.com" but not "notevil.com".
func (d *Database) MatchDomain(hostname string) (*DomainEntry, bool) {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, entry := range d.domainEntries {
		domain := strings.ToLower(entry.Domain)
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return &entry, true
		}
	}
	return nil, false
}

// DomainCount returns the number of domain IOC entries in the database.
func (d *Database) DomainCount() int {
	return len(d.domainEntries)
}

// Match checks if a SHA-256 hash is in the IOC database.
// Returns the IOCMatchInfo (compatible with scanner.IOCChecker) and whether a match was found.
func (d *Database) Match(sha256 string) (*scanner.IOCMatchInfo, bool) {
	e, ok := d.entries[strings.ToLower(sha256)]
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
	allowedHosts := []string{"api.skillledger.in"}
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

	return d.fetchAndMerge(apiURL, &http.Client{Timeout: 5 * time.Second})
}

// FetchUpdatesWithClient is like FetchUpdates but uses the provided HTTP client
// and skips URL validation. Intended for testing with httptest.NewTLSServer.
func (d *Database) FetchUpdatesWithClient(apiURL string, client *http.Client) error {
	return d.fetchAndMerge(apiURL, client)
}

// updateResponse supports both hash and domain IOC entries from the API.
type updateResponse struct {
	Hashes  []Entry       `json:"hashes,omitempty"`
	Domains []DomainEntry `json:"domains,omitempty"`
}

func (d *Database) fetchAndMerge(apiURL string, client *http.Client) error {
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
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("reading IOC response: %w", err)
	}

	// Try new object format with hashes + domains fields first.
	var update updateResponse
	if err := json.Unmarshal(body, &update); err == nil && (len(update.Hashes) > 0 || len(update.Domains) > 0) {
		for _, e := range update.Hashes {
			d.entries[strings.ToLower(e.SHA256)] = e
		}
		d.domainEntries = append(d.domainEntries, update.Domains...)
		return nil
	}

	// Backward compat: plain []Entry array (hash-only).
	var entries []Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Errorf("parsing IOC response: %w", err)
	}
	for _, e := range entries {
		d.entries[strings.ToLower(e.SHA256)] = e
	}
	return nil
}

// LoadWithCache loads the IOC database preferring cached data when the cache
// is newer than buildTime (D-06). Falls back to bundled data when:
//   - cacheDir is empty
//   - metadata.json is missing or unparseable
//   - cache is older than build time (bundled is fresher)
//   - cache file is missing or corrupt (D-07: deletes corrupt file)
func LoadWithCache(cacheDir string, buildTime time.Time) (*Database, error) {
	if cacheDir == "" {
		return Load()
	}

	meta, err := threatsync.LoadMetadata(cacheDir)
	if err != nil {
		log.Debug().Err(err).Msg("ioc: no cache metadata, using bundled data")
		return Load()
	}

	// D-06: only use cache if it's newer than build time.
	if !meta.FetchedAt.After(buildTime) {
		log.Debug().
			Time("fetched_at", meta.FetchedAt).
			Time("build_time", buildTime).
			Msg("ioc: cache older than build, using bundled data")
		return Load()
	}

	// Attempt to read cached IOC data.
	cachePath := filepath.Join(cacheDir, "ioc.json")
	data, err := os.ReadFile(cachePath)
	if err != nil {
		log.Debug().Err(err).Msg("ioc: cache file missing, using bundled data")
		return Load()
	}

	// Parse as updateResponse (API response format with hashes + domains).
	var resp updateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		// D-07: corrupt cache -- delete and fall back to bundled.
		log.Warn().Err(err).Str("path", cachePath).Msg("ioc: corrupt cache file, deleting")
		os.Remove(cachePath)
		return Load()
	}

	// Build Database from cached response.
	db := &Database{entries: make(map[string]Entry, len(resp.Hashes))}
	for _, e := range resp.Hashes {
		db.entries[strings.ToLower(e.SHA256)] = e
	}
	db.domainEntries = resp.Domains

	log.Debug().
		Int("hashes", len(resp.Hashes)).
		Int("domains", len(resp.Domains)).
		Msg("ioc: loaded from cache")
	return db, nil
}

// Count returns the number of IOC entries in the database.
func (d *Database) Count() int {
	return len(d.entries)
}
