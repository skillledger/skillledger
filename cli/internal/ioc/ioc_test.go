package ioc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/ioc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_BundledData(t *testing.T) {
	db, err := ioc.Load()
	require.NoError(t, err)
	assert.Equal(t, 0, db.Count(), "bundled seed data should be empty")
}

func TestMatch_Found(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddEntry(ioc.Entry{
		SHA256:      "abc123def456",
		Description: "Known malicious MCP server",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-04-01T00:00:00Z",
	})

	match, found := db.Match("abc123def456")
	require.True(t, found)
	assert.Equal(t, "abc123def456", match.SHA256)
	assert.Equal(t, "Known malicious MCP server", match.Description)
	assert.Equal(t, "critical", match.Severity)
}

func TestMatch_NotFound(t *testing.T) {
	db := ioc.NewDatabase()

	match, found := db.Match("unknown_hash")
	assert.False(t, found)
	assert.Nil(t, match)
}

func TestFetchUpdates_RejectsHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdates(ts.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestFetchUpdates_RejectsUnknownHost(t *testing.T) {
	db := ioc.NewDatabase()
	err := db.FetchUpdates("https://evil.example.com/ioc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestFetchUpdatesWithClient_Success(t *testing.T) {
	entries := []ioc.Entry{
		{
			SHA256:      "hash1",
			Description: "Malicious skill 1",
			Severity:    "critical",
			Source:      "test-feed",
			ReportedAt:  "2026-04-01T00:00:00Z",
		},
		{
			SHA256:      "hash2",
			Description: "Malicious skill 2",
			Severity:    "high",
			Source:      "test-feed",
			ReportedAt:  "2026-04-02T00:00:00Z",
		},
	}
	data, err := json.Marshal(entries)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err = db.FetchUpdatesWithClient(ts.URL, ts.Client())
	require.NoError(t, err)
	assert.Equal(t, 2, db.Count())

	match, found := db.Match("hash1")
	require.True(t, found)
	assert.Equal(t, "Malicious skill 1", match.Description)

	match, found = db.Match("hash2")
	require.True(t, found)
	assert.Equal(t, "Malicious skill 2", match.Description)
}

func TestFetchUpdatesWithClient_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	client := &http.Client{Timeout: 1 * time.Second}
	err := db.FetchUpdatesWithClient(ts.URL, client)
	assert.Error(t, err, "should timeout")
}

func TestFetchUpdatesWithClient_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdatesWithClient(ts.URL, ts.Client())
	assert.Error(t, err, "should fail on invalid JSON")
}

func TestFetchUpdatesWithClient_LargeResponse(t *testing.T) {
	// Create a response larger than 1MB
	largeBody := "[" + strings.Repeat(`{"sha256":"x","description":"d","severity":"s","source":"src","reported_at":"t"},`, 50000)
	largeBody = largeBody[:len(largeBody)-1] + "]" // remove trailing comma, close array

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdatesWithClient(ts.URL, ts.Client())
	// With 1MB limit, parsing a >1MB body should either error or only parse partial data
	// The LimitReader will truncate, causing a JSON decode error
	assert.Error(t, err, "should error when response exceeds 1MB limit")
}

func TestFetchUpdatesWithClient_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdatesWithClient(ts.URL, ts.Client())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

// --- Domain IOC tests ---

func TestMatchDomain_ExactMatch(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	match, found := db.MatchDomain("evil.com")
	require.True(t, found)
	assert.Equal(t, "evil.com", match.Domain)
	assert.Equal(t, "critical", match.Severity)
}

func TestMatchDomain_SubdomainMatch(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	match, found := db.MatchDomain("sub.evil.com")
	require.True(t, found)
	assert.Equal(t, "evil.com", match.Domain)
}

func TestMatchDomain_NoPartialMatch(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	_, found := db.MatchDomain("notevil.com")
	assert.False(t, found, "notevil.com should NOT match IOC evil.com")
}

func TestMatchDomain_CaseInsensitive(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	match, found := db.MatchDomain("Evil.COM")
	require.True(t, found)
	assert.Equal(t, "evil.com", match.Domain)
}

func TestMatchDomain_TrailingDot(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	match, found := db.MatchDomain("evil.com.")
	require.True(t, found)
	assert.Equal(t, "evil.com", match.Domain)
}

func TestMatchDomain_NotFound(t *testing.T) {
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "Test malicious domain",
		Severity:    "critical",
		Source:      "test",
		ReportedAt:  "2026-01-01",
	})

	_, found := db.MatchDomain("safe.example.com")
	assert.False(t, found)
}

func TestLoad_IncludesDomains(t *testing.T) {
	db, err := ioc.Load()
	require.NoError(t, err)
	assert.Greater(t, db.DomainCount(), 0, "bundled domain data should have entries")
}

func TestDomainCount(t *testing.T) {
	db := ioc.NewDatabase()
	assert.Equal(t, 0, db.DomainCount())

	db.AddDomainEntry(ioc.DomainEntry{Domain: "a.com"})
	db.AddDomainEntry(ioc.DomainEntry{Domain: "b.com"})
	db.AddDomainEntry(ioc.DomainEntry{Domain: "c.com"})
	assert.Equal(t, 3, db.DomainCount())
}

// --- LoadWithCache tests ---

// writeTestMetadata writes a metadata.json compatible with threatsync.LoadMetadata.
func writeTestMetadata(t *testing.T, dir string, fetchedAt time.Time) {
	t.Helper()
	meta := map[string]interface{}{
		"ioc_etag":   `"test-etag"`,
		"yara_etag":  `"test-yara"`,
		"fetched_at": fetchedAt.Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0600))
}

// writeTestIOCCache writes a valid IOC cache file in API response format.
func writeTestIOCCache(t *testing.T, dir string) {
	t.Helper()
	resp := map[string]interface{}{
		"hashes": []map[string]string{
			{"sha256": "cached-hash-1", "description": "cached entry", "severity": "high", "source": "cache-test", "reported_at": "2026-01-01"},
			{"sha256": "cached-hash-2", "description": "another cached", "severity": "medium", "source": "cache-test", "reported_at": "2026-01-01"},
		},
		"domains": []map[string]string{
			{"domain": "cached-evil.com", "description": "cached domain", "severity": "critical", "source": "cache-test", "reported_at": "2026-01-01"},
		},
	}
	data, err := json.Marshal(resp)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ioc.json"), data, 0600))
}

func TestLoadWithCache_CacheNewerThanBuild(t *testing.T) {
	dir := t.TempDir()
	buildTime := time.Now().Add(-1 * time.Hour) // Build was 1 hour ago

	writeTestMetadata(t, dir, time.Now()) // Cache fetched just now
	writeTestIOCCache(t, dir)

	db, err := ioc.LoadWithCache(dir, buildTime)
	require.NoError(t, err)

	// Should have loaded from cache (2 hashes, 1 domain)
	assert.Equal(t, 2, db.Count(), "should have 2 hash entries from cache")
	assert.Equal(t, 1, db.DomainCount(), "should have 1 domain entry from cache")

	// Verify specific cache entry exists
	_, found := db.Match("cached-hash-1")
	assert.True(t, found, "should find cached-hash-1")
}

func TestLoadWithCache_BundledNewer(t *testing.T) {
	dir := t.TempDir()
	buildTime := time.Now()                                                     // Build is now
	writeTestMetadata(t, dir, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) // Cache is old
	writeTestIOCCache(t, dir)

	db, err := ioc.LoadWithCache(dir, buildTime)
	require.NoError(t, err)

	// Should have loaded from bundled data, not cache
	_, found := db.Match("cached-hash-1")
	assert.False(t, found, "should NOT find cached-hash-1 when using bundled data")
}

func TestLoadWithCache_CorruptCache(t *testing.T) {
	dir := t.TempDir()
	buildTime := time.Now().Add(-1 * time.Hour)

	writeTestMetadata(t, dir, time.Now())

	// Write corrupt JSON to ioc.json
	cachePath := filepath.Join(dir, "ioc.json")
	require.NoError(t, os.WriteFile(cachePath, []byte(`{{{invalid json`), 0600))

	db, err := ioc.LoadWithCache(dir, buildTime)
	require.NoError(t, err)

	// Corrupt file should be deleted (D-07)
	_, statErr := os.Stat(cachePath)
	assert.True(t, os.IsNotExist(statErr), "corrupt cache file should be deleted")

	// Should have fallen back to bundled data
	_, found := db.Match("cached-hash-1")
	assert.False(t, found, "should NOT find cached-hash-1 when falling back to bundled")
}

func TestLoadWithCache_NoCacheDir(t *testing.T) {
	db, err := ioc.LoadWithCache("", time.Now())
	require.NoError(t, err)

	// Should load bundled data (Count may be 0 for empty seed, but no error)
	assert.NotNil(t, db)
}

func TestLoadWithCache_MissingCacheFiles(t *testing.T) {
	dir := t.TempDir()
	buildTime := time.Now().Add(-1 * time.Hour)

	// Write metadata but no ioc.json
	writeTestMetadata(t, dir, time.Now())

	db, err := ioc.LoadWithCache(dir, buildTime)
	require.NoError(t, err)

	// Should fall back to bundled data
	_, found := db.Match("cached-hash-1")
	assert.False(t, found, "should NOT find cached-hash-1")
}
