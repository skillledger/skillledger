package ioc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestFetchUpdates_Success(t *testing.T) {
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
	err = db.FetchUpdates(ts.URL)
	require.NoError(t, err)
	assert.Equal(t, 2, db.Count())

	match, found := db.Match("hash1")
	require.True(t, found)
	assert.Equal(t, "Malicious skill 1", match.Description)

	match, found = db.Match("hash2")
	require.True(t, found)
	assert.Equal(t, "Malicious skill 2", match.Description)
}

func TestFetchUpdates_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdates(ts.URL)
	assert.Error(t, err, "should timeout after 5 seconds")
}

func TestFetchUpdates_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdates(ts.URL)
	assert.Error(t, err, "should fail on invalid JSON")
}

func TestFetchUpdates_LargeResponse(t *testing.T) {
	// Create a response larger than 1MB
	largeBody := "[" + strings.Repeat(`{"sha256":"x","description":"d","severity":"s","source":"src","reported_at":"t"},`, 50000)
	largeBody = largeBody[:len(largeBody)-1] + "]" // remove trailing comma, close array

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdates(ts.URL)
	// With 1MB limit, parsing a >1MB body should either error or only parse partial data
	// The LimitReader will truncate, causing a JSON decode error
	assert.Error(t, err, "should error when response exceeds 1MB limit")
}

func TestFetchUpdates_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	db := ioc.NewDatabase()
	err := db.FetchUpdates(ts.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}
