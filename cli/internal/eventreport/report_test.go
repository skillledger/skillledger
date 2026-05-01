package eventreport

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCredentials writes a credentials.json file that EnsureFresh can load.
func setupCredentials(t *testing.T) func() {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	credDir := filepath.Join(home, ".skillledger")
	credFile := filepath.Join(credDir, "credentials.json")

	existingData, existingErr := os.ReadFile(credFile)

	err = os.MkdirAll(credDir, 0700)
	require.NoError(t, err)

	creds := map[string]interface{}{
		"access_token":  "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig",
		"refresh_token": "test-refresh-token",
		"expires_at":    9999999999,
	}
	data, _ := json.Marshal(creds)
	err = os.WriteFile(credFile, data, 0600)
	require.NoError(t, err)

	return func() {
		if existingErr == nil {
			os.WriteFile(credFile, existingData, 0600)
		} else {
			os.Remove(credFile)
		}
	}
}

func TestReportEvents(t *testing.T) {
	var mu sync.Mutex
	var receivedBatches []EventBatch

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
		case "/ee/v1/events":
			body, _ := io.ReadAll(r.Body)
			var batch EventBatch
			json.Unmarshal(body, &batch)
			mu.Lock()
			receivedBatches = append(receivedBatches, batch)
			mu.Unlock()

			// Verify auth header
			assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cleanup := setupCredentials(t)
	defer cleanup()

	events := []Event{
		{Type: "violation", Ecosystem: "claude-code", SkillID: "skill-1", Rule: "no-network", Severity: "high", Timestamp: time.Now()},
		{Type: "violation", Ecosystem: "mcp", SkillID: "skill-2", Rule: "no-fs-write", Severity: "medium", Timestamp: time.Now()},
		{Type: "ioc-match", Ecosystem: "npm", SkillID: "skill-3", Rule: "hash-match", Severity: "critical", Details: map[string]interface{}{"hash": "abc123"}, Timestamp: time.Now()},
	}

	reporter := NewReporter(ts.URL)
	reporter.ReportEventsAsync("test-org", events)

	completed := reporter.WaitForReport(5 * time.Second)
	require.True(t, completed, "report should complete within timeout")

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, receivedBatches, 1, "3 events should be sent in 1 batch")
	assert.Equal(t, "test-org", receivedBatches[0].OrgSlug)
	assert.Len(t, receivedBatches[0].Events, 3)
	assert.Equal(t, "violation", receivedBatches[0].Events[0].Type)
	assert.Equal(t, "skill-1", receivedBatches[0].Events[0].SkillID)
}

func TestReportEventsChunking(t *testing.T) {
	var mu sync.Mutex
	var requestCount int
	var batchSizes []int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
		case "/ee/v1/events":
			body, _ := io.ReadAll(r.Body)
			var batch EventBatch
			json.Unmarshal(body, &batch)
			mu.Lock()
			requestCount++
			batchSizes = append(batchSizes, len(batch.Events))
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cleanup := setupCredentials(t)
	defer cleanup()

	// Create 150 events to trigger chunking (maxBatchSize=100)
	events := make([]Event, 150)
	for i := range events {
		events[i] = Event{
			Type:      "violation",
			Ecosystem: "claude-code",
			SkillID:   "skill-test",
			Rule:      "test-rule",
			Severity:  "low",
			Timestamp: time.Now(),
		}
	}

	reporter := NewReporter(ts.URL)
	reporter.ReportEventsAsync("chunk-org", events)

	completed := reporter.WaitForReport(5 * time.Second)
	require.True(t, completed)

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, 2, requestCount, "150 events should be chunked into 2 requests")
	assert.Contains(t, batchSizes, 100, "first batch should have 100 events")
	assert.Contains(t, batchSizes, 50, "second batch should have 50 events")
}

func TestReportProfile(t *testing.T) {
	var receivedProfile Profile
	var received bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
		case "/ee/v1/profiles":
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedProfile)
			received = true

			assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cleanup := setupCredentials(t)
	defer cleanup()

	profile := Profile{
		OrgSlug:      "test-org",
		SkillID:      "my-skill",
		Ecosystem:    "claude-code",
		Capabilities: []string{"network", "filesystem", "subprocess"},
		DetectedAt:   time.Now(),
	}

	reporter := NewReporter(ts.URL)
	reporter.ReportProfileAsync(profile)

	// Give goroutine time to complete (no done channel for profile)
	time.Sleep(500 * time.Millisecond)

	assert.True(t, received, "profile should have been received by server")
	assert.Equal(t, "test-org", receivedProfile.OrgSlug)
	assert.Equal(t, "my-skill", receivedProfile.SkillID)
	assert.Equal(t, "claude-code", receivedProfile.Ecosystem)
	assert.ElementsMatch(t, []string{"network", "filesystem", "subprocess"}, receivedProfile.Capabilities)
}

func TestReportEventsAuthFailure(t *testing.T) {
	// Temporarily rename credentials file to simulate no auth
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	credFile := filepath.Join(home, ".skillledger", "credentials.json")
	backupFile := credFile + ".bak-eventreport-test"

	if existingData, readErr := os.ReadFile(credFile); readErr == nil {
		os.Rename(credFile, backupFile)
		defer func() {
			os.WriteFile(credFile, existingData, 0600)
			os.Remove(backupFile)
		}()
	} else {
		defer func() {
			os.Remove(credFile)
		}()
	}

	serverHit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ee/v1/events" {
			serverHit = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	events := []Event{
		{Type: "violation", Ecosystem: "test", SkillID: "s1", Rule: "r1", Severity: "low", Timestamp: time.Now()},
	}

	reporter := NewReporter(ts.URL)
	reporter.ReportEventsAsync("test-org", events)

	completed := reporter.WaitForReport(2 * time.Second)
	assert.True(t, completed, "should complete even without auth")
	assert.False(t, serverHit, "no HTTP request should be made without credentials")
}
