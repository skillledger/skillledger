package threatsync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iocResponseJSON returns a sample IOC API response.
func iocResponseJSON() []byte {
	resp := map[string]interface{}{
		"updated_at": "2026-01-01T00:00:00Z",
		"count":      2,
		"hashes": []map[string]string{
			{"sha256": "abc123", "description": "test hash", "severity": "high", "source": "test", "reported_at": "2026-01-01"},
		},
		"domains": []map[string]string{
			{"domain": "evil.com", "description": "test domain", "severity": "critical", "source": "test", "reported_at": "2026-01-01"},
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

// yaraResponseJSON returns a sample YARA API response.
func yaraResponseJSON() []byte {
	resp := map[string]interface{}{
		"updated_at": "2026-01-01T00:00:00Z",
		"count":      1,
		"rules": []map[string]string{
			{"name": "test_rule", "content": "rule test_rule { condition: true }", "source": "test"},
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

// newTestServer creates an httptest server that serves IOC and YARA endpoints.
// It also serves a credentials refresh endpoint so EnsureFresh can work.
func newTestServer(iocETag, yaraETag string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			w.Header().Set("Content-Type", "application/json")
			// Return a fake JWT with exp far in the future
			// JWT payload: {"exp": 9999999999}
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
		case "/v1/ioc":
			if inm := r.Header.Get("If-None-Match"); inm != "" && inm == iocETag {
				w.Header().Set("ETag", iocETag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"ioc-etag-new"`)
			w.Header().Set("Content-Type", "application/json")
			w.Write(iocResponseJSON())
		case "/v1/yara":
			if inm := r.Header.Get("If-None-Match"); inm != "" && inm == yaraETag {
				w.Header().Set("ETag", yaraETag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"yara-etag-new"`)
			w.Header().Set("Content-Type", "application/json")
			w.Write(yaraResponseJSON())
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// setupCredentials writes a credentials.json file that EnsureFresh can load.
// The serviceURL must match the test server URL.
func setupCredentials(t *testing.T, serviceURL string) func() {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	credDir := filepath.Join(home, ".skillledger")
	credFile := filepath.Join(credDir, "credentials.json")

	// Save existing credentials if any to restore later
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

func TestSyncer_FetchesAndCaches(t *testing.T) {
	ts := newTestServer("", "")
	defer ts.Close()

	cleanup := setupCredentials(t, ts.URL)
	defer cleanup()

	cacheDir := t.TempDir()
	syncer := NewSyncer(ts.URL, cacheDir)
	syncer.StartAsync()

	completed := syncer.WaitForSync(5 * time.Second)
	require.True(t, completed, "sync should complete within timeout")

	// Verify IOC cache file exists with correct content
	iocData, err := os.ReadFile(filepath.Join(cacheDir, iocCacheFile))
	require.NoError(t, err)
	assert.Contains(t, string(iocData), "abc123")

	// Verify YARA cache file exists
	yaraData, err := os.ReadFile(filepath.Join(cacheDir, yaraCacheFile))
	require.NoError(t, err)
	assert.Contains(t, string(yaraData), "test_rule")

	// Verify file permissions are 0600
	iocInfo, err := os.Stat(filepath.Join(cacheDir, iocCacheFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), iocInfo.Mode().Perm())

	yaraInfo, err := os.Stat(filepath.Join(cacheDir, yaraCacheFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), yaraInfo.Mode().Perm())

	// Verify metadata has ETags and recent FetchedAt
	meta, err := LoadMetadata(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, `"ioc-etag-new"`, meta.IOCETag)
	assert.Equal(t, `"yara-etag-new"`, meta.YARAETag)
	assert.WithinDuration(t, time.Now(), meta.FetchedAt, 10*time.Second)
}

func TestSyncer_ETag304_SkipsWrite(t *testing.T) {
	ts := newTestServer(`"existing-ioc-etag"`, `"existing-yara-etag"`)
	defer ts.Close()

	cleanup := setupCredentials(t, ts.URL)
	defer cleanup()

	cacheDir := t.TempDir()

	// Pre-populate cache files
	os.WriteFile(filepath.Join(cacheDir, iocCacheFile), []byte(`{"original":"ioc"}`), 0600)
	os.WriteFile(filepath.Join(cacheDir, yaraCacheFile), []byte(`{"original":"yara"}`), 0600)

	// Pre-populate metadata with the ETags the server will match
	meta := Metadata{
		IOCETag:   `"existing-ioc-etag"`,
		YARAETag:  `"existing-yara-etag"`,
		FetchedAt: time.Now().Add(-1 * time.Hour),
	}
	metaData, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(cacheDir, metadataFile), metaData, 0600)

	syncer := NewSyncer(ts.URL, cacheDir)
	syncer.StartAsync()
	completed := syncer.WaitForSync(5 * time.Second)
	require.True(t, completed)

	// Verify cache files were NOT overwritten
	iocData, _ := os.ReadFile(filepath.Join(cacheDir, iocCacheFile))
	assert.Equal(t, `{"original":"ioc"}`, string(iocData))

	yaraData, _ := os.ReadFile(filepath.Join(cacheDir, yaraCacheFile))
	assert.Equal(t, `{"original":"yara"}`, string(yaraData))

	// Verify metadata FetchedAt was updated
	newMeta, err := LoadMetadata(cacheDir)
	require.NoError(t, err)
	assert.True(t, newMeta.FetchedAt.After(meta.FetchedAt), "FetchedAt should be updated")
}

func TestSyncer_WaitForSync_CompletesInTime(t *testing.T) {
	ts := newTestServer("", "")
	defer ts.Close()

	cleanup := setupCredentials(t, ts.URL)
	defer cleanup()

	syncer := NewSyncer(ts.URL, t.TempDir())
	syncer.StartAsync()

	completed := syncer.WaitForSync(2 * time.Second)
	assert.True(t, completed, "sync against fast server should complete within 2s")
}

func TestSyncer_WaitForSync_Timeout(t *testing.T) {
	// Server that sleeps longer than the wait timeout
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/refresh" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
			return
		}
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cleanup := setupCredentials(t, ts.URL)
	defer cleanup()

	syncer := NewSyncer(ts.URL, t.TempDir())
	syncer.StartAsync()

	completed := syncer.WaitForSync(100 * time.Millisecond)
	assert.False(t, completed, "WaitForSync should time out")
}

func TestSyncer_AuthFailure_SilentFallback(t *testing.T) {
	// Temporarily rename credentials file to simulate no auth
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	credFile := filepath.Join(home, ".skillledger", "credentials.json")
	backupFile := credFile + ".bak-test"

	if existingData, err := os.ReadFile(credFile); err == nil {
		os.Rename(credFile, backupFile)
		defer func() {
			os.WriteFile(credFile, existingData, 0600)
			os.Remove(backupFile)
		}()
	} else {
		// No credentials file exists; nothing to move
		defer func() {
			os.Remove(credFile)
		}()
	}

	cacheDir := t.TempDir()
	syncer := NewSyncer("http://localhost:1", cacheDir)
	syncer.StartAsync()

	completed := syncer.WaitForSync(2 * time.Second)
	assert.True(t, completed, "sync should complete (done channel closes) even without auth")

	// No cache files should be written
	_, err = os.Stat(filepath.Join(cacheDir, iocCacheFile))
	assert.True(t, os.IsNotExist(err))
}

func TestSyncer_AtomicWrite_NoPartialFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-file")

	err := atomicWriteFile(path, []byte("hello world"), 0600)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Verify no temp files remain
	entries, _ := os.ReadDir(dir)
	assert.Len(t, entries, 1, "only the final file should exist, no temp leftovers")
}

func TestSyncer_ServerError_SilentFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/refresh" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cleanup := setupCredentials(t, ts.URL)
	defer cleanup()

	cacheDir := t.TempDir()
	syncer := NewSyncer(ts.URL, cacheDir)
	syncer.StartAsync()

	completed := syncer.WaitForSync(5 * time.Second)
	assert.True(t, completed, "sync should complete even with server errors")

	// No cache data files should be written (server returned 500)
	_, err := os.Stat(filepath.Join(cacheDir, iocCacheFile))
	assert.True(t, os.IsNotExist(err))

	// Metadata should still be written (with empty etags)
	meta, err := LoadMetadata(cacheDir)
	require.NoError(t, err)
	assert.Empty(t, meta.IOCETag)
	assert.WithinDuration(t, time.Now(), meta.FetchedAt, 10*time.Second)
}
