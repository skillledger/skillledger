package orgsync

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

// setupCredentials writes a credentials.json file that EnsureFresh can load.
func setupCredentials(t *testing.T) func() {
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

// newOrgPolicyServer creates an httptest server that serves org policy endpoint.
func newOrgPolicyServer(etag string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/refresh":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig","refresh_token":"rt","token_type":"bearer"}`))
		case "/ee/v1/orgs/test-org/policy":
			if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
				w.Header().Set("ETag", etag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"policy-etag-v1"`)
			w.Header().Set("Content-Type", "application/json")
			resp := policyResponse{Rego: "package org\ndefault allow = false"}
			data, _ := json.Marshal(resp)
			w.Write(data)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestOrgSyncFresh(t *testing.T) {
	ts := newOrgPolicyServer("")
	defer ts.Close()

	cleanup := setupCredentials(t)
	defer cleanup()

	cacheDir := t.TempDir()
	syncer := NewOrgSyncer(ts.URL, cacheDir, "test-org")
	syncer.StartAsync()

	completed := syncer.WaitForSync(5 * time.Second)
	require.True(t, completed, "sync should complete within timeout")

	// Verify cached file contains pure Rego (not JSON)
	data, err := os.ReadFile(syncer.CachedPolicyPath())
	require.NoError(t, err)
	assert.Equal(t, "package org\ndefault allow = false", string(data))

	// Verify it's not JSON
	var js json.RawMessage
	assert.Error(t, json.Unmarshal(data, &js), "cached file should be pure Rego, not JSON")

	// Verify metadata file has ETag
	metaData, err := os.ReadFile(filepath.Join(cacheDir, metadataFile))
	require.NoError(t, err)
	var meta Metadata
	require.NoError(t, json.Unmarshal(metaData, &meta))
	assert.Equal(t, `"policy-etag-v1"`, meta.ETag)
	assert.WithinDuration(t, time.Now(), meta.FetchedAt, 10*time.Second)

	// Verify file permissions are 0600
	info, err := os.Stat(syncer.CachedPolicyPath())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestOrgSyncNotModified(t *testing.T) {
	ts := newOrgPolicyServer(`"existing-etag"`)
	defer ts.Close()

	cleanup := setupCredentials(t)
	defer cleanup()

	cacheDir := t.TempDir()

	// Pre-populate cache with existing policy
	os.WriteFile(filepath.Join(cacheDir, policyFile), []byte("package org\ndefault allow = true"), 0600)

	// Pre-populate metadata with the ETag the server will match
	meta := Metadata{
		ETag:      `"existing-etag"`,
		FetchedAt: time.Now().Add(-1 * time.Hour),
	}
	metaBytes, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(cacheDir, metadataFile), metaBytes, 0600)

	syncer := NewOrgSyncer(ts.URL, cacheDir, "test-org")
	syncer.StartAsync()
	completed := syncer.WaitForSync(5 * time.Second)
	require.True(t, completed)

	// Verify cached file was NOT overwritten
	data, _ := os.ReadFile(filepath.Join(cacheDir, policyFile))
	assert.Equal(t, "package org\ndefault allow = true", string(data))

	// Verify metadata FetchedAt was updated
	newMetaData, err := os.ReadFile(filepath.Join(cacheDir, metadataFile))
	require.NoError(t, err)
	var newMeta Metadata
	require.NoError(t, json.Unmarshal(newMetaData, &newMeta))
	assert.True(t, newMeta.FetchedAt.After(meta.FetchedAt), "FetchedAt should be updated")
}

func TestOrgSyncTimeout(t *testing.T) {
	// Server that sleeps longer than the 2s httpTimeout
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

	cleanup := setupCredentials(t)
	defer cleanup()

	cacheDir := t.TempDir()

	// Pre-populate cache so we can verify it's unchanged after timeout
	os.WriteFile(filepath.Join(cacheDir, policyFile), []byte("existing policy"), 0600)

	syncer := NewOrgSyncer(ts.URL, cacheDir, "test-org")
	syncer.StartAsync()

	// The HTTP timeout is 2s, so doSync should complete within ~3s
	completed := syncer.WaitForSync(5 * time.Second)
	assert.True(t, completed, "sync should complete after HTTP timeout")

	// Verify cached file was NOT changed (fallback behavior)
	data, _ := os.ReadFile(filepath.Join(cacheDir, policyFile))
	assert.Equal(t, "existing policy", string(data))
}

func TestOrgSyncAuthFailure(t *testing.T) {
	// Temporarily rename credentials file to simulate no auth
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	credFile := filepath.Join(home, ".skillledger", "credentials.json")
	backupFile := credFile + ".bak-orgsync-test"

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

	cacheDir := t.TempDir()
	syncer := NewOrgSyncer("http://localhost:1", cacheDir, "test-org")
	syncer.StartAsync()

	completed := syncer.WaitForSync(2 * time.Second)
	assert.True(t, completed, "sync should complete (done channel closes) even without auth")

	// No cache files should be written
	_, err = os.Stat(filepath.Join(cacheDir, policyFile))
	assert.True(t, os.IsNotExist(err))
}

func TestLoadCachedPolicy(t *testing.T) {
	cacheDir := t.TempDir()
	regoContent := "package test\ndefault allow = true\n"

	// Write a policy file
	err := os.WriteFile(filepath.Join(cacheDir, policyFile), []byte(regoContent), 0600)
	require.NoError(t, err)

	// Verify LoadCachedPolicy reads it back
	content, err := LoadCachedPolicy(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, regoContent, content)

	// Verify error on missing file
	_, err = LoadCachedPolicy(t.TempDir())
	assert.Error(t, err)
}
