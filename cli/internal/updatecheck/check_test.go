package updatecheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAsync_NewerVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "1.2.0"})
	}))
	defer server.Close()

	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	require.NotNil(t, result)
	assert.True(t, result.UpdateAvail)
	assert.Equal(t, "1.2.0", result.LatestVersion)
}

func TestCheckAsync_SameVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "1.0.0"})
	}))
	defer server.Close()

	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	require.NotNil(t, result)
	assert.False(t, result.UpdateAvail)
}

func TestCheckAsync_OlderVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "0.9.0"})
	}))
	defer server.Close()

	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	require.NotNil(t, result)
	assert.False(t, result.UpdateAvail)
}

func TestCheckAsync_NetworkFailure(t *testing.T) {
	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, "http://localhost:1") // port 1 = guaranteed failure
	result := <-ch
	assert.Nil(t, result)
}

func TestCheckAsync_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	assert.Nil(t, result)
}

func TestCheckAsync_CacheWritten(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "2.0.0"})
	}))
	defer server.Close()

	fs := afero.NewMemMapFs()
	ch := CheckAsync("1.0.0", fs, server.URL)
	<-ch

	cachePath := filepath.Join(CacheDir(), cacheFileName)
	data, err := afero.ReadFile(fs, cachePath)
	require.NoError(t, err)

	var entry CacheEntry
	require.NoError(t, json.Unmarshal(data, &entry))
	assert.Equal(t, "2.0.0", entry.LatestVersion)
	assert.WithinDuration(t, time.Now(), entry.LastCheck, 5*time.Second)
}

func TestCheckAsync_CacheFresh_SkipsNetwork(t *testing.T) {
	fs := afero.NewMemMapFs()
	cachePath := filepath.Join(CacheDir(), cacheFileName)
	fs.MkdirAll(filepath.Dir(cachePath), 0o755)
	entry := CacheEntry{LastCheck: time.Now(), LatestVersion: "3.0.0"}
	data, _ := json.Marshal(entry)
	afero.WriteFile(fs, cachePath, data, 0o644)

	// Server that should NOT be hit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not have hit the server -- cache is fresh")
	}))
	defer server.Close()

	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	require.NotNil(t, result)
	assert.True(t, result.UpdateAvail)
	assert.Equal(t, "3.0.0", result.LatestVersion)
}

func TestCheckAsync_CacheStale_HitsNetwork(t *testing.T) {
	fs := afero.NewMemMapFs()
	cachePath := filepath.Join(CacheDir(), cacheFileName)
	fs.MkdirAll(filepath.Dir(cachePath), 0o755)
	staleEntry := CacheEntry{LastCheck: time.Now().Add(-25 * time.Hour), LatestVersion: "1.0.0"}
	data, _ := json.Marshal(staleEntry)
	afero.WriteFile(fs, cachePath, data, 0o644)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"version": "4.0.0"})
	}))
	defer server.Close()

	ch := CheckAsync("1.0.0", fs, server.URL)
	result := <-ch
	require.NotNil(t, result)
	assert.True(t, result.UpdateAvail)
	assert.Equal(t, "4.0.0", result.LatestVersion)
}

func TestShouldCheck_Default(t *testing.T) {
	// Ensure env vars are clean
	os.Unsetenv("SKILLLEDGER_NO_UPDATE_CHECK")
	os.Unsetenv("CI")
	assert.True(t, ShouldCheck(false))
}

func TestShouldCheck_Flag(t *testing.T) {
	assert.False(t, ShouldCheck(true))
}

func TestShouldCheck_EnvVar(t *testing.T) {
	t.Setenv("SKILLLEDGER_NO_UPDATE_CHECK", "1")
	assert.False(t, ShouldCheck(false))
}

func TestShouldCheck_CI(t *testing.T) {
	t.Setenv("CI", "true")
	assert.False(t, ShouldCheck(false))
}

func TestCompareVersions_Valid(t *testing.T) {
	r := compareVersions("1.0.0", "1.1.0")
	require.NotNil(t, r)
	assert.True(t, r.UpdateAvail)
}

func TestCompareVersions_InvalidCurrent(t *testing.T) {
	r := compareVersions("not-a-version", "1.1.0")
	assert.Nil(t, r)
}
