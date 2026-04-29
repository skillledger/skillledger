// Package updatecheck provides non-blocking update checking against the npm
// registry. It is designed to be spawned as a goroutine in PersistentPreRun
// and read in PersistentPostRun, so the check never delays command execution.
package updatecheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"golang.org/x/mod/semver"
)

const (
	// RegistryURL is the npm registry endpoint for version checks.
	// Exported so root.go can pass it to CheckAsync (avoids hardcoding
	// the URL in multiple packages).
	RegistryURL    = "https://registry.npmjs.org/skillledger/latest"
	cacheTTL       = 24 * time.Hour
	requestTimeout = 2 * time.Second
	cacheFileName  = "last-update-check"
)

// Result holds the outcome of an update check.
type Result struct {
	LatestVersion string
	UpdateAvail   bool
}

// CacheEntry is the JSON structure persisted to disk.
type CacheEntry struct {
	LastCheck     time.Time `json:"last_check"`
	LatestVersion string    `json:"latest_version"`
}

// ShouldCheck returns false when update checking is suppressed.
// Opt-outs per D-15: SKILLLEDGER_NO_UPDATE_CHECK=1, CI=true, noUpdateCheck flag.
func ShouldCheck(noUpdateCheckFlag bool) bool {
	if noUpdateCheckFlag {
		return false
	}
	if os.Getenv("SKILLLEDGER_NO_UPDATE_CHECK") == "1" {
		return false
	}
	if os.Getenv("CI") != "" {
		return false
	}
	return true
}

// CacheDir returns the XDG-respectful cache directory (D-16).
// Linux: $XDG_CACHE_HOME/skillledger or ~/.cache/skillledger
// macOS/Windows: ~/.skillledger
func CacheDir() string {
	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			return filepath.Join(xdg, "skillledger")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".cache", "skillledger")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".skillledger")
}

// CheckAsync spawns a goroutine that checks the npm registry for a newer version.
// The returned channel receives at most one *Result. If the check fails or is
// throttled by cache, the channel closes with no value sent (nil receive).
// Never blocks the caller. Per D-14.
func CheckAsync(currentVersion string, fs afero.Fs, registryEndpoint string) <-chan *Result {
	ch := make(chan *Result, 1)
	go func() {
		defer close(ch)
		result := doCheck(currentVersion, fs, registryEndpoint)
		if result != nil {
			ch <- result
		}
	}()
	return ch
}

func doCheck(currentVersion string, fs afero.Fs, registryEndpoint string) *Result {
	cachePath := filepath.Join(CacheDir(), cacheFileName)

	// Check cache -- skip network if checked within cacheTTL
	if entry, err := readCache(fs, cachePath); err == nil {
		if time.Since(entry.LastCheck) < cacheTTL {
			log.Debug().Time("last_check", entry.LastCheck).Msg("update check: using cached result")
			return compareVersions(currentVersion, entry.LatestVersion)
		}
	}

	// Fetch from registry
	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Get(registryEndpoint)
	if err != nil {
		log.Debug().Err(err).Msg("update check: registry request failed")
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug().Int("status", resp.StatusCode).Msg("update check: registry returned non-200")
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.Debug().Err(err).Msg("update check: failed to read response")
		return nil
	}

	var data struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.Version == "" {
		log.Debug().Err(err).Msg("update check: failed to parse version from registry")
		return nil
	}

	// Write cache
	writeCache(fs, cachePath, &CacheEntry{
		LastCheck:     time.Now(),
		LatestVersion: data.Version,
	})

	return compareVersions(currentVersion, data.Version)
}

func compareVersions(current, latest string) *Result {
	// Ensure "v" prefix for semver comparison
	cv := current
	if cv != "" && cv[0] != 'v' {
		cv = "v" + cv
	}
	lv := latest
	if lv != "" && lv[0] != 'v' {
		lv = "v" + lv
	}

	if !semver.IsValid(cv) || !semver.IsValid(lv) {
		return nil
	}

	return &Result{
		LatestVersion: latest,
		UpdateAvail:   semver.Compare(lv, cv) > 0,
	}
}

func readCache(fs afero.Fs, path string) (*CacheEntry, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, err
	}
	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func writeCache(fs afero.Fs, path string, entry *CacheEntry) {
	dir := filepath.Dir(path)
	if err := fs.MkdirAll(dir, 0o755); err != nil {
		log.Debug().Err(err).Msg("update check: failed to create cache dir")
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if err := afero.WriteFile(fs, path, data, 0o644); err != nil {
		log.Debug().Err(err).Msg("update check: failed to write cache")
	}
}

// PrintNotice prints the update notice to stderr if an update is available.
// Per D-14: only prints if stderr is a TTY (caller checks TTY before calling).
func PrintNotice(result *Result, currentVersion string) {
	if result == nil || !result.UpdateAvail {
		return
	}
	fmt.Fprintf(os.Stderr, "\nA new version of skillledger is available: v%s (you have v%s).\nUpdate with: npm i -g skillledger\n\n", result.LatestVersion, currentVersion)
}
