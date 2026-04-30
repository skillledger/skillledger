// Package threatsync provides background synchronization of threat intelligence
// data (IOC hashes/domains and YARA rules) from the SkillLedger hosted service.
// It uses ETag conditional requests to minimize bandwidth and writes cache files
// atomically with restricted permissions.
package threatsync

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/credentials"
)

const (
	// maxResponseBytes caps API response bodies at 10 MB (T-20-04).
	maxResponseBytes = 10 << 20
	// httpTimeout is the per-request HTTP client timeout (T-20-05).
	httpTimeout = 5 * time.Second
	// metadataFile is the name of the cache metadata file.
	metadataFile = "metadata.json"
	// iocCacheFile is the name of the cached IOC response.
	iocCacheFile = "ioc.json"
	// yaraCacheFile is the name of the cached YARA response.
	yaraCacheFile = "yara.json"
)

// Metadata holds ETag values and the last fetch timestamp for cache freshness
// comparison (D-01).
type Metadata struct {
	IOCETag   string    `json:"ioc_etag"`
	YARAETag  string    `json:"yara_etag"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Syncer fetches threat intelligence data from the hosted service in the
// background and caches it locally. Per D-03, it uses a channel for signaling
// completion.
type Syncer struct {
	done       chan struct{}
	cacheDir   string
	serviceURL string
}

// NewSyncer creates a Syncer that will fetch from serviceURL and write cache
// files to cacheDir.
func NewSyncer(serviceURL, cacheDir string) *Syncer {
	return &Syncer{
		done:       make(chan struct{}),
		cacheDir:   cacheDir,
		serviceURL: serviceURL,
	}
}

// StartAsync spawns a background goroutine that fetches IOC and YARA data
// from the hosted service. Auth failures and network errors are logged at
// Debug level and do not propagate (Pitfall 4: treat auth failure as offline).
func (s *Syncer) StartAsync() {
	go func() {
		defer close(s.done)
		s.doSync()
	}()
}

// WaitForSync blocks until the sync goroutine completes or the timeout
// elapses. Returns true if sync finished, false on timeout (D-04).
func (s *Syncer) WaitForSync(timeout time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// LoadMetadata reads and parses the cache metadata.json from cacheDir.
// Returns an error if the file is missing or unparseable.
func LoadMetadata(cacheDir string) (*Metadata, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, metadataFile))
	if err != nil {
		return nil, fmt.Errorf("reading cache metadata: %w", err)
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing cache metadata: %w", err)
	}
	return &m, nil
}

func (s *Syncer) doSync() {
	// Step 1: Get auth token. On failure, treat as offline (Pitfall 4).
	creds, err := credentials.EnsureFresh(s.serviceURL)
	if err != nil {
		log.Debug().Err(err).Msg("threatsync: auth failed, skipping sync")
		return
	}

	// Step 2: Create cache directory with restricted permissions (D-01).
	if err := os.MkdirAll(s.cacheDir, 0700); err != nil {
		log.Debug().Err(err).Msg("threatsync: failed to create cache directory")
		return
	}

	// Step 3: Load existing metadata for stored ETags.
	meta, err := LoadMetadata(s.cacheDir)
	if err != nil {
		// No existing metadata is fine; start fresh.
		meta = &Metadata{}
	}

	// Step 4: Fetch IOC data with ETag conditional request.
	iocBody, newIOCETag, iocChanged, err := fetchWithETag(
		s.serviceURL+"/v1/ioc", meta.IOCETag, creds.AccessToken,
	)
	if err != nil {
		log.Debug().Err(err).Msg("threatsync: IOC fetch failed")
	} else if iocChanged {
		if writeErr := atomicWriteFile(
			filepath.Join(s.cacheDir, iocCacheFile), iocBody, 0600,
		); writeErr != nil {
			log.Debug().Err(writeErr).Msg("threatsync: failed to write IOC cache")
		} else {
			meta.IOCETag = newIOCETag
		}
	}

	// Step 5: Fetch YARA data with same ETag/auth pattern.
	yaraBody, newYARAETag, yaraChanged, err := fetchWithETag(
		s.serviceURL+"/v1/yara", meta.YARAETag, creds.AccessToken,
	)
	if err != nil {
		log.Debug().Err(err).Msg("threatsync: YARA fetch failed")
	} else if yaraChanged {
		if writeErr := atomicWriteFile(
			filepath.Join(s.cacheDir, yaraCacheFile), yaraBody, 0600,
		); writeErr != nil {
			log.Debug().Err(writeErr).Msg("threatsync: failed to write YARA cache")
		} else {
			meta.YARAETag = newYARAETag
		}
	}

	// Step 6: Write updated metadata atomically.
	meta.FetchedAt = time.Now().UTC()
	metaData, err := json.Marshal(meta)
	if err != nil {
		log.Debug().Err(err).Msg("threatsync: failed to marshal metadata")
		return
	}
	if err := atomicWriteFile(
		filepath.Join(s.cacheDir, metadataFile), metaData, 0600,
	); err != nil {
		log.Debug().Err(err).Msg("threatsync: failed to write metadata")
	}
}

// fetchWithETag performs an HTTP GET with Bearer auth and If-None-Match header.
// Returns (nil, oldEtag, false, nil) on 304 Not Modified.
func fetchWithETag(endpoint, etag, token string) (body []byte, newETag string, changed bool, err error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, false, nil
	case http.StatusOK:
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if readErr != nil {
			return nil, "", false, fmt.Errorf("reading response: %w", readErr)
		}
		newETag := resp.Header.Get("ETag")
		return respBody, newETag, true, nil
	default:
		return nil, "", false, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, endpoint)
	}
}

// atomicWriteFile writes data to path atomically by writing to a temp file
// in the same directory and then renaming. Temp file is cleaned up on error.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up temp file on any error.
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	success = true
	return nil
}
