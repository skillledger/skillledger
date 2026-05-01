// Package orgsync provides background synchronization of org-wide OPA policy
// from the SkillLedger hosted service. It uses ETag conditional requests to
// minimize bandwidth and writes cache files atomically with restricted permissions.
package orgsync

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
	// httpTimeout is the per-request HTTP client timeout (D-04: 2s for policy fetch).
	httpTimeout = 2 * time.Second
	// policyFile is the cached org policy file name (pure Rego).
	policyFile = "org-policy.rego"
	// metadataFile stores ETag and fetch timestamp.
	metadataFile = "org-policy-meta.json"
	// maxResponseBytes caps policy response at 1MB (T-25-07).
	maxResponseBytes = 1 << 20
)

// Metadata holds the ETag value and the last fetch timestamp for cache
// freshness comparison.
type Metadata struct {
	ETag      string    `json:"etag"`
	FetchedAt time.Time `json:"fetched_at"`
}

// policyResponse is the JSON shape returned by GET /ee/v1/orgs/{slug}/policy.
type policyResponse struct {
	Rego string `json:"rego"`
}

// OrgSyncer fetches org-wide policy from the hosted service in the background
// and caches it locally as a pure Rego file.
type OrgSyncer struct {
	done       chan struct{}
	cacheDir   string
	serviceURL string
	orgSlug    string
}

// NewOrgSyncer creates an OrgSyncer that will fetch from serviceURL and write
// cache files to cacheDir for the given org slug.
func NewOrgSyncer(serviceURL, cacheDir, orgSlug string) *OrgSyncer {
	return &OrgSyncer{
		done:       make(chan struct{}),
		cacheDir:   cacheDir,
		serviceURL: serviceURL,
		orgSlug:    orgSlug,
	}
}

// StartAsync spawns a background goroutine that fetches org policy from the
// hosted service. Auth failures and network errors are logged at Debug level
// and do not propagate.
func (s *OrgSyncer) StartAsync() {
	go func() {
		defer close(s.done)
		s.doSync()
	}()
}

// WaitForSync blocks until the sync goroutine completes or the timeout elapses.
// Returns true if sync finished, false on timeout.
func (s *OrgSyncer) WaitForSync(timeout time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// CachedPolicyPath returns the filesystem path to the cached org policy file.
func (s *OrgSyncer) CachedPolicyPath() string {
	return filepath.Join(s.cacheDir, policyFile)
}

// LoadCachedPolicy reads and returns the cached Rego policy file content.
// Returns an error if the file does not exist.
func LoadCachedPolicy(cacheDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, policyFile))
	if err != nil {
		return "", fmt.Errorf("reading cached org policy: %w", err)
	}
	return string(data), nil
}

func (s *OrgSyncer) doSync() {
	// Step 1: Get auth token. On failure, treat as offline.
	creds, err := credentials.EnsureFresh(s.serviceURL)
	if err != nil {
		log.Debug().Err(err).Msg("orgsync: auth failed, skipping sync")
		return
	}

	// Step 2: Create cache directory with restricted permissions.
	if err := os.MkdirAll(s.cacheDir, 0700); err != nil {
		log.Debug().Err(err).Msg("orgsync: failed to create cache directory")
		return
	}

	// Step 3: Load existing metadata for stored ETag.
	meta := &Metadata{}
	if metaData, readErr := os.ReadFile(filepath.Join(s.cacheDir, metadataFile)); readErr == nil {
		_ = json.Unmarshal(metaData, meta)
	}

	// Step 4: Fetch policy with ETag conditional request.
	endpoint := s.serviceURL + "/ee/v1/orgs/" + s.orgSlug + "/policy"
	body, newETag, changed, err := fetchWithETag(endpoint, meta.ETag, creds.AccessToken)
	if err != nil {
		log.Debug().Err(err).Msg("orgsync: policy fetch failed")
		return
	}

	if changed {
		// Parse the JSON response to extract the rego field.
		var pr policyResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			log.Debug().Err(err).Msg("orgsync: failed to parse policy response JSON")
			return
		}

		// Step 5: Write pure Rego to cache file.
		if err := atomicWriteFile(s.CachedPolicyPath(), []byte(pr.Rego), 0600); err != nil {
			log.Debug().Err(err).Msg("orgsync: failed to write policy cache")
			return
		}
		meta.ETag = newETag
	}

	// Step 6: Write updated metadata atomically.
	meta.FetchedAt = time.Now().UTC()
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		log.Debug().Err(err).Msg("orgsync: failed to marshal metadata")
		return
	}
	if err := atomicWriteFile(filepath.Join(s.cacheDir, metadataFile), metaBytes, 0600); err != nil {
		log.Debug().Err(err).Msg("orgsync: failed to write metadata")
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
