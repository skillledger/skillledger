package tlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// LookupResponse is the payload returned from the /log/lookup/{artifact_id} endpoint.
type LookupResponse struct {
	ArtifactID     string `json:"artifact_id"`
	SHA256         string `json:"sha256"`
	ContentAddress string `json:"content_address"`
	LogIndex       int64  `json:"log_index"`
	Publisher      string `json:"publisher"`
	PublishedAt    string `json:"published_at"`
}

// LookupEntry queries the transparency log service for an artifact entry.
// It returns the entry metadata if found, or an error if the artifact is
// not in the log or the service is unavailable.
func (c *Client) LookupEntry(ctx context.Context, artifactID string) (*LookupResponse, error) {
	url := c.serviceURL + "/log/lookup/" + artifactID
	log.Debug().Str("url", url).Msg("looking up artifact in transparency log")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending lookup request: %w", err)
	}
	defer resp.Body.Close()

	log.Debug().Int("status", resp.StatusCode).Msg("lookup response received")

	// T-07-01: Limit response body to 1MB to prevent denial of service
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("artifact %q not found in transparency log", artifactID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("log service returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var lookupResp LookupResponse
	if err := json.Unmarshal(respBody, &lookupResp); err != nil {
		return nil, fmt.Errorf("decoding lookup response: %w", err)
	}

	return &lookupResp, nil
}
