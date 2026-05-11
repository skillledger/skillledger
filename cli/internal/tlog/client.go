// Package tlog provides an HTTP client for the SkillLedger transparency log
// service. It communicates with the FastAPI service's /log/publish endpoint
// to submit artifact entries to the transparency log.
package tlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Client is an HTTP client for the SkillLedger transparency log service.
type Client struct {
	serviceURL string
	http       *http.Client
	apiKey     string
}

// Option configures the Client.
type Option func(*Client)

// WithServiceURL overrides the default service URL.
func WithServiceURL(u string) Option {
	return func(c *Client) { c.serviceURL = u }
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithAPIKey sets the Bearer token used for authenticated publish requests.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// NewClient creates a transparency log client with the given options.
// Defaults to https://api.skillledger.in.
func NewClient(opts ...Option) *Client {
	c := &Client{
		serviceURL: "https://api.skillledger.in",
		http:       http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// PublishRequest is the payload sent to the /log/publish endpoint.
type PublishRequest struct {
	ArtifactID     string `json:"artifact_id"`
	SHA256         string `json:"sha256"`
	ContentAddress string `json:"content_address"`
	Publisher      string `json:"publisher"`
}

// PublishResponse is the payload returned from the /log/publish endpoint.
type PublishResponse struct {
	LogIndex   int64  `json:"log_index"`
	ArtifactID string `json:"artifact_id"`
}

// PublishEntry submits an artifact entry to the transparency log service.
func (c *Client) PublishEntry(ctx context.Context, req *PublishRequest) (*PublishResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling publish request: %w", err)
	}

	url := c.serviceURL + "/log/publish"
	log.Debug().Str("url", url).Msg("publishing to transparency log")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending publish request: %w", err)
	}
	defer resp.Body.Close()

	log.Debug().Int("status", resp.StatusCode).Msg("publish response received")

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return nil, fmt.Errorf("log service busy, retry later")
	case resp.StatusCode == http.StatusUnprocessableEntity:
		return nil, fmt.Errorf("validation error from log service: %s", string(respBody))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("log service returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var publishResp PublishResponse
	if err := json.Unmarshal(respBody, &publishResp); err != nil {
		return nil, fmt.Errorf("unmarshaling publish response: %w", err)
	}

	return &publishResp, nil
}
