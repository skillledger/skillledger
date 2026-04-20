package tlog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupEntry_Success(t *testing.T) {
	expected := LookupResponse{
		ArtifactID:     "my-skill-v1.0.0",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abcdef12",
		LogIndex:       42,
		Publisher:      "dev@example.com",
		PublishedAt:    "2026-04-20T10:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/log/lookup/my-skill-v1.0.0", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	resp, err := c.LookupEntry(context.Background(), "my-skill-v1.0.0")
	require.NoError(t, err)

	assert.Equal(t, expected.ArtifactID, resp.ArtifactID)
	assert.Equal(t, expected.SHA256, resp.SHA256)
	assert.Equal(t, expected.ContentAddress, resp.ContentAddress)
	assert.Equal(t, expected.LogIndex, resp.LogIndex)
	assert.Equal(t, expected.Publisher, resp.Publisher)
	assert.Equal(t, expected.PublishedAt, resp.PublishedAt)
}

func TestLookupEntry_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"not found"}`))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.LookupEntry(context.Background(), "nonexistent-skill")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in transparency log")
}

func TestLookupEntry_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.LookupEntry(context.Background(), "some-skill")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log service returned status 500")
}

func TestLookupEntry_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.LookupEntry(context.Background(), "some-skill")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding")
}
