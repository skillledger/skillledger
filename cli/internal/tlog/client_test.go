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

func TestNewClient_Defaults(t *testing.T) {
	c := NewClient()
	assert.Equal(t, "https://api.skillledger.dev", c.serviceURL)
	assert.NotNil(t, c.http)
}

func TestNewClient_WithServiceURL(t *testing.T) {
	c := NewClient(WithServiceURL("http://custom:9999"))
	assert.Equal(t, "http://custom:9999", c.serviceURL)
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	custom := &http.Client{}
	c := NewClient(WithHTTPClient(custom))
	assert.Same(t, custom, c.http)
}

func TestPublishEntry_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/log/publish", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, http.MethodPost, r.Method)

		var req PublishRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "test-artifact", req.ArtifactID)

		resp := PublishResponse{LogIndex: 42, ArtifactID: "test-artifact"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	resp, err := c.PublishEntry(context.Background(), &PublishRequest{
		ArtifactID:     "test-artifact",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abc123",
		Publisher:      "test@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(42), resp.LogIndex)
	assert.Equal(t, "test-artifact", resp.ArtifactID)
}

func TestPublishEntry_ServiceBusy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.PublishEntry(context.Background(), &PublishRequest{
		ArtifactID: "test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "busy")
}

func TestPublishEntry_ValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"detail":"invalid artifact_id"}`))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.PublishEntry(context.Background(), &PublishRequest{
		ArtifactID: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation error")
}

func TestPublishEntry_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	c := NewClient(WithServiceURL(server.URL))
	_, err := c.PublishEntry(context.Background(), &PublishRequest{
		ArtifactID: "test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestPublish_ValidInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := PublishResponse{LogIndex: 99, ArtifactID: "my-skill"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	result, err := Publish(context.Background(), PublishInput{
		ArtifactID:     "my-skill",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abcdef12",
		Publisher:      "dev@example.com",
		ServiceURL:     server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(99), result.LogIndex)
	assert.Equal(t, "my-skill", result.ArtifactID)
}

func TestPublish_EmptyArtifactID(t *testing.T) {
	_, err := Publish(context.Background(), PublishInput{
		ArtifactID:     "",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abc",
		Publisher:      "dev@example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "artifact ID is required")
}

func TestPublish_InvalidSHA256(t *testing.T) {
	_, err := Publish(context.Background(), PublishInput{
		ArtifactID:     "my-skill",
		SHA256:         "not-valid-hex",
		ContentAddress: "sha256-abc",
		Publisher:      "dev@example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "64 lowercase hex characters")
}

func TestPublish_EmptyContentAddress(t *testing.T) {
	_, err := Publish(context.Background(), PublishInput{
		ArtifactID:     "my-skill",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "",
		Publisher:      "dev@example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content address must start with \"sha256-\"")
}

func TestPublish_EmptyPublisher(t *testing.T) {
	_, err := Publish(context.Background(), PublishInput{
		ArtifactID:     "my-skill",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abc",
		Publisher:      "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "publisher identity is required")
}
