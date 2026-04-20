package logclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/sumdb/note"
)

// testVerifier creates a note.Verifier for testing.
func testVerifier(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(nil, "test-log")
	require.NoError(t, err)
	signer, err := note.NewSigner(skey)
	require.NoError(t, err)
	verifier, err := note.NewVerifier(vkey)
	require.NoError(t, err)
	return signer, verifier
}

func TestNewClient_Defaults(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:2025", c.logURL)
	assert.Equal(t, "test-log", c.origin)
	assert.NotNil(t, c.http)
	assert.NotNil(t, c.fetcher)
	assert.NotNil(t, c.verifier)
}

func TestNewClient_WithOptions(t *testing.T) {
	_, v := testVerifier(t)
	customHTTP := &http.Client{}

	c, err := NewClient(v,
		WithLogURL("http://example.com:3000"),
		WithHTTPClient(customHTTP),
		WithOrigin("custom-origin"),
	)
	require.NoError(t, err)
	assert.Equal(t, "http://example.com:3000", c.logURL)
	assert.Equal(t, "custom-origin", c.origin)
	assert.Same(t, customHTTP, c.http)
}

func TestNewClient_InvalidURL(t *testing.T) {
	_, v := testVerifier(t)
	_, err := NewClient(v, WithLogURL("://bad-url"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing log URL")
}

func TestFetchCheckpoint_Success(t *testing.T) {
	signer, v := testVerifier(t)

	// Create a signed checkpoint.
	cpBody := "test-log\n1\ndGVzdA==\n"
	n, err := note.Sign(&note.Note{Text: cpBody}, signer)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/checkpoint", r.URL.Path)
		w.Write(n)
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	data, err := c.FetchCheckpoint(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "test-log")
}

func TestFetchCheckpoint_ServerError(t *testing.T) {
	_, v := testVerifier(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	_, err = c.FetchCheckpoint(context.Background())
	assert.Error(t, err)
}

func TestAddEntry_Success(t *testing.T) {
	_, v := testVerifier(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/add", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "42")
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	idx, err := c.AddEntry(context.Background(), []byte(`{"artifact_id":"test"}`))
	require.NoError(t, err)
	assert.Equal(t, uint64(42), idx)
}

func TestAddEntry_Pushback(t *testing.T) {
	_, v := testVerifier(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "log is busy, retry later")
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	_, err = c.AddEntry(context.Background(), []byte(`{"artifact_id":"test"}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "busy")
}

func TestAddEntry_InvalidResponse(t *testing.T) {
	_, v := testVerifier(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "not-a-number")
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	_, err = c.AddEntry(context.Background(), []byte(`{"artifact_id":"test"}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing index")
}

func TestAddEntry_ServerError(t *testing.T) {
	_, v := testVerifier(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "validation error: artifact_id is required")
	}))
	defer ts.Close()

	c, err := NewClient(v, WithLogURL(ts.URL))
	require.NoError(t, err)

	_, err = c.AddEntry(context.Background(), []byte(`{}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestTileFetcher_ReturnsFunction(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v)
	require.NoError(t, err)

	tf := c.TileFetcher()
	assert.NotNil(t, tf)
}

func TestCheckpointFetcher_ReturnsFunction(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v)
	require.NoError(t, err)

	cf := c.CheckpointFetcher()
	assert.NotNil(t, cf)
}

func TestVerifier_ReturnsVerifier(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v)
	require.NoError(t, err)

	assert.Equal(t, v, c.Verifier())
}

func TestOrigin_DefaultsToVerifierName(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v)
	require.NoError(t, err)

	assert.Equal(t, "test-log", c.Origin())
}

func TestOrigin_WithCustomOrigin(t *testing.T) {
	_, v := testVerifier(t)
	c, err := NewClient(v, WithOrigin("custom-origin"))
	require.NoError(t, err)

	assert.Equal(t, "custom-origin", c.Origin())
}
