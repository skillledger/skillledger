package personality

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/sumdb/note"
)

// validEntry returns a LogEntry with all fields set to valid values.
func validEntry() *LogEntry {
	return &LogEntry{
		ArtifactID:     "github.com/example/skill@v1.0.0",
		SHA256:         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ContentAddress: "sha256-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		PublishedAt:    "2026-04-19T12:00:00Z",
		Publisher:      "user@example.com",
	}
}

func TestLogEntry_Validate_Valid(t *testing.T) {
	entry := validEntry()
	err := ValidateEntry(entry)
	assert.NoError(t, err)
}

func TestLogEntry_Validate_EmptyArtifactID(t *testing.T) {
	entry := validEntry()
	entry.ArtifactID = ""
	err := ValidateEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "artifact_id")
}

func TestLogEntry_Validate_InvalidSHA256(t *testing.T) {
	tests := []struct {
		name   string
		sha256 string
	}{
		{"too short", "a1b2c3"},
		{"uppercase", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"},
		{"non-hex", "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		{"too long", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2ff"},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := validEntry()
			entry.SHA256 = tc.sha256
			err := ValidateEntry(entry)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "sha256")
		})
	}
}

func TestLogEntry_Validate_MissingContentAddress(t *testing.T) {
	entry := validEntry()
	entry.ContentAddress = ""
	err := ValidateEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content_address")
}

func TestLogEntry_Validate_BadContentAddressPrefix(t *testing.T) {
	entry := validEntry()
	entry.ContentAddress = "md5-abc123"
	err := ValidateEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "content_address")
}

func TestLogEntry_Validate_EmptyPublishedAt(t *testing.T) {
	entry := validEntry()
	entry.PublishedAt = ""
	err := ValidateEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "published_at")
}

func TestLogEntry_SerializeEntry(t *testing.T) {
	entry := validEntry()
	data, err := SerializeEntry(entry)
	require.NoError(t, err)

	// Verify it produces valid JSON.
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// Verify all fields are present.
	assert.Equal(t, entry.ArtifactID, parsed["artifact_id"])
	assert.Equal(t, entry.SHA256, parsed["sha256"])
	assert.Equal(t, entry.ContentAddress, parsed["content_address"])
	assert.Equal(t, entry.PublishedAt, parsed["published_at"])
	assert.Equal(t, entry.Publisher, parsed["publisher"])
}

func TestLogEntry_SerializeEntry_Deterministic(t *testing.T) {
	entry := validEntry()
	data1, err := SerializeEntry(entry)
	require.NoError(t, err)
	data2, err := SerializeEntry(entry)
	require.NoError(t, err)
	assert.Equal(t, data1, data2, "serialization should be deterministic")
}

func TestLogEntry_FieldCount(t *testing.T) {
	// TLOG-02: entries contain only hashes and metadata, not full artifacts.
	// LogEntry should have exactly 5 fields.
	entry := validEntry()
	data, err := SerializeEntry(entry)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Len(t, parsed, 5, "LogEntry should have exactly 5 fields (hashes only, no full artifact content)")
}

// testSigner generates a fresh note.Signer for testing using note.GenerateKey.
func testSigner(t *testing.T) note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, "test-log")
	require.NoError(t, err, "generating test signing key")
	signer, err := note.NewSigner(skey)
	require.NoError(t, err, "creating signer from generated key")
	return signer
}

func TestPersonality_DefaultOptions(t *testing.T) {
	p := &Personality{
		storagePath:        "/data/tlog",
		batchMaxSize:       256,
		batchMaxAge:        250000000, // 250ms
		checkpointInterval: 10000000000, // 10s
		pushbackMax:        4096,
	}
	assert.Equal(t, "/data/tlog", p.StoragePath())
	assert.Equal(t, uint(256), p.batchMaxSize)
	assert.Equal(t, uint(4096), p.pushbackMax)
}

func TestPersonality_WithOptions(t *testing.T) {
	p := &Personality{
		storagePath:  "/data/tlog",
		batchMaxSize: 256,
		pushbackMax:  4096,
	}
	WithStoragePath("/custom/path")(p)
	WithBatchSize(512)(p)
	WithPushbackMaxEntries(8192)(p)

	assert.Equal(t, "/custom/path", p.StoragePath())
	assert.Equal(t, uint(512), p.batchMaxSize)
	assert.Equal(t, uint(8192), p.pushbackMax)
}

func TestPersonality_New_WithTempDir(t *testing.T) {
	signer := testSigner(t)
	ctx := context.Background()
	tmpDir := t.TempDir()

	p, err := New(ctx, signer, WithStoragePath(tmpDir))
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, tmpDir, p.StoragePath())

	// Shutdown cleanly.
	err = p.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestHandleAdd_InvalidJSON(t *testing.T) {
	signer := testSigner(t)
	ctx := context.Background()
	tmpDir := t.TempDir()

	p, err := New(ctx, signer, WithStoragePath(tmpDir))
	require.NoError(t, err)
	defer p.Shutdown(ctx)

	req := httptest.NewRequest(http.MethodPost, "/add", strings.NewReader("{invalid json"))
	w := httptest.NewRecorder()
	p.HandleAdd(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid JSON")
}

func TestHandleAdd_ValidationFails(t *testing.T) {
	signer := testSigner(t)
	ctx := context.Background()
	tmpDir := t.TempDir()

	p, err := New(ctx, signer, WithStoragePath(tmpDir))
	require.NoError(t, err)
	defer p.Shutdown(ctx)

	// Entry with empty ArtifactID fails validation.
	entry := validEntry()
	entry.ArtifactID = ""
	body, _ := json.Marshal(entry)

	req := httptest.NewRequest(http.MethodPost, "/add", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.HandleAdd(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "validation error")
}

func TestHandleAdd_Success(t *testing.T) {
	signer := testSigner(t)
	ctx := context.Background()
	tmpDir := t.TempDir()

	p, err := New(ctx, signer, WithStoragePath(tmpDir))
	require.NoError(t, err)
	defer p.Shutdown(ctx)

	entry := validEntry()
	body, _ := json.Marshal(entry)

	req := httptest.NewRequest(http.MethodPost, "/add", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.HandleAdd(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "0", w.Body.String(), "first entry should get index 0")
}
