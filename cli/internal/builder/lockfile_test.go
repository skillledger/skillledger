package builder_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/canon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testFs = afero.NewOsFs()

func newTestLockfile() *builder.Lockfile {
	return &builder.Lockfile{
		SkillLedger:    1,
		ArtifactID:     "example-skill",
		Version:        "1.0.0",
		SHA256:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		ContentAddress: "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.tar.gz",
		BuiltAt:        "2026-01-15T10:30:00Z",
		Source: builder.LockfileSource{
			Repository: "https://github.com/example/skill",
			Ref:        "v1.0.0",
			Directory:  "src/",
		},
	}
}

func TestLockfile_ContainsHash(t *testing.T) {
	lf := newTestLockfile()
	dir := t.TempDir()
	path := filepath.Join(dir, "skill-lock.json")

	require.NoError(t, builder.WriteLockfile(testFs, path, lf))

	got, err := builder.ReadLockfile(testFs, path)
	require.NoError(t, err)

	assert.Equal(t, lf.SHA256, got.SHA256)
}

func TestLockfile_ProvenanceField(t *testing.T) {
	dir := t.TempDir()

	// Empty provenance should be omitted from JSON output.
	lf := newTestLockfile()
	lf.Provenance = ""
	path1 := filepath.Join(dir, "no-prov.json")
	require.NoError(t, builder.WriteLockfile(testFs, path1, lf))

	raw, err := os.ReadFile(path1)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	_, exists := m["provenance"]
	assert.False(t, exists, "provenance key should be absent when empty")

	// Non-empty provenance should be present.
	lf.Provenance = "intoto:sha256:abc"
	path2 := filepath.Join(dir, "with-prov.json")
	require.NoError(t, builder.WriteLockfile(testFs, path2, lf))

	raw2, err := os.ReadFile(path2)
	require.NoError(t, err)

	var m2 map[string]any
	require.NoError(t, json.Unmarshal(raw2, &m2))
	_, exists2 := m2["provenance"]
	assert.True(t, exists2, "provenance key should be present when non-empty")
	assert.Equal(t, "intoto:sha256:abc", m2["provenance"])
}

func TestLockfile_LogEntryIDField(t *testing.T) {
	dir := t.TempDir()

	// Empty log_entry_id should be omitted.
	lf := newTestLockfile()
	lf.LogEntryID = ""
	path1 := filepath.Join(dir, "no-log.json")
	require.NoError(t, builder.WriteLockfile(testFs, path1, lf))

	raw, err := os.ReadFile(path1)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	_, exists := m["log_entry_id"]
	assert.False(t, exists, "log_entry_id key should be absent when empty")

	// Non-empty log_entry_id should be present.
	lf.LogEntryID = "entry-12345"
	path2 := filepath.Join(dir, "with-log.json")
	require.NoError(t, builder.WriteLockfile(testFs, path2, lf))

	raw2, err := os.ReadFile(path2)
	require.NoError(t, err)

	var m2 map[string]any
	require.NoError(t, json.Unmarshal(raw2, &m2))
	_, exists2 := m2["log_entry_id"]
	assert.True(t, exists2, "log_entry_id key should be present when non-empty")
	assert.Equal(t, "entry-12345", m2["log_entry_id"])
}

func TestLockfile_Canonical(t *testing.T) {
	lf := newTestLockfile()
	dir := t.TempDir()
	path := filepath.Join(dir, "skill-lock.json")

	require.NoError(t, builder.WriteLockfile(testFs, path, lf))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	// Strip trailing newline for canonicalization comparison.
	content := bytes.TrimRight(raw, "\n")

	recanonical, err := canon.Canonicalize(content)
	require.NoError(t, err)

	assert.Equal(t, content, recanonical, "lockfile content should already be JCS canonical")
}

func TestLockfile_Deterministic(t *testing.T) {
	lf := newTestLockfile()
	dir := t.TempDir()
	path1 := filepath.Join(dir, "lock1.json")
	path2 := filepath.Join(dir, "lock2.json")

	require.NoError(t, builder.WriteLockfile(testFs, path1, lf))
	require.NoError(t, builder.WriteLockfile(testFs, path2, lf))

	data1, err := os.ReadFile(path1)
	require.NoError(t, err)

	data2, err := os.ReadFile(path2)
	require.NoError(t, err)

	assert.Equal(t, data1, data2, "two writes of the same lockfile must produce identical bytes")
}

func TestLockfile_SourceFields(t *testing.T) {
	lf := newTestLockfile()
	dir := t.TempDir()
	path := filepath.Join(dir, "skill-lock.json")

	require.NoError(t, builder.WriteLockfile(testFs, path, lf))

	got, err := builder.ReadLockfile(testFs, path)
	require.NoError(t, err)

	assert.Equal(t, "https://github.com/example/skill", got.Source.Repository)
	assert.Equal(t, "v1.0.0", got.Source.Ref)
	assert.Equal(t, "src/", got.Source.Directory)
}

func TestLockfile_BuiltAtFormat(t *testing.T) {
	lf := newTestLockfile()
	dir := t.TempDir()
	path := filepath.Join(dir, "skill-lock.json")

	require.NoError(t, builder.WriteLockfile(testFs, path, lf))

	got, err := builder.ReadLockfile(testFs, path)
	require.NoError(t, err)

	_, parseErr := time.Parse(time.RFC3339, got.BuiltAt)
	assert.NoError(t, parseErr, "BuiltAt should be valid RFC3339 format")
}

func TestReadLockfile_RoundTrip(t *testing.T) {
	lf := newTestLockfile()
	lf.Provenance = "intoto:sha256:deadbeef"
	lf.LogEntryID = "entry-99999"

	dir := t.TempDir()
	path := filepath.Join(dir, "skill-lock.json")

	require.NoError(t, builder.WriteLockfile(testFs, path, lf))

	got, err := builder.ReadLockfile(testFs, path)
	require.NoError(t, err)

	assert.Equal(t, lf.SkillLedger, got.SkillLedger)
	assert.Equal(t, lf.ArtifactID, got.ArtifactID)
	assert.Equal(t, lf.Version, got.Version)
	assert.Equal(t, lf.SHA256, got.SHA256)
	assert.Equal(t, lf.ContentAddress, got.ContentAddress)
	assert.Equal(t, lf.BuiltAt, got.BuiltAt)
	assert.Equal(t, lf.Provenance, got.Provenance)
	assert.Equal(t, lf.LogEntryID, got.LogEntryID)
	assert.Equal(t, lf.Source.Repository, got.Source.Repository)
	assert.Equal(t, lf.Source.Ref, got.Source.Ref)
	assert.Equal(t, lf.Source.Directory, got.Source.Directory)
}
