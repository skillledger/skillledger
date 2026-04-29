package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelManager_ModelDir(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	expected := filepath.Join(baseDir, "models", DefaultModelName)
	assert.Equal(t, expected, mm.ModelDir())
}

func TestModelManager_Paths(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	modelDir := filepath.Join(baseDir, "models", DefaultModelName)
	assert.Equal(t, filepath.Join(modelDir, modelFileName), mm.ModelPath())
	assert.Equal(t, filepath.Join(modelDir, tokenizerFileName), mm.TokenizerPath())
	// ORT lib path depends on platform
	ortPath := mm.OrtLibPath()
	assert.True(t, filepath.Dir(ortPath) == modelDir, "ORT lib should be in model dir")
}

func TestModelManager_IsDownloaded_Empty(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	assert.False(t, mm.IsDownloaded(), "Should return false when no files exist")
}

func TestModelManager_IsDownloaded_PartialFiles(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Create only the model dir and model file (missing tokenizer and ORT lib)
	modelDir := mm.ModelDir()
	require.NoError(t, os.MkdirAll(modelDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(modelDir, modelFileName), []byte("fake model"), 0600))

	assert.False(t, mm.IsDownloaded(), "Should return false when only some files exist")
}

func TestModelManager_IsDownloaded_Complete(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Create all required files
	modelDir := mm.ModelDir()
	require.NoError(t, os.MkdirAll(modelDir, 0700))
	require.NoError(t, os.WriteFile(mm.ModelPath(), []byte("fake model"), 0600))
	require.NoError(t, os.WriteFile(mm.TokenizerPath(), []byte("fake tokenizer"), 0600))
	require.NoError(t, os.WriteFile(mm.OrtLibPath(), []byte("fake ort lib"), 0600))

	assert.True(t, mm.IsDownloaded(), "Should return true when all files exist")
}

func TestModelManager_Verify_NoFiles(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Set pinned checksums so Verify actually tries to check files.
	origChecksums := pinnedChecksums
	defer func() { pinnedChecksums = origChecksums }()
	pinnedChecksums = map[string]string{
		modelFileName:     "abc123",
		tokenizerFileName: "def456",
		ortLibFileName():  "789abc",
	}

	err := mm.Verify()
	assert.Error(t, err, "Verify should fail when files do not exist")
}

func TestModelManager_Verify_Mismatch(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Create model dir and all files with wrong content
	modelDir := mm.ModelDir()
	require.NoError(t, os.MkdirAll(modelDir, 0700))
	require.NoError(t, os.WriteFile(mm.ModelPath(), []byte("wrong content"), 0600))
	require.NoError(t, os.WriteFile(mm.TokenizerPath(), []byte("wrong tokenizer"), 0600))
	require.NoError(t, os.WriteFile(mm.OrtLibPath(), []byte("wrong ort"), 0600))

	// Set pinned checksums that don't match file contents.
	origChecksums := pinnedChecksums
	defer func() { pinnedChecksums = origChecksums }()
	pinnedChecksums = map[string]string{
		modelFileName:     "0000000000000000000000000000000000000000000000000000000000000000",
		tokenizerFileName: "1111111111111111111111111111111111111111111111111111111111111111",
		ortLibFileName():  "2222222222222222222222222222222222222222222222222222222222222222",
	}

	err := mm.Verify()
	assert.Error(t, err, "Verify should fail when checksums don't match")
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestModelManager_Verify_PlaceholderMode(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Ensure pinnedChecksums has placeholder values (CR-03: fail-closed).
	origChecksums := pinnedChecksums
	defer func() { pinnedChecksums = origChecksums }()
	pinnedChecksums = map[string]string{
		"model.onnx":     "PLACEHOLDER",
		"tokenizer.json": "PLACEHOLDER",
	}

	// With placeholder checksums, Verify should fail-closed (CR-03).
	err := mm.Verify()
	assert.Error(t, err, "Verify should fail-closed when checksums are PLACEHOLDER")
	assert.Contains(t, err.Error(), "no valid pinned checksum")
}

func TestModelManager_Verify_EmptyChecksums_FailClosed(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Empty pinnedChecksums should also fail-closed (CR-03).
	origChecksums := pinnedChecksums
	defer func() { pinnedChecksums = origChecksums }()
	pinnedChecksums = map[string]string{}

	// With no checksums at all, Verify should fail for any file without a pinned hash.
	err := mm.Verify()
	assert.Error(t, err, "Verify should fail-closed when no checksums exist")
}

func TestModelManager_Verify_CorrectChecksums(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// Create model dir
	modelDir := mm.ModelDir()
	require.NoError(t, os.MkdirAll(modelDir, 0700))

	// Write files and compute their actual checksums
	modelContent := []byte("test model content for verification")
	tokenizerContent := []byte("test tokenizer content for verification")
	ortContent := []byte("test ort content for verification")

	require.NoError(t, os.WriteFile(mm.ModelPath(), modelContent, 0600))
	require.NoError(t, os.WriteFile(mm.TokenizerPath(), tokenizerContent, 0600))
	require.NoError(t, os.WriteFile(mm.OrtLibPath(), ortContent, 0600))

	// Override pinnedChecksums for this test
	origChecksums := pinnedChecksums
	defer func() { pinnedChecksums = origChecksums }()

	pinnedChecksums = map[string]string{
		modelFileName:     computeSHA256(modelContent),
		tokenizerFileName: computeSHA256(tokenizerContent),
		ortLibFileName():  computeSHA256(ortContent),
	}

	err := mm.Verify()
	assert.NoError(t, err, "Verify should pass when checksums match")
}

func TestModelManager_Info_NotDownloaded(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	status, err := mm.Info()
	require.NoError(t, err)

	assert.False(t, status.Downloaded)
	assert.Equal(t, modelVersion, status.Version)
	assert.Equal(t, runtime.GOOS+"-"+runtime.GOARCH, status.Platform)
	assert.False(t, status.Verified)
}

func TestModelManager_Info_Downloaded(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	modelDir := mm.ModelDir()
	require.NoError(t, os.MkdirAll(modelDir, 0700))
	require.NoError(t, os.WriteFile(mm.ModelPath(), []byte("fake model data"), 0600))
	require.NoError(t, os.WriteFile(mm.TokenizerPath(), []byte("fake tokenizer"), 0600))
	require.NoError(t, os.WriteFile(mm.OrtLibPath(), []byte("fake ort"), 0600))

	status, err := mm.Info()
	require.NoError(t, err)

	assert.True(t, status.Downloaded)
	assert.Equal(t, mm.ModelPath(), status.ModelPath)
	assert.Equal(t, mm.TokenizerPath(), status.TokenizerPath)
	assert.Equal(t, mm.OrtLibPath(), status.OrtLibPath)
	assert.Greater(t, status.ModelSize, int64(0))
}

func TestModelManager_PlatformDetection(t *testing.T) {
	info, err := ortPlatformInfo()

	// Should succeed on supported platforms (darwin-arm64, linux-amd64, linux-arm64)
	key := runtime.GOOS + "-" + runtime.GOARCH
	switch key {
	case "darwin-arm64", "linux-amd64", "linux-arm64", "darwin-amd64":
		require.NoError(t, err, "Should support platform %s", key)
		assert.NotEmpty(t, info.URL, "URL should not be empty")
		assert.NotEmpty(t, info.FileName, "FileName should not be empty")
	default:
		// On unsupported platforms, error is expected
		assert.Error(t, err, "Should error on unsupported platform %s", key)
	}
}

func TestModelManager_ToModelInfo(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	info := mm.ToModelInfo()
	assert.Equal(t, DefaultModelName, info.Name)
	assert.Equal(t, modelVersion, info.Version)
	assert.Equal(t, mm.ModelPath(), info.ModelPath)
	assert.Equal(t, mm.TokenizerPath(), info.TokenizerPath)
	assert.Equal(t, mm.OrtLibPath(), info.OrtLibPath)
}

func TestModelManager_ModelDirPermissions(t *testing.T) {
	baseDir := t.TempDir()
	mm := NewModelManager(baseDir)

	// EnsureModelDir creates the directory with 0700
	err := mm.EnsureModelDir()
	require.NoError(t, err)

	fi, err := os.Stat(mm.ModelDir())
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	// Check permissions (on Unix systems)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
	}
}

// computeSHA256 is a test helper that computes sha256 hex digest.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
