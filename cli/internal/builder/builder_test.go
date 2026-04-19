package builder_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testManifestYAML = `skillledger: 1
id: com.example.test-skill
version: "1.0.0"
kind: mcp-server
source:
  repository: https://github.com/example/test-skill
  ref: v1.0.0
capabilities:
  filesystem:
    - read
`

func writeManifest(t *testing.T, dir string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, "skillledger.yaml"), []byte(testManifestYAML), 0644)
	require.NoError(t, err)
}

func writeSourceFiles(t *testing.T, dir string) {
	t.Helper()
	srcDir := filepath.Join(dir, "src")
	require.NoError(t, os.MkdirAll(srcDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "main.py"), []byte(`print("hello")`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Test Skill"), 0644))
}

func TestBuild_ProducesArtifact(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	writeManifest(t, sourceDir)
	writeSourceFiles(t, sourceDir)

	b := builder.NewBuilder(builder.WithEpoch(time.Unix(1700000000, 0).UTC()))
	result, err := b.Build(sourceDir, outputDir)

	require.NoError(t, err)
	assert.True(t, filepath.Ext(result.ArtifactPath) == ".gz" || regexp.MustCompile(`\.skillledger\.tar\.gz$`).MatchString(result.ArtifactPath),
		"artifact path should end with .skillledger.tar.gz, got: %s", result.ArtifactPath)

	info, err := os.Stat(result.ArtifactPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}

func TestBuild_Deterministic(t *testing.T) {
	epoch := time.Unix(1700000000, 0).UTC()

	sourceDir1 := t.TempDir()
	outputDir1 := t.TempDir()
	writeManifest(t, sourceDir1)
	writeSourceFiles(t, sourceDir1)

	sourceDir2 := t.TempDir()
	outputDir2 := t.TempDir()
	writeManifest(t, sourceDir2)
	writeSourceFiles(t, sourceDir2)

	b1 := builder.NewBuilder(builder.WithEpoch(epoch))
	result1, err := b1.Build(sourceDir1, outputDir1)
	require.NoError(t, err)

	b2 := builder.NewBuilder(builder.WithEpoch(epoch))
	result2, err := b2.Build(sourceDir2, outputDir2)
	require.NoError(t, err)

	artifact1, err := os.ReadFile(result1.ArtifactPath)
	require.NoError(t, err)
	artifact2, err := os.ReadFile(result2.ArtifactPath)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(artifact1, artifact2), "artifacts should be byte-identical")
	assert.Equal(t, result1.SHA256, result2.SHA256)
	assert.Equal(t, result1.Filename, result2.Filename)
}

func TestBuild_ContentAddressed(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	writeManifest(t, sourceDir)
	writeSourceFiles(t, sourceDir)

	b := builder.NewBuilder(builder.WithEpoch(time.Unix(1700000000, 0).UTC()))
	result, err := b.Build(sourceDir, outputDir)
	require.NoError(t, err)

	// Filename: test-skill-1.0.0-<12 hex chars>.skillledger.tar.gz
	re := regexp.MustCompile(`^com\.example\.test-skill-1\.0\.0-[a-f0-9]{12}\.skillledger\.tar\.gz$`)
	assert.True(t, re.MatchString(result.Filename), "filename should match content-addressed pattern, got: %s", result.Filename)

	// SHA256 is 64 hex chars
	reHash := regexp.MustCompile(`^[a-f0-9]{64}$`)
	assert.True(t, reHash.MatchString(result.SHA256), "SHA256 should be 64 hex chars, got: %s", result.SHA256)
}

func TestBuild_GeneratesLockfile(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	writeManifest(t, sourceDir)
	writeSourceFiles(t, sourceDir)

	b := builder.NewBuilder(builder.WithEpoch(time.Unix(1700000000, 0).UTC()))
	result, err := b.Build(sourceDir, outputDir)
	require.NoError(t, err)

	assert.True(t, filepath.Base(result.LockfilePath) == "skill-lock.json")

	lf, err := builder.ReadLockfile(result.LockfilePath)
	require.NoError(t, err)

	assert.Equal(t, "com.example.test-skill", lf.ArtifactID)
	assert.Equal(t, "1.0.0", lf.Version)
	assert.Equal(t, result.SHA256, lf.SHA256)
	assert.Equal(t, result.Filename, lf.ContentAddress)
	assert.Equal(t, "https://github.com/example/test-skill", lf.Source.Repository)
	assert.Equal(t, "v1.0.0", lf.Source.Ref)
}

func TestBuild_InvalidManifest(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	// Write manifest missing required fields
	err := os.WriteFile(filepath.Join(sourceDir, "skillledger.yaml"), []byte("invalid: true\n"), 0644)
	require.NoError(t, err)

	b := builder.NewBuilder(builder.WithEpoch(time.Unix(1700000000, 0).UTC()))
	_, err = b.Build(sourceDir, outputDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "manifest")
}

func TestBuild_MissingManifest(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	b := builder.NewBuilder(builder.WithEpoch(time.Unix(1700000000, 0).UTC()))
	_, err := b.Build(sourceDir, outputDir)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading manifest")
}

func TestBuild_SourceDateEpoch(t *testing.T) {
	sourceDir := t.TempDir()
	outputDir := t.TempDir()

	writeManifest(t, sourceDir)
	writeSourceFiles(t, sourceDir)

	// Set SOURCE_DATE_EPOCH
	oldVal := os.Getenv("SOURCE_DATE_EPOCH")
	os.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	defer func() {
		if oldVal == "" {
			os.Unsetenv("SOURCE_DATE_EPOCH")
		} else {
			os.Setenv("SOURCE_DATE_EPOCH", oldVal)
		}
	}()

	b := builder.NewBuilder() // no WithEpoch -- should use SOURCE_DATE_EPOCH
	result, err := b.Build(sourceDir, outputDir)
	require.NoError(t, err)

	lf, err := builder.ReadLockfile(result.LockfilePath)
	require.NoError(t, err)

	assert.Equal(t, "2023-11-14T22:13:20Z", lf.BuiltAt)
}
