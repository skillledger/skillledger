package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skillledger/skillledger/internal/manifest"
)

func TestParseAndValidate_ValidManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "valid", "claude-code-skill.yaml"))
	require.NoError(t, err)

	m, validationErrors, err := manifest.ParseAndValidate(data)
	require.NoError(t, err)
	assert.Empty(t, validationErrors)
	require.NotNil(t, m)

	assert.Equal(t, 1, m.SkillLedger)
	assert.Equal(t, "com.example.code-reviewer", m.ID)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, "claude-code-skill", m.Kind)
	assert.Equal(t, "https://github.com/example/code-reviewer", m.Source.Repository)
	assert.Contains(t, m.Capabilities.Filesystem, "read")
	assert.Contains(t, m.Capabilities.Network, "outbound:*.anthropic.com")
}

func TestParseAndValidate_InvalidManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "missing-required.yaml"))
	require.NoError(t, err)

	m, validationErrors, err := manifest.ParseAndValidate(data)
	require.NoError(t, err) // Parse itself shouldn't error, just validation
	assert.Nil(t, m)
	assert.NotEmpty(t, validationErrors, "missing required fields should produce validation errors")
}

func TestParseAndValidate_InvalidYAML(t *testing.T) {
	// Use YAML with a tab in the indentation (tabs are forbidden in YAML)
	_, _, err := manifest.ParseAndValidate([]byte("key:\n\t- bad indent"))
	assert.Error(t, err, "malformed YAML should return error")
}

func TestParseAndValidate_AllKinds(t *testing.T) {
	kinds := []string{
		"claude-code-skill", "mcp-server", "openclaw-plugin",
		"anthropic-skill", "openai-tool", "codex-tool",
		"opencode", "generic",
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "valid", kind+".yaml"))
			require.NoError(t, err)

			m, validationErrors, err := manifest.ParseAndValidate(data)
			require.NoError(t, err)
			assert.Empty(t, validationErrors, "valid %s manifest should have no validation errors", kind)
			require.NotNil(t, m)
			assert.Equal(t, kind, m.Kind)
		})
	}
}
