package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skillledger/skillledger/internal/schema"
	"gopkg.in/yaml.v3"
)

func yamlToJSON(t *testing.T, yamlBytes []byte) []byte {
	t.Helper()
	var raw map[string]interface{}
	require.NoError(t, yaml.Unmarshal(yamlBytes, &raw))
	jsonBytes, err := json.Marshal(raw)
	require.NoError(t, err)
	return jsonBytes
}

func TestNewValidator(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)
	require.NotNil(t, v)
}

// SPEC-03: Core fields validate
func TestCoreFields(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)

	// Valid: all required fields present
	validYAML, err := os.ReadFile(filepath.Join("..", "..", "testdata", "valid", "claude-code-skill.yaml"))
	require.NoError(t, err)
	assert.NoError(t, v.Validate(yamlToJSON(t, validYAML)))

	// Invalid: missing required fields
	invalidYAML, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "missing-required.yaml"))
	require.NoError(t, err)
	assert.Error(t, v.Validate(yamlToJSON(t, invalidYAML)))
}

// SPEC-02: Core-plus-profiles -- strict core, flexible profiles
func TestCoreProfiles(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)

	// Unknown top-level field should be REJECTED (unevaluatedProperties: false)
	unknownYAML, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "unknown-core-field.yaml"))
	require.NoError(t, err)
	err = v.Validate(yamlToJSON(t, unknownYAML))
	assert.Error(t, err, "unknown top-level fields must be rejected")

	// Unknown profile field should be ACCEPTED (additionalProperties: true on profiles, per D-04)
	forwardCompatYAML := []byte(`
skillledger: 1
id: com.example.test
version: "1.0.0"
kind: generic
source:
  repository: https://github.com/example/test
capabilities: {}
profile:
  runtime: node
  entrypoint: index.js
  future_field: "this should be accepted"
`)
	assert.NoError(t, v.Validate(yamlToJSON(t, forwardCompatYAML)), "unknown profile fields must be accepted")
}

// SPEC-02: All 8 ecosystem kinds validate
func TestAllEcosystemKinds(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)

	kinds := []string{
		"claude-code-skill", "mcp-server", "openclaw-plugin",
		"anthropic-skill", "openai-tool", "codex-tool",
		"opencode", "generic",
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "testdata", "valid", kind+".yaml"))
			require.NoError(t, err, "test fixture must exist for kind: %s", kind)
			assert.NoError(t, v.Validate(yamlToJSON(t, yamlBytes)), "valid %s manifest must pass validation", kind)
		})
	}
}

// SPEC-04: Capability schema validates scoped permissions
func TestCapabilities(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)

	// Valid scoped permissions
	validCaps := []byte(`
skillledger: 1
id: com.example.test
version: "1.0.0"
kind: generic
source:
  repository: https://github.com/example/test
capabilities:
  filesystem:
    - "read"
    - "write:./data"
  network:
    - "outbound:*.example.com"
  secrets:
    - "env:API_KEY"
    - "file:/etc/secret"
    - "vault:my/secret"
  tools:
    - "execute:bash"
`)
	assert.NoError(t, v.Validate(yamlToJSON(t, validCaps)), "valid capability scopes must pass")

	// Invalid scope pattern
	badCaps, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "bad-capability-scope.yaml"))
	require.NoError(t, err)
	assert.Error(t, v.Validate(yamlToJSON(t, badCaps)), "invalid capability scope 'delete:./data' must be rejected")
}

// SPEC-03: Bad kind and bad version format rejected
func TestInvalidKindAndVersion(t *testing.T) {
	v, err := schema.NewValidator()
	require.NoError(t, err)

	badKind, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "bad-kind.yaml"))
	require.NoError(t, err)
	assert.Error(t, v.Validate(yamlToJSON(t, badKind)), "invalid kind must be rejected")

	badVersion, err := os.ReadFile(filepath.Join("..", "..", "testdata", "invalid", "bad-version-format.yaml"))
	require.NoError(t, err)
	assert.Error(t, v.Validate(yamlToJSON(t, badVersion)), "non-SemVer version must be rejected")
}
