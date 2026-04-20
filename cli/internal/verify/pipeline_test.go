package verify

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPipeline_DefaultOptions(t *testing.T) {
	p := NewPipeline(nil, nil, nil)
	require.NotNil(t, p)
	assert.False(t, p.skipTlog, "skipTlog should default to false")
	assert.Nil(t, p.sigVerifier)
	assert.Nil(t, p.tlogLooker)
	assert.Nil(t, p.policyEval)
}

func TestNewPipeline_WithSkipTlog(t *testing.T) {
	p := NewPipeline(nil, nil, nil, WithSkipTlog(true))
	require.NotNil(t, p)
	assert.True(t, p.skipTlog, "skipTlog should be true when WithSkipTlog(true) is applied")
}

func TestVerifyInput_JSONRoundtrip(t *testing.T) {
	input := VerifyInput{
		ArtifactPath: "/path/to/artifact.tar.gz",
		BundlePath:   "/path/to/bundle.sigstore.json",
		LockfilePath: "/path/to/lockfile.json",
		ManifestPath: "/path/to/manifest.yaml",
		PolicyPreset: "strict",
		PolicyFile:   "",
		SkipTlog:     true,
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var decoded VerifyInput
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, input.ArtifactPath, decoded.ArtifactPath)
	assert.Equal(t, input.BundlePath, decoded.BundlePath)
	assert.Equal(t, input.LockfilePath, decoded.LockfilePath)
	assert.Equal(t, input.ManifestPath, decoded.ManifestPath)
	assert.Equal(t, input.PolicyPreset, decoded.PolicyPreset)
	assert.Equal(t, input.SkipTlog, decoded.SkipTlog)

	// Verify omitempty: empty PolicyFile should not appear in JSON
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, hasPolicyFile := raw["policy_file"]
	assert.False(t, hasPolicyFile, "empty PolicyFile should be omitted from JSON")
}

func TestVerifyResult_JSONRoundtrip(t *testing.T) {
	result := VerifyResult{
		Passed: false,
		Steps: []StepResult{
			{Name: "signature", Passed: true, Detail: "verified with cosign"},
			{Name: "tlog", Passed: true, Detail: "found at log index 42"},
			{Name: "policy", Passed: false, Detail: "policy evaluation failed", Error: "network access denied"},
		},
		Violations: []string{"network access to *.evil.com denied by policy"},
		Warnings:   []string{"filesystem access is broad"},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded VerifyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, result.Passed, decoded.Passed)
	assert.Len(t, decoded.Steps, 3)
	assert.Equal(t, "signature", decoded.Steps[0].Name)
	assert.True(t, decoded.Steps[0].Passed)
	assert.Equal(t, "policy", decoded.Steps[2].Name)
	assert.False(t, decoded.Steps[2].Passed)
	assert.Equal(t, "network access denied", decoded.Steps[2].Error)
	assert.Equal(t, result.Violations, decoded.Violations)
	assert.Equal(t, result.Warnings, decoded.Warnings)
}

func TestStepResult_OmitEmptyError(t *testing.T) {
	step := StepResult{Name: "signature", Passed: true, Detail: "ok"}
	data, err := json.Marshal(step)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, hasError := raw["error"]
	assert.False(t, hasError, "empty Error should be omitted from JSON")
}

func TestVerifyResult_OmitEmptyCollections(t *testing.T) {
	result := VerifyResult{Passed: true, Steps: []StepResult{}}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	_, hasViolations := raw["violations"]
	_, hasWarnings := raw["warnings"]
	assert.False(t, hasViolations, "nil Violations should be omitted from JSON")
	assert.False(t, hasWarnings, "nil Warnings should be omitted from JSON")
}
