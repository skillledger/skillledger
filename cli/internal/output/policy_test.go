package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/skillledger/skillledger/internal/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintPolicyResult_JSONMode(t *testing.T) {
	result := &output.PolicyCheckResult{
		File:       "test-manifest.yaml",
		Policy:     "strict",
		Decision:   "deny",
		Violations: []string{"filesystem write access not permitted"},
		Warnings:   nil,
	}

	var buf bytes.Buffer
	err := output.PrintPolicyResult(&buf, result, true)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, "test-manifest.yaml", decoded["file"])
	assert.Equal(t, "strict", decoded["policy"])
	assert.Equal(t, "deny", decoded["decision"])
	assert.Len(t, decoded["violations"], 1)
}

func TestPrintPolicyResult_TextAllow(t *testing.T) {
	result := &output.PolicyCheckResult{
		File:     "test-manifest.yaml",
		Policy:   "strict",
		Decision: "allow",
	}

	var buf bytes.Buffer
	err := output.PrintPolicyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "ALLOW")
	assert.Contains(t, out, "test-manifest.yaml")
	assert.Contains(t, out, "strict")
}

func TestPrintPolicyResult_TextDeny(t *testing.T) {
	result := &output.PolicyCheckResult{
		File:       "test-manifest.yaml",
		Policy:     "strict",
		Decision:   "deny",
		Violations: []string{"filesystem write access not permitted"},
	}

	var buf bytes.Buffer
	err := output.PrintPolicyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "DENY")
	assert.Contains(t, out, "filesystem write access not permitted")
}

func TestPrintPolicyResult_TextWarn(t *testing.T) {
	result := &output.PolicyCheckResult{
		File:     "test-manifest.yaml",
		Policy:   "moderate",
		Decision: "warn",
		Warnings: []string{"network access to external domains"},
	}

	var buf bytes.Buffer
	err := output.PrintPolicyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "WARN")
	assert.Contains(t, out, "network access to external domains")
}

func TestPrintCompileResult_JSONMode(t *testing.T) {
	rego := "package skillledger.policy\n\ndefault decision := \"allow\"\n"

	var buf bytes.Buffer
	err := output.PrintCompileResult(&buf, rego, true)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, rego, decoded["rego"])
}

func TestPrintCompileResult_TextMode(t *testing.T) {
	rego := "package skillledger.policy\n\ndefault decision := \"allow\"\n"

	var buf bytes.Buffer
	err := output.PrintCompileResult(&buf, rego, false)
	require.NoError(t, err)

	assert.Equal(t, rego, buf.String())
}

func TestPrintPresetList_JSONMode(t *testing.T) {
	presets := []string{"strict", "moderate", "permissive"}

	var buf bytes.Buffer
	err := output.PrintPresetList(&buf, presets, true)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)

	presetsVal, ok := decoded["presets"].([]any)
	require.True(t, ok)
	assert.Len(t, presetsVal, 3)
	assert.Equal(t, "strict", presetsVal[0])
}

func TestPrintPresetList_TextMode(t *testing.T) {
	presets := []string{"strict", "moderate", "permissive"}

	var buf bytes.Buffer
	err := output.PrintPresetList(&buf, presets, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "Available presets:")
	assert.Contains(t, out, "strict")
	assert.Contains(t, out, "moderate")
	assert.Contains(t, out, "permissive")
}
