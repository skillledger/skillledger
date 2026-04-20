package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/skillledger/skillledger/internal/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintVerifyResult_JSONMode_Pass(t *testing.T) {
	result := &output.VerifyCheckResult{
		Artifact: "/tmp/skill.skillledger.tar.gz",
		Passed:   true,
		Steps: []output.VerifyStepOutput{
			{Name: "hash-check", Passed: true, Detail: "SHA-256 matches lockfile"},
			{Name: "signature", Passed: true, Detail: "Signed by user@example.com (issuer: https://accounts.google.com)"},
			{Name: "tlog", Passed: true, Detail: "Found in transparency log at index 42"},
			{Name: "policy", Passed: true, Detail: "moderate: allow"},
		},
	}

	var buf bytes.Buffer
	err := output.PrintVerifyResult(&buf, result, true)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, "/tmp/skill.skillledger.tar.gz", decoded["artifact"])
	assert.Equal(t, true, decoded["passed"])
	steps, ok := decoded["steps"].([]any)
	require.True(t, ok)
	assert.Len(t, steps, 4)
	// Violations and warnings should be absent (omitempty)
	_, hasViolations := decoded["violations"]
	assert.False(t, hasViolations)
	_, hasWarnings := decoded["warnings"]
	assert.False(t, hasWarnings)
}

func TestPrintVerifyResult_JSONMode_Fail(t *testing.T) {
	result := &output.VerifyCheckResult{
		Artifact: "/tmp/skill.skillledger.tar.gz",
		Passed:   false,
		Steps: []output.VerifyStepOutput{
			{Name: "hash-check", Passed: true, Detail: "SHA-256 matches lockfile"},
			{Name: "signature", Passed: false, Error: "bundle verification failed: certificate expired"},
		},
		Violations: []string{"signature verification failed"},
	}

	var buf bytes.Buffer
	err := output.PrintVerifyResult(&buf, result, true)
	require.NoError(t, err)

	var decoded map[string]any
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)

	assert.Equal(t, false, decoded["passed"])
	violations, ok := decoded["violations"].([]any)
	require.True(t, ok)
	assert.Len(t, violations, 1)
	assert.Equal(t, "signature verification failed", violations[0])
}

func TestPrintVerifyResult_TextMode_Pass(t *testing.T) {
	result := &output.VerifyCheckResult{
		Artifact: "/tmp/skill.skillledger.tar.gz",
		Passed:   true,
		Steps: []output.VerifyStepOutput{
			{Name: "hash-check", Passed: true, Detail: "SHA-256 matches lockfile"},
			{Name: "signature", Passed: true, Detail: "Signed by user@example.com"},
			{Name: "policy", Passed: true, Detail: "moderate: allow"},
		},
	}

	var buf bytes.Buffer
	err := output.PrintVerifyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "PASS")
	assert.Contains(t, out, "/tmp/skill.skillledger.tar.gz")
	assert.Contains(t, out, "hash-check")
	assert.Contains(t, out, "signature")
}

func TestPrintVerifyResult_TextMode_Fail(t *testing.T) {
	result := &output.VerifyCheckResult{
		Artifact: "/tmp/skill.skillledger.tar.gz",
		Passed:   false,
		Steps: []output.VerifyStepOutput{
			{Name: "hash-check", Passed: true, Detail: "SHA-256 matches lockfile"},
			{Name: "signature", Passed: false, Error: "bundle verification failed"},
		},
		Violations: []string{"filesystem write access not permitted"},
	}

	var buf bytes.Buffer
	err := output.PrintVerifyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "FAIL")
	assert.Contains(t, out, "Violations:")
	assert.Contains(t, out, "filesystem write access not permitted")
}

func TestPrintVerifyResult_TextMode_Warn(t *testing.T) {
	result := &output.VerifyCheckResult{
		Artifact: "/tmp/skill.skillledger.tar.gz",
		Passed:   true, // warnings do not cause failure
		Steps: []output.VerifyStepOutput{
			{Name: "hash-check", Passed: true, Detail: "SHA-256 matches lockfile"},
			{Name: "signature", Passed: true, Detail: "Signed by user@example.com"},
			{Name: "policy", Passed: true, Detail: "moderate: allow with warnings"},
		},
		Warnings: []string{"network access to external domains"},
	}

	var buf bytes.Buffer
	err := output.PrintVerifyResult(&buf, result, false)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "PASS") // warnings don't fail
	assert.Contains(t, out, "Warnings:")
	assert.Contains(t, out, "network access to external domains")
}
