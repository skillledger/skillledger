package output_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skillledger/skillledger/internal/output"
)

func TestPrintValidationResult_TextValid(t *testing.T) {
	var buf bytes.Buffer
	result := &output.ValidationResult{
		Valid: true,
		File:  "test.yaml",
		Kind:  "mcp-server",
	}
	err := output.PrintValidationResult(&buf, result, false)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "VALID")
	assert.Contains(t, buf.String(), "test.yaml")
	assert.Contains(t, buf.String(), "mcp-server")
}

func TestPrintValidationResult_TextInvalid(t *testing.T) {
	var buf bytes.Buffer
	result := &output.ValidationResult{
		Valid: false,
		File:  "bad.yaml",
		Errors: []output.ValidationErr{
			{Path: "/id", Message: "missing required field"},
		},
	}
	err := output.PrintValidationResult(&buf, result, false)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "INVALID")
	assert.Contains(t, buf.String(), "/id")
}

func TestPrintValidationResult_JSON(t *testing.T) {
	var buf bytes.Buffer
	result := &output.ValidationResult{
		Valid: true,
		File:  "test.yaml",
		Kind:  "generic",
	}
	err := output.PrintValidationResult(&buf, result, true)
	require.NoError(t, err)

	var decoded output.ValidationResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.True(t, decoded.Valid)
	assert.Equal(t, "test.yaml", decoded.File)
	assert.Equal(t, "generic", decoded.Kind)
}
