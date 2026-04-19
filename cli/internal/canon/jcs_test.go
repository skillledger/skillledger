package canon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skillledger/skillledger/internal/canon"
)

// SPEC-01: Deterministic output
func TestCanonical_Deterministic(t *testing.T) {
	// Same logical JSON with different key ordering
	input1 := []byte(`{"b": 2, "a": 1, "c": 3}`)
	input2 := []byte(`{"a": 1, "c": 3, "b": 2}`)
	input3 := []byte(`{"c":3,"b":2,"a":1}`)

	out1, err := canon.Canonicalize(input1)
	require.NoError(t, err)
	out2, err := canon.Canonicalize(input2)
	require.NoError(t, err)
	out3, err := canon.Canonicalize(input3)
	require.NoError(t, err)

	assert.Equal(t, string(out1), string(out2), "same logical JSON must produce identical canonical output")
	assert.Equal(t, string(out1), string(out3), "same logical JSON must produce identical canonical output")
	// JCS sorts keys
	assert.Equal(t, `{"a":1,"b":2,"c":3}`, string(out1))
}

// SPEC-01: Nested objects sorted
func TestCanonical_NestedObjects(t *testing.T) {
	input := []byte(`{"z": {"b": 2, "a": 1}, "a": "first"}`)
	out, err := canon.Canonicalize(input)
	require.NoError(t, err)
	assert.Equal(t, `{"a":"first","z":{"a":1,"b":2}}`, string(out))
}

// SPEC-01: No whitespace in canonical output
func TestCanonical_NoWhitespace(t *testing.T) {
	input := []byte(`{
		"key": "value",
		"number": 42
	}`)
	out, err := canon.Canonicalize(input)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "\n", "canonical output must have no newlines")
	assert.NotContains(t, string(out), "\t", "canonical output must have no tabs")
	assert.Equal(t, `{"key":"value","number":42}`, string(out))
}

func TestCanonical_InvalidJSON(t *testing.T) {
	_, err := canon.Canonicalize([]byte("not json"))
	assert.Error(t, err, "invalid JSON must return error")
}

// SPEC-01: Manifest-shaped input produces deterministic canonical form
func TestCanonical_ManifestShaped(t *testing.T) {
	manifest1 := []byte(`{
		"capabilities": {"filesystem": ["read"]},
		"kind": "generic",
		"version": "1.0.0",
		"id": "com.example.test",
		"source": {"repository": "https://github.com/example/test"},
		"skillledger": 1
	}`)
	manifest2 := []byte(`{
		"skillledger": 1,
		"id": "com.example.test",
		"version": "1.0.0",
		"kind": "generic",
		"source": {"repository": "https://github.com/example/test"},
		"capabilities": {"filesystem": ["read"]}
	}`)

	out1, err := canon.Canonicalize(manifest1)
	require.NoError(t, err)
	out2, err := canon.Canonicalize(manifest2)
	require.NoError(t, err)

	assert.Equal(t, string(out1), string(out2), "same manifest with different field order must produce identical canonical JSON")
}
