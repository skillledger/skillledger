package signer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_DefaultOptions(t *testing.T) {
	v := NewVerifier()
	assert.Empty(t, v.expectedIssuer)
	assert.Empty(t, v.expectedSAN)
}

func TestVerifier_WithOptions(t *testing.T) {
	v := NewVerifier(
		WithExpectedIssuer("https://accounts.google.com"),
		WithExpectedSAN("user@example.com"),
	)
	assert.Equal(t, "https://accounts.google.com", v.expectedIssuer)
	assert.Equal(t, "user@example.com", v.expectedSAN)
}

func TestVerifier_InvalidBundlePath(t *testing.T) {
	v := NewVerifier()
	_, err := v.Verify("/nonexistent/path/bundle.sigstore.json", []byte("deadbeef"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading bundle")
}

func TestVerifyResult_Fields(t *testing.T) {
	now := time.Now()
	result := &VerifyResult{
		SignerIdentity: "user@example.com",
		Issuer:         "https://accounts.google.com",
		SignedAt:        now,
	}
	assert.Equal(t, "user@example.com", result.SignerIdentity)
	assert.Equal(t, "https://accounts.google.com", result.Issuer)
	assert.Equal(t, now, result.SignedAt)
}

func TestVerifier_MultipleOptions(t *testing.T) {
	// Verify options can be applied incrementally
	v := NewVerifier(
		WithExpectedIssuer("https://token.actions.githubusercontent.com"),
	)
	assert.Equal(t, "https://token.actions.githubusercontent.com", v.expectedIssuer)
	assert.Empty(t, v.expectedSAN, "SAN should be empty when not set")
}
