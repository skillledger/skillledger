package signer

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSigner_DefaultURLs(t *testing.T) {
	s := NewSigner()
	assert.Equal(t, "https://fulcio.sigstore.dev", s.fulcioURL)
	assert.Equal(t, "https://rekor.sigstore.dev", s.rekorURL)
	assert.Empty(t, s.identityToken)
}

func TestSigner_WithOptions(t *testing.T) {
	s := NewSigner(
		WithFulcioURL("https://fulcio.example.com"),
		WithRekorURL("https://rekor.example.com"),
		WithIdentityToken("test-token-123"),
	)
	assert.Equal(t, "https://fulcio.example.com", s.fulcioURL)
	assert.Equal(t, "https://rekor.example.com", s.rekorURL)
	assert.Equal(t, "test-token-123", s.identityToken)
}

func TestSigner_NoToken_Error(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "")

	s := NewSigner()
	stmt := makeTestStatement(t)

	_, err := s.Sign(stmt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no OIDC token")
}

func TestSigner_EnvToken(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "env-token-456")

	s := NewSigner()
	stmt := makeTestStatement(t)

	// Sign will fail at Fulcio (network call) but should get past token resolution
	_, err := s.Sign(stmt)
	require.Error(t, err)
	// The error should NOT be about missing token -- it should fail later at Fulcio
	assert.NotContains(t, err.Error(), "no OIDC token")
}

func TestSigner_OptionTokenOverridesEnv(t *testing.T) {
	t.Setenv("SIGSTORE_ID_TOKEN", "env-token")

	s := NewSigner(WithIdentityToken("option-token"))

	token, err := s.resolveToken()
	require.NoError(t, err)
	assert.Equal(t, "option-token", token)
}

func TestSignResult_Fields(t *testing.T) {
	// Verify SignResult struct has expected fields and they are assignable
	result := &SignResult{
		BundlePath: "/path/to/artifact.sigstore.json",
		BundleJSON: []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
		LogIndex:   42,
	}

	assert.Equal(t, "/path/to/artifact.sigstore.json", result.BundlePath)
	assert.NotEmpty(t, result.BundleJSON)
	assert.Equal(t, int64(42), result.LogIndex)
}

// makeTestStatement creates a minimal valid in-toto statement for testing.
func makeTestStatement(t *testing.T) *intoto.Statement {
	t.Helper()
	predicate, err := structpb.NewStruct(map[string]interface{}{
		"buildDefinition": map[string]interface{}{
			"buildType": "https://skillledger.in/SkillBuild/v1",
		},
	})
	require.NoError(t, err)

	return &intoto.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []*intoto.ResourceDescriptor{
			{
				Name:   "test-artifact",
				Digest: map[string]string{"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
			},
		},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate:     predicate,
	}
}
