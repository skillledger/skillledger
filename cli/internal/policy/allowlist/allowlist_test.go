package allowlist_test

import (
	"context"
	"testing"

	"github.com/skillledger/skillledger/internal/policy/allowlist"
	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_CreatesAllowlistWithCorrectCount(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
		{CertIdentity: "https://github.com/other/*", Issuer: "https://accounts.google.com"},
	}
	al := allowlist.Load(entries)
	require.NotNil(t, al)
	assert.False(t, al.IsEmpty())
}

func TestToRegoData_ConvertsEntriesToOPAFormat(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
	}
	al := allowlist.Load(entries)
	require.NotNil(t, al)

	data := al.ToRegoData()
	require.NotNil(t, data)

	publishers, ok := data["publishers"].(map[string]any)
	require.True(t, ok, "expected publishers key")

	list, ok := publishers["allowlist"].([]any)
	require.True(t, ok, "expected allowlist key")
	assert.Len(t, list, 1)

	entry, ok := list[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://github.com/myorg/*", entry["cert_identity"])
	assert.Equal(t, "https://accounts.google.com", entry["issuer"])
}

// Helper: minimal policy Rego that defines decision logic for testing allowlist
const minimalPolicyRego = `package skillledger.policy
import rego.v1
default decision := "allow"
decision := "deny" if count(deny) > 0
`

func newAllowlistEvaluator(t *testing.T, entries []allowlist.Entry) *eval.Evaluator {
	t.Helper()
	al := allowlist.Load(entries)
	require.NotNil(t, al)

	modules := map[string]string{
		"allowlist.rego": allowlist.AllowlistRego,
	}
	e, err := eval.NewEvaluatorWithData(minimalPolicyRego, modules, al.ToRegoData())
	require.NoError(t, err)
	return e
}

func TestAllowlistRego_MatchingGlobAllows(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
	}
	e := newAllowlistEvaluator(t, entries)

	input := map[string]any{
		"attestation": map[string]any{
			"signed_by": "https://github.com/myorg/skill-builder",
			"issuer":    "https://accounts.google.com",
		},
	}
	result, err := e.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestAllowlistRego_NonMatchingIdentityDenies(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
	}
	e := newAllowlistEvaluator(t, entries)

	input := map[string]any{
		"attestation": map[string]any{
			"signed_by": "https://github.com/otherorg/tool",
			"issuer":    "https://accounts.google.com",
		},
	}
	result, err := e.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
	assert.Contains(t, result.Violations, "publisher not in allowlist")
}

func TestAllowlistRego_EmptyAllowlistAllows(t *testing.T) {
	entries := []allowlist.Entry{}
	e := newAllowlistEvaluator(t, entries)

	input := map[string]any{
		"attestation": map[string]any{
			"signed_by": "anyone",
			"issuer":    "any-issuer",
		},
	}
	result, err := e.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestAllowlistRego_NonEmptyAllowlistMissingAttestationDenies(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
	}
	e := newAllowlistEvaluator(t, entries)

	input := map[string]any{
		"attestation": map[string]any{
			"signed_by": "",
			"issuer":    "",
		},
	}
	result, err := e.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
	assert.Contains(t, result.Violations, "publisher not in allowlist")
}

func TestAllowlistRego_GlobPatternMatching(t *testing.T) {
	entries := []allowlist.Entry{
		{CertIdentity: "https://github.com/myorg/*", Issuer: "https://accounts.google.com"},
	}
	e := newAllowlistEvaluator(t, entries)

	// Should match
	input1 := map[string]any{
		"attestation": map[string]any{
			"signed_by": "https://github.com/myorg/skill-builder",
			"issuer":    "https://accounts.google.com",
		},
	}
	result1, err := e.Evaluate(context.Background(), input1)
	require.NoError(t, err)
	assert.Equal(t, "allow", result1.Decision)

	// Should NOT match - different org
	input2 := map[string]any{
		"attestation": map[string]any{
			"signed_by": "https://github.com/otherorg/tool",
			"issuer":    "https://accounts.google.com",
		},
	}
	result2, err := e.Evaluate(context.Background(), input2)
	require.NoError(t, err)
	assert.Equal(t, "deny", result2.Decision)
}
