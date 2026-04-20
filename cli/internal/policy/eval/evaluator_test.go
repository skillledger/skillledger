package eval_test

import (
	"context"
	"testing"

	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const denyAllRego = `package skillledger.policy
import rego.v1
default decision := "deny"
deny contains "all denied" if { true }
warnings := set()
`

const allowAllRego = `package skillledger.policy
import rego.v1
default decision := "allow"
deny := set()
warnings := set()
`

const warnRego = `package skillledger.policy
import rego.v1
default decision := "allow"
deny := set()
warnings contains "something warned" if { true }
decision := "warn" if { count(deny) == 0; count(warnings) > 0 }
`

const invalidRego = `package skillledger.policy
this is not valid rego at all !!!
`

func testInput() map[string]any {
	return map[string]any{
		"capabilities": map[string]any{
			"filesystem": []any{"read", "write:./data"},
			"network":    []any{"outbound:*.openai.com"},
			"secrets":    []any{"env:API_KEY"},
			"tools":      []any{"execute:python"},
		},
		"attestation": map[string]any{
			"signed_by": "https://github.com/example-org/skill-builder",
			"issuer":    "https://accounts.google.com",
		},
	}
}

func TestNewEvaluator_ValidRego(t *testing.T) {
	e, err := eval.NewEvaluator(allowAllRego)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNewEvaluator_InvalidRego(t *testing.T) {
	_, err := eval.NewEvaluator(invalidRego)
	require.Error(t, err)
}

func TestEvaluate_DenyAll(t *testing.T) {
	e, err := eval.NewEvaluator(denyAllRego)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), testInput())
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
	assert.Contains(t, result.Violations, "all denied")
}

func TestEvaluate_AllowAll(t *testing.T) {
	e, err := eval.NewEvaluator(allowAllRego)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), testInput())
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
	assert.Empty(t, result.Violations)
	assert.Empty(t, result.Warnings)
}

func TestEvaluate_WarnOnly(t *testing.T) {
	e, err := eval.NewEvaluator(warnRego)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), testInput())
	require.NoError(t, err)
	assert.Equal(t, "warn", result.Decision)
	assert.Contains(t, result.Warnings, "something warned")
}

func TestEvaluate_EmptyResultsFailClosed(t *testing.T) {
	// A Rego policy with no matching rules should fail closed
	emptyRego := `package skillledger.policy
import rego.v1
`
	e, err := eval.NewEvaluator(emptyRego)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), testInput())
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
}

func TestNewEvaluatorWithData(t *testing.T) {
	regoWithData := `package skillledger.policy
import rego.v1
default decision := "deny"
deny := set()
warnings := set()
decision := "allow" if {
    some pub in data.allowlist.publishers
    pub == input.attestation.signed_by
}
`
	data := map[string]any{
		"allowlist": map[string]any{
			"publishers": []any{
				"https://github.com/example-org/skill-builder",
			},
		},
	}

	e, err := eval.NewEvaluatorWithData(regoWithData, nil, data)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), testInput())
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}
