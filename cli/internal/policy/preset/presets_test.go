package preset_test

import (
	"context"
	"testing"

	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/skillledger/skillledger/internal/policy/preset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-policy-agent/opa/v1/rego"
)

func TestGet_Strict(t *testing.T) {
	src, err := preset.Get("strict")
	require.NoError(t, err)
	assert.NotEmpty(t, src)
	assert.Contains(t, src, "package skillledger.policy")
}

func TestGet_Moderate(t *testing.T) {
	src, err := preset.Get("moderate")
	require.NoError(t, err)
	assert.NotEmpty(t, src)
	assert.Contains(t, src, "package skillledger.policy")
}

func TestGet_Permissive(t *testing.T) {
	src, err := preset.Get("permissive")
	require.NoError(t, err)
	assert.NotEmpty(t, src)
	assert.Contains(t, src, "package skillledger.policy")
}

func TestGet_Unknown(t *testing.T) {
	_, err := preset.Get("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown preset")
}

func TestList(t *testing.T) {
	names := preset.List()
	assert.Equal(t, []string{"moderate", "permissive", "strict"}, names)
}

func TestPresets_ParseableByOPA(t *testing.T) {
	for _, name := range []string{"strict", "moderate", "permissive"} {
		t.Run(name, func(t *testing.T) {
			src, err := preset.Get(name)
			require.NoError(t, err)

			_, err = rego.New(
				rego.Query("data.skillledger.policy"),
				rego.Module("policy.rego", src),
			).PrepareForEval(context.Background())
			require.NoError(t, err, "preset %q should be parseable by OPA", name)
		})
	}
}

func capabilitiesInput(caps map[string]any) map[string]any {
	return map[string]any{
		"capabilities": caps,
		"attestation": map[string]any{
			"signed_by": "https://github.com/example-org/skill-builder",
		},
	}
}

func TestStrict_DeniesWrite(t *testing.T) {
	src, err := preset.Get("strict")
	require.NoError(t, err)

	e, err := eval.NewEvaluator(src)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), capabilitiesInput(map[string]any{
		"filesystem": []any{"write:./data"},
		"network":    []any{},
		"secrets":    []any{},
		"tools":      []any{},
	}))
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
}

func TestPermissive_AllowsAnything(t *testing.T) {
	src, err := preset.Get("permissive")
	require.NoError(t, err)

	e, err := eval.NewEvaluator(src)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), capabilitiesInput(map[string]any{
		"filesystem": []any{"write:./data", "read"},
		"network":    []any{"outbound:*.openai.com"},
		"secrets":    []any{"env:API_KEY"},
		"tools":      []any{"execute:python", "execute:bash"},
	}))
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestModerate_WarnsOnWrite(t *testing.T) {
	src, err := preset.Get("moderate")
	require.NoError(t, err)

	e, err := eval.NewEvaluator(src)
	require.NoError(t, err)

	result, err := e.Evaluate(context.Background(), capabilitiesInput(map[string]any{
		"filesystem": []any{"write:./data"},
		"network":    []any{"outbound:*.openai.com"},
		"secrets":    []any{},
		"tools":      []any{},
	}))
	require.NoError(t, err)
	assert.Equal(t, "warn", result.Decision)
}
