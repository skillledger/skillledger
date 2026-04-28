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

// --- Runtime preset tests ---

func TestGetRuntime_AllPresets(t *testing.T) {
	for _, name := range []string{"strict", "moderate", "permissive"} {
		t.Run(name, func(t *testing.T) {
			src, err := preset.GetRuntime(name)
			require.NoError(t, err)
			assert.Contains(t, src, "package skillledger.runtime_policy")
		})
	}
}

func TestGetRuntime_Unknown(t *testing.T) {
	_, err := preset.GetRuntime("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown runtime preset")
}

func TestListRuntime(t *testing.T) {
	names := preset.ListRuntime()
	assert.Equal(t, []string{"moderate", "permissive", "strict"}, names)
}

func TestRuntimePreset_StrictCompiles(t *testing.T) {
	src, err := preset.GetRuntime("strict")
	require.NoError(t, err)

	ctx := context.Background()
	_, err = rego.New(
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("test.rego", src),
	).PrepareForEval(ctx)
	require.NoError(t, err, "strict runtime preset should compile without errors")
}

func TestRuntimePreset_StrictEvaluates(t *testing.T) {
	src, err := preset.GetRuntime("strict")
	require.NoError(t, err)

	ctx := context.Background()
	prepared, err := rego.New(
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("test.rego", src),
	).PrepareForEval(ctx)
	require.NoError(t, err)

	input := map[string]any{
		"action": map[string]any{
			"type":        "http_request",
			"destination": "evil.com",
			"method":      "GET",
			"tool":        "",
			"resource":    "",
		},
		"manifest": map[string]any{
			"capabilities": map[string]any{
				"network":    []any{"api.openai.com"},
				"tools":      []any{},
				"filesystem": []any{},
				"secrets":    []any{},
			},
		},
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	require.NoError(t, err)
	require.NotEmpty(t, rs)
	require.NotEmpty(t, rs[0].Expressions)

	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	require.True(t, ok, "result should be a map")

	decision, ok := val["decision"].(string)
	require.True(t, ok, "decision should be a string")
	assert.Equal(t, "deny", decision, "undeclared destination should be denied by strict preset")

	// Check deny set is non-empty
	denySet, ok := val["deny"]
	require.True(t, ok, "deny set should exist")
	switch d := denySet.(type) {
	case map[string]any:
		assert.NotEmpty(t, d, "deny set should be non-empty")
	case []any:
		assert.NotEmpty(t, d, "deny set should be non-empty")
	default:
		t.Fatalf("unexpected deny type: %T", denySet)
	}
}

func TestRuntimePreset_ModerateCompiles(t *testing.T) {
	src, err := preset.GetRuntime("moderate")
	require.NoError(t, err)

	ctx := context.Background()
	_, err = rego.New(
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("test.rego", src),
	).PrepareForEval(ctx)
	require.NoError(t, err, "moderate runtime preset should compile without errors")
}

func TestRuntimePreset_PermissiveCompiles(t *testing.T) {
	src, err := preset.GetRuntime("permissive")
	require.NoError(t, err)

	ctx := context.Background()
	_, err = rego.New(
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("test.rego", src),
	).PrepareForEval(ctx)
	require.NoError(t, err, "permissive runtime preset should compile without errors")
}

// --- Trust-tier-aware runtime preset tests ---

// evalRuntimePreset compiles a runtime preset and evaluates with given input,
// returning the full result map (decision, deny, warnings).
func evalRuntimePreset(t *testing.T, presetName string, input map[string]any) map[string]any {
	t.Helper()
	src, err := preset.GetRuntime(presetName)
	require.NoError(t, err)

	ctx := context.Background()
	prepared, err := rego.New(
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("test.rego", src),
	).PrepareForEval(ctx)
	require.NoError(t, err)

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	require.NoError(t, err)
	require.NotEmpty(t, rs)
	require.NotEmpty(t, rs[0].Expressions)

	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	require.True(t, ok, "result should be a map")
	return val
}

func runtimeInput(trustTier, actionType, destination, tool string, manifestNetwork, manifestTools []any) map[string]any {
	return map[string]any{
		"trust_tier": trustTier,
		"action": map[string]any{
			"type":        actionType,
			"destination": destination,
			"method":      "GET",
			"tool":        tool,
			"resource":    "",
		},
		"manifest": map[string]any{
			"capabilities": map[string]any{
				"network":    manifestNetwork,
				"tools":      manifestTools,
				"filesystem": []any{},
				"secrets":    []any{},
			},
		},
	}
}

func TestRuntimePreset_TrustTier_Strict_UnverifiedNonLocalhost_Deny(t *testing.T) {
	input := runtimeInput("unverified", "http_request", "evil.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "strict", input)
	assert.Equal(t, "deny", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Strict_UnverifiedLocalhost_Allow(t *testing.T) {
	input := runtimeInput("unverified", "http_request", "localhost:8080", "", []any{}, []any{})
	result := evalRuntimePreset(t, "strict", input)
	assert.Equal(t, "allow", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Strict_UnverifiedUndeclaredTool_Deny(t *testing.T) {
	input := runtimeInput("unverified", "mcp_tool_call", "", "evil_tool", []any{}, []any{"safe_tool"})
	result := evalRuntimePreset(t, "strict", input)
	assert.Equal(t, "deny", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Strict_PartialUndeclaredDest_Deny(t *testing.T) {
	input := runtimeInput("partial", "http_request", "evil.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "strict", input)
	assert.Equal(t, "deny", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Strict_VerifiedDeclared_Allow(t *testing.T) {
	input := runtimeInput("verified", "http_request", "api.openai.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "strict", input)
	assert.Equal(t, "allow", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Moderate_UnverifiedNonLocalhost_Deny(t *testing.T) {
	input := runtimeInput("unverified", "http_request", "evil.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "moderate", input)
	assert.Equal(t, "deny", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Moderate_PartialAction_Warn(t *testing.T) {
	input := runtimeInput("partial", "http_request", "api.openai.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "moderate", input)
	// Partial skills should produce warnings in moderate preset
	warnings, ok := result["warnings"]
	require.True(t, ok, "warnings should exist")
	switch w := warnings.(type) {
	case map[string]any:
		assert.NotEmpty(t, w, "partial skill should produce warnings")
	case []any:
		assert.NotEmpty(t, w, "partial skill should produce warnings")
	}
}

func TestRuntimePreset_TrustTier_Moderate_VerifiedDeclared_Allow(t *testing.T) {
	input := runtimeInput("verified", "http_request", "api.openai.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "moderate", input)
	assert.Equal(t, "allow", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_Permissive_UnverifiedNonLocalhost_Warn(t *testing.T) {
	input := runtimeInput("unverified", "http_request", "evil.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "permissive", input)
	// Permissive preset warns instead of blocking for unverified
	decision := result["decision"].(string)
	assert.Equal(t, "warn", decision, "permissive should warn, not block, for unverified skills")
}

func TestRuntimePreset_TrustTier_Permissive_Verified_Allow(t *testing.T) {
	input := runtimeInput("verified", "http_request", "api.openai.com", "", []any{"api.openai.com"}, []any{})
	result := evalRuntimePreset(t, "permissive", input)
	assert.Equal(t, "allow", result["decision"].(string))
}

func TestRuntimePreset_TrustTier_AbsentFromInput_BackwardCompat(t *testing.T) {
	// All presets should work when trust_tier is absent from input
	for _, presetName := range []string{"strict", "moderate", "permissive"} {
		t.Run(presetName, func(t *testing.T) {
			input := map[string]any{
				"action": map[string]any{
					"type":        "http_request",
					"destination": "api.openai.com",
					"method":      "GET",
					"tool":        "",
					"resource":    "",
				},
				"manifest": map[string]any{
					"capabilities": map[string]any{
						"network":    []any{"api.openai.com"},
						"tools":      []any{},
						"filesystem": []any{},
						"secrets":    []any{},
					},
				},
			}
			// Should not panic or error -- backward compat
			result := evalRuntimePreset(t, presetName, input)
			_, ok := result["decision"].(string)
			assert.True(t, ok, "decision should be a string")
		})
	}
}
