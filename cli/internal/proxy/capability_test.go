package proxy_test

import (
	"context"
	"sync"
	"testing"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockObserver records Observe calls for testing learning mode.
type mockObserver struct {
	mu      sync.Mutex
	actions []proxy.RuntimeAction
}

func (m *mockObserver) Observe(action proxy.RuntimeAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.actions = append(m.actions, action)
}

func (m *mockObserver) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.actions)
}

func testManifestWithNetwork(hosts ...string) *manifest.Manifest {
	return &manifest.Manifest{
		SkillLedger: 1,
		ID:          "test-skill",
		Capabilities: manifest.Capabilities{
			Network: hosts,
		},
	}
}

func testManifestWithTools(tools ...string) *manifest.Manifest {
	return &manifest.Manifest{
		SkillLedger: 1,
		ID:          "test-skill",
		Capabilities: manifest.Capabilities{
			Tools: tools,
		},
	}
}

func TestRuntimeEvaluator_AllowDeclaredDestination(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "api.openai.com",
	}, "verified", "")

	assert.Empty(t, findings, "declared destination should produce no findings")
}

func TestRuntimeEvaluator_BlockUndeclaredDestination(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "")

	require.NotEmpty(t, findings, "undeclared destination should produce findings")
	found := false
	for _, f := range findings {
		if f.Scanner == "capability" && f.Decision == proxy.ActionBlock {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a block finding from capability scanner")
}

func TestRuntimeEvaluator_BlockUndeclaredTool(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithTools("read", "write"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:    "skill-a",
		ActionType: "mcp_tool_call",
		ToolName:   "exec",
	}, "verified", "")

	require.NotEmpty(t, findings, "undeclared tool should produce findings")
	found := false
	for _, f := range findings {
		if f.Scanner == "capability" && f.Decision == proxy.ActionBlock {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a block finding for undeclared tool")
}

func TestRuntimeEvaluator_AllowDeclaredTool(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithTools("read", "write"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:    "skill-a",
		ActionType: "mcp_tool_call",
		ToolName:   "read",
	}, "verified", "")

	assert.Empty(t, findings, "declared tool should produce no findings")
}

func TestRuntimeEvaluator_LearningMode(t *testing.T) {
	// No manifest for "unknown-skill"
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	observer := &mockObserver{}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, observer, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "unknown-skill",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "", "")

	assert.Empty(t, findings, "learning mode (no manifest) should produce no findings")
	assert.Equal(t, 1, observer.Count(), "observer should have been called once")
}

func TestRuntimeEvaluator_FailClosed(t *testing.T) {
	// Test with a manifest that has empty capabilities -- the strict policy
	// with default decision "deny" should produce a block finding for any action
	manifests := map[string]*manifest.Manifest{
		"skill-a": {
			SkillLedger:  1,
			ID:           "skill-a",
			Capabilities: manifest.Capabilities{},
		},
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "anything.com",
	}, "verified", "")

	require.NotEmpty(t, findings, "empty capabilities should produce deny findings")
	hasBlock := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.True(t, hasBlock, "fail-closed: expected ActionBlock finding")
}

func TestRuntimeEvaluator_ReloadPolicy(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	// Strict: undeclared destination should block
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "")
	require.NotEmpty(t, findings, "strict should produce findings for undeclared dest")
	hasBlock := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.True(t, hasBlock, "strict preset should block undeclared destination")

	// Reload to permissive
	err = re.ReloadPolicy("permissive", nil)
	require.NoError(t, err)

	// Permissive: undeclared destination should warn (not block)
	findings = re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "")
	// Permissive produces warnings, not deny
	hasBlock = false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.False(t, hasBlock, "permissive preset should not block undeclared destination")
}

func TestRuntimeEvaluator_ModeratePreset(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("moderate", manifests, config, nil, nil)
	require.NoError(t, err)

	// Moderate: undeclared destination should warn (not block)
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "")
	hasBlock := false
	hasWarn := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
		}
		if f.Decision == proxy.ActionWarn {
			hasWarn = true
		}
	}
	assert.False(t, hasBlock, "moderate should not block undeclared destinations")
	assert.True(t, hasWarn, "moderate should warn on undeclared destinations")

	// Moderate: undeclared tool should block
	findings = re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:    "skill-a",
		ActionType: "mcp_tool_call",
		ToolName:   "exec",
	}, "verified", "")
	hasBlock = false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.True(t, hasBlock, "moderate should block undeclared tools")
}

// TestBuildRuntimeInput_TrustTierVerified verifies that the trust tier is included
// in OPA input when set to "verified".
func TestBuildRuntimeInput_TrustTierVerified(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	// Verified skill accessing declared destination should be allowed.
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "api.openai.com",
	}, "verified", "")

	assert.Empty(t, findings, "verified skill with declared destination should have no findings")
}

// TestBuildRuntimeInput_TrustTierDefaultsToUnverified verifies that empty trust tier
// defaults to "unverified" (fail-closed per T-13-09).
func TestBuildRuntimeInput_TrustTierDefaultsToUnverified(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	// Use strict preset which blocks unverified non-localhost HTTP.
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	// Empty trust tier should default to "unverified" and trigger strict lockdown
	// for non-localhost destination.
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "", "") // empty trust tier

	require.NotEmpty(t, findings, "empty trust tier should default to unverified and produce findings")
	hasBlock := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.True(t, hasBlock, "unverified trust tier should block undeclared non-localhost destinations")
}

// TestEvaluate_PresetOverride verifies that a preset override selects the correct
// PreparedQuery and caches it for subsequent calls.
func TestEvaluate_PresetOverride(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	// Default preset is strict.
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	// Override to permissive: undeclared destination should warn, not block.
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "permissive")

	hasBlock := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.False(t, hasBlock, "permissive override should not block undeclared destination")

	// Call again with same override -- should use cached PreparedQuery.
	findings2 := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "evil.com",
	}, "verified", "permissive")

	hasBlock2 := false
	for _, f := range findings2 {
		if f.Decision == proxy.ActionBlock {
			hasBlock2 = true
			break
		}
	}
	assert.False(t, hasBlock2, "cached permissive override should not block")
}

// TestEvaluate_UnverifiedStrictLockdown verifies that unverified skills under strict
// preset get lockdown (block non-localhost).
func TestEvaluate_UnverifiedStrictLockdown(t *testing.T) {
	manifests := map[string]*manifest.Manifest{
		"skill-a": testManifestWithNetwork("api.openai.com"),
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("strict", manifests, config, nil, nil)
	require.NoError(t, err)

	// Unverified + strict should block non-localhost even if declared.
	findings := re.Evaluate(context.Background(), proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "api.openai.com",
	}, "unverified", "strict")

	require.NotEmpty(t, findings, "unverified skill under strict should get lockdown")
	hasBlock := false
	for _, f := range findings {
		if f.Decision == proxy.ActionBlock {
			hasBlock = true
			break
		}
	}
	assert.True(t, hasBlock, "unverified skill under strict preset should be blocked for non-localhost")
}

func BenchmarkRuntimeEval(b *testing.B) {
	caps := make([]string, 10)
	for i := range caps {
		caps[i] = "*.example" + string(rune('0'+i)) + ".com"
	}
	caps[0] = "api.openai.com" // exact match for the benchmark action

	manifests := map[string]*manifest.Manifest{
		"bench-skill": {
			SkillLedger: 1,
			ID:          "bench-skill",
			Capabilities: manifest.Capabilities{
				Network: caps,
			},
		},
	}
	config := proxy.DefaultPolicyConfig()
	re, err := proxy.NewRuntimeEvaluator("moderate", manifests, config, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	action := proxy.RuntimeAction{
		SkillID:     "bench-skill",
		ActionType:  "http_request",
		Destination: "api.openai.com",
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re.Evaluate(ctx, action, "verified", "")
	}
}
