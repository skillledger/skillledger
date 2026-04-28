package proxy_test

import (
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicyConfig_Valid(t *testing.T) {
	yaml := []byte(`
preset: strict
response_actions:
  secret_exfil: block
  ioc_match: warn
  capability_violation: log
`)
	pc, err := proxy.LoadPolicyConfig(yaml)
	require.NoError(t, err)
	assert.Equal(t, "strict", pc.Preset)
	assert.Equal(t, "block", pc.ResponseActions["secret_exfil"])
	assert.Equal(t, "warn", pc.ResponseActions["ioc_match"])
	assert.Equal(t, "log", pc.ResponseActions["capability_violation"])
}

func TestLoadPolicyConfig_InvalidPreset(t *testing.T) {
	yaml := []byte(`preset: unknown`)
	_, err := proxy.LoadPolicyConfig(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid preset")
}

func TestLoadPolicyConfig_InvalidAction(t *testing.T) {
	yaml := []byte(`
preset: strict
response_actions:
  secret_exfil: destroy
`)
	_, err := proxy.LoadPolicyConfig(yaml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid response action")
}

func TestDefaultPolicyConfig(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	assert.Equal(t, "moderate", pc.Preset)

	expectedKeys := []string{
		"secret_exfil", "ioc_match", "undeclared_destination",
		"undeclared_tool", "capability_violation", "dns_exfil", "slow_drip",
		// Phase 12: MCP protection violation types.
		"pin_change_midsession", "pin_change_between", "prompt_injection",
	}
	for _, key := range expectedKeys {
		_, ok := pc.ResponseActions[key]
		assert.True(t, ok, "default config should have key: %s", key)
	}
	assert.Len(t, pc.ResponseActions, 10)
}

func TestMergePolicyConfigs(t *testing.T) {
	base := proxy.DefaultPolicyConfig()
	override := &proxy.PolicyConfig{
		Preset: "strict",
		ResponseActions: map[string]string{
			"secret_exfil": "block",
		},
	}

	result := proxy.MergePolicyConfigs(base, override)

	assert.Equal(t, "strict", result.Preset, "override preset should win")
	assert.Equal(t, "block", result.ResponseActions["secret_exfil"], "override action should win")
	// Verify other defaults are preserved
	assert.Equal(t, "block", result.ResponseActions["ioc_match"], "non-overridden default should be preserved")
	assert.Equal(t, "warn", result.ResponseActions["undeclared_destination"], "non-overridden default should be preserved")
}

func TestActionFor_Known(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	assert.Equal(t, proxy.ActionBlock, pc.ActionFor("ioc_match"))
	assert.Equal(t, proxy.ActionWarn, pc.ActionFor("secret_exfil"))
	assert.Equal(t, proxy.ActionLog, pc.ActionFor("slow_drip"))
}

func TestActionFor_Unknown(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	// Fail-closed: unknown violation type returns ActionBlock
	assert.Equal(t, proxy.ActionBlock, pc.ActionFor("nonexistent_violation"))
}

func TestActionFor_Phase12ViolationTypes(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	// Mid-session rug-pull: always block (CONTEXT.md: no warn option).
	assert.Equal(t, proxy.ActionBlock, pc.ActionFor("pin_change_midsession"))
	// Between-session change: warn by default.
	assert.Equal(t, proxy.ActionWarn, pc.ActionFor("pin_change_between"))
	// Prompt injection: warn-only default (CONTEXT.md).
	assert.Equal(t, proxy.ActionWarn, pc.ActionFor("prompt_injection"))
}

// --- Provenance tier-to-preset mapping tests ---

func TestLoadPolicyConfig_WithProvenance(t *testing.T) {
	yamlData := []byte(`
preset: moderate
provenance:
  verified: moderate
  partial: strict
  unverified: block_all
response_actions:
  secret_exfil: warn
`)
	pc, err := proxy.LoadPolicyConfig(yamlData)
	require.NoError(t, err)
	assert.Equal(t, "moderate", pc.Preset)
	assert.Equal(t, "moderate", pc.Provenance["verified"])
	assert.Equal(t, "strict", pc.Provenance["partial"])
	assert.Equal(t, "block_all", pc.Provenance["unverified"])
	assert.Equal(t, "warn", pc.ResponseActions["secret_exfil"])
}

func TestLoadPolicyConfig_InvalidProvenancePreset(t *testing.T) {
	yamlData := []byte(`
preset: moderate
provenance:
  verified: nonexistent
`)
	_, err := proxy.LoadPolicyConfig(yamlData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid provenance preset")
}

func TestLoadPolicyConfig_InvalidTierName(t *testing.T) {
	yamlData := []byte(`
preset: moderate
provenance:
  unknown_tier: strict
`)
	_, err := proxy.LoadPolicyConfig(yamlData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trust tier")
}

func TestProvenancePresetFor_Defaults(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	assert.Equal(t, "moderate", pc.ProvenancePresetFor("verified"))
	assert.Equal(t, "strict", pc.ProvenancePresetFor("partial"))
	assert.Equal(t, "strict", pc.ProvenancePresetFor("unverified"))
}

func TestProvenancePresetFor_CustomMapping(t *testing.T) {
	yamlData := []byte(`
preset: moderate
provenance:
  verified: permissive
  partial: moderate
  unverified: strict
`)
	pc, err := proxy.LoadPolicyConfig(yamlData)
	require.NoError(t, err)
	assert.Equal(t, "permissive", pc.ProvenancePresetFor("verified"))
	assert.Equal(t, "moderate", pc.ProvenancePresetFor("partial"))
	assert.Equal(t, "strict", pc.ProvenancePresetFor("unverified"))
}

func TestProvenancePresetFor_BlockAll(t *testing.T) {
	yamlData := []byte(`
preset: moderate
provenance:
  unverified: block_all
`)
	pc, err := proxy.LoadPolicyConfig(yamlData)
	require.NoError(t, err)
	assert.Equal(t, "block_all", pc.ProvenancePresetFor("unverified"))
	// Non-configured tiers fall back to defaults
	assert.Equal(t, "moderate", pc.ProvenancePresetFor("verified"))
	assert.Equal(t, "strict", pc.ProvenancePresetFor("partial"))
}

func TestMergePolicyConfigs_Provenance(t *testing.T) {
	base := &proxy.PolicyConfig{
		Preset: "moderate",
		ResponseActions: map[string]string{
			"secret_exfil": "warn",
		},
		Provenance: map[string]string{
			"verified":   "moderate",
			"partial":    "strict",
			"unverified": "strict",
		},
	}
	override := &proxy.PolicyConfig{
		Provenance: map[string]string{
			"unverified": "block_all",
		},
	}

	result := proxy.MergePolicyConfigs(base, override)
	assert.Equal(t, "moderate", result.Provenance["verified"], "non-overridden provenance should be preserved")
	assert.Equal(t, "strict", result.Provenance["partial"], "non-overridden provenance should be preserved")
	assert.Equal(t, "block_all", result.Provenance["unverified"], "overridden provenance should win")
}

func TestDefaultPolicyConfig_NilProvenance(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	assert.Nil(t, pc.Provenance, "default config should have nil Provenance")
}

func TestLoadPolicyConfig_WithoutProvenance_StillWorks(t *testing.T) {
	yamlData := []byte(`
preset: strict
response_actions:
  secret_exfil: block
`)
	pc, err := proxy.LoadPolicyConfig(yamlData)
	require.NoError(t, err)
	assert.Equal(t, "strict", pc.Preset)
	assert.Nil(t, pc.Provenance)
	// ProvenancePresetFor should still return defaults
	assert.Equal(t, "moderate", pc.ProvenancePresetFor("verified"))
	assert.Equal(t, "strict", pc.ProvenancePresetFor("unverified"))
}

func TestProvenancePresetFor_UnknownTier_DefaultsToStrict(t *testing.T) {
	pc := proxy.DefaultPolicyConfig()
	assert.Equal(t, "strict", pc.ProvenancePresetFor("unknown"))
}
