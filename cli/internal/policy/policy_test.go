package policy_test

import (
	"context"
	"testing"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validDSLYAML = `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "Skills must not have write access"
  network:
    - deny: any("outbound")
      except: ["outbound:*.anthropic.com"]
      message: "Only Anthropic endpoints allowed"
`

const dslWithAllowlist = `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "Skills must not have write access"
publishers:
  allowlist:
    - cert-identity: "https://github.com/myorg/*"
      issuer: "https://accounts.google.com"
`

func TestLoadPolicy_ValidDSL(t *testing.T) {
	e, err := policy.LoadPolicy([]byte(validDSLYAML))
	require.NoError(t, err)
	require.NotNil(t, e)
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	_, err := policy.LoadPolicy([]byte("not valid yaml: ["))
	require.Error(t, err)
}

func TestLoadPreset_Strict(t *testing.T) {
	e, err := policy.LoadPreset("strict")
	require.NoError(t, err)
	require.NotNil(t, e)
}

func TestLoadPreset_Nonexistent(t *testing.T) {
	_, err := policy.LoadPreset("nonexistent")
	require.Error(t, err)
}

func TestEvaluateManifest_StrictDenyWrite(t *testing.T) {
	e, err := policy.LoadPreset("strict")
	require.NoError(t, err)

	caps := manifest.Capabilities{
		Filesystem: []string{"read:/home", "write:/tmp"},
	}
	result, err := policy.EvaluateManifest(context.Background(), e, caps, nil)
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
}

func TestEvaluateManifest_PermissiveAllow(t *testing.T) {
	e, err := policy.LoadPreset("permissive")
	require.NoError(t, err)

	caps := manifest.Capabilities{
		Filesystem: []string{"read:/home"},
	}
	result, err := policy.EvaluateManifest(context.Background(), e, caps, nil)
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestEvaluateInput_AllowlistMatchingPublisher(t *testing.T) {
	e, err := policy.LoadPolicy([]byte(dslWithAllowlist))
	require.NoError(t, err)

	pi := policy.PolicyInput{
		Capabilities: manifest.Capabilities{
			Filesystem: []string{"read:/home"},
		},
		SignedBy: "https://github.com/myorg/skill-builder",
		Issuer:   "https://accounts.google.com",
	}
	result, err := policy.EvaluateInput(context.Background(), e, pi)
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestEvaluateInput_AllowlistNonMatchingPublisher(t *testing.T) {
	e, err := policy.LoadPolicy([]byte(dslWithAllowlist))
	require.NoError(t, err)

	pi := policy.PolicyInput{
		Capabilities: manifest.Capabilities{
			Filesystem: []string{"read:/home"},
		},
		SignedBy: "https://github.com/otherorg/tool",
		Issuer:   "https://accounts.google.com",
	}
	result, err := policy.EvaluateInput(context.Background(), e, pi)
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
}

func TestEvaluateInput_WrongIssuerDenies(t *testing.T) {
	e, err := policy.LoadPolicy([]byte(dslWithAllowlist))
	require.NoError(t, err)

	pi := policy.PolicyInput{
		Capabilities: manifest.Capabilities{
			Filesystem: []string{"read:/home"},
		},
		SignedBy: "https://github.com/myorg/skill-builder",
		Issuer:   "https://wrong-issuer.example.com",
	}
	result, err := policy.EvaluateInput(context.Background(), e, pi)
	require.NoError(t, err)
	assert.Equal(t, "deny", result.Decision)
}

func TestEvaluateManifest_NilAttestation_NoAllowlist(t *testing.T) {
	e, err := policy.LoadPolicy([]byte(validDSLYAML))
	require.NoError(t, err)

	caps := manifest.Capabilities{
		Filesystem: []string{"read:/home"},
	}
	result, err := policy.EvaluateManifest(context.Background(), e, caps, nil)
	require.NoError(t, err)
	assert.Equal(t, "allow", result.Decision)
}

func TestListPresets(t *testing.T) {
	presets := policy.ListPresets()
	require.NotEmpty(t, presets)
	assert.Contains(t, presets, "strict")
	assert.Contains(t, presets, "moderate")
	assert.Contains(t, presets, "permissive")
}
