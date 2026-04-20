package policy

import (
	"context"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/policy/allowlist"
	"github.com/skillledger/skillledger/internal/policy/eval"
)

// PolicyInput provides all fields needed for policy evaluation including
// allowlist matching. Use this instead of EvaluateManifest when issuer
// information is available (e.g., from Sigstore verification or --issuer flag).
type PolicyInput struct {
	Capabilities manifest.Capabilities
	SignedBy     string // cert-identity from signing verification
	Issuer       string // OIDC issuer from signing verification (required for allowlist matching)
}

// LoadPolicy parses DSL YAML, compiles to Rego, and returns an Evaluator.
func LoadPolicy(data []byte) (*eval.Evaluator, error) {
	return nil, nil // stub
}

// LoadPolicyFile reads a policy file and returns an Evaluator.
func LoadPolicyFile(path string) (*eval.Evaluator, error) {
	return nil, nil // stub
}

// LoadPreset loads a named preset policy and returns an Evaluator.
func LoadPreset(name string) (*eval.Evaluator, error) {
	return nil, nil // stub
}

// LoadPresetWithAllowlist loads a preset with allowlist entries.
func LoadPresetWithAllowlist(name string, entries []allowlist.Entry) (*eval.Evaluator, error) {
	return nil, nil // stub
}

// EvaluateInput evaluates a PolicyInput against a prepared Evaluator.
func EvaluateInput(ctx context.Context, e *eval.Evaluator, pi PolicyInput) (*eval.PolicyResult, error) {
	return nil, nil // stub
}

// EvaluateManifest evaluates manifest capabilities and attestation against a policy.
func EvaluateManifest(ctx context.Context, e *eval.Evaluator, caps manifest.Capabilities, att *manifest.Attestation) (*eval.PolicyResult, error) {
	return nil, nil // stub
}

// ListPresets returns all available preset names.
func ListPresets() []string {
	return nil // stub
}
