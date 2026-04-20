package policy

import (
	"context"
	"fmt"
	"os"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/policy/allowlist"
	"github.com/skillledger/skillledger/internal/policy/dsl"
	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/skillledger/skillledger/internal/policy/preset"
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
	p, err := dsl.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	regoSrc, err := dsl.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("compiling policy: %w", err)
	}

	// Convert DSL allowlist entries to allowlist package entries.
	entries := make([]allowlist.Entry, len(p.Publishers.Allowlist))
	for i, ae := range p.Publishers.Allowlist {
		entries[i] = allowlist.Entry{
			CertIdentity: ae.CertIdentity,
			Issuer:       ae.Issuer,
		}
	}

	al := allowlist.Load(entries)
	if !al.IsEmpty() {
		modules := map[string]string{
			"allowlist.rego": allowlist.AllowlistRego,
		}
		return eval.NewEvaluatorWithData(regoSrc, modules, al.ToRegoData())
	}

	return eval.NewEvaluator(regoSrc)
}

// LoadPolicyFile reads a policy file and returns an Evaluator.
func LoadPolicyFile(path string) (*eval.Evaluator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return LoadPolicy(data)
}

// LoadPreset loads a named preset policy and returns an Evaluator.
func LoadPreset(name string) (*eval.Evaluator, error) {
	regoSrc, err := preset.Get(name)
	if err != nil {
		return nil, fmt.Errorf("loading preset: %w", err)
	}
	return eval.NewEvaluator(regoSrc)
}

// LoadPresetWithAllowlist loads a preset with allowlist entries.
func LoadPresetWithAllowlist(name string, entries []allowlist.Entry) (*eval.Evaluator, error) {
	regoSrc, err := preset.Get(name)
	if err != nil {
		return nil, fmt.Errorf("loading preset: %w", err)
	}

	al := allowlist.Load(entries)
	modules := map[string]string{
		"allowlist.rego": allowlist.AllowlistRego,
	}
	return eval.NewEvaluatorWithData(regoSrc, modules, al.ToRegoData())
}

// EvaluateInput evaluates a PolicyInput against a prepared Evaluator.
// This is the PRIMARY evaluation function that passes both SignedBy and Issuer to OPA.
func EvaluateInput(ctx context.Context, e *eval.Evaluator, pi PolicyInput) (*eval.PolicyResult, error) {
	input := map[string]any{
		"capabilities": map[string]any{
			"filesystem": toAnySlice(pi.Capabilities.Filesystem),
			"network":    toAnySlice(pi.Capabilities.Network),
			"secrets":    toAnySlice(pi.Capabilities.Secrets),
			"tools":      toAnySlice(pi.Capabilities.Tools),
		},
		"attestation": map[string]any{
			"signed_by": pi.SignedBy,
			"issuer":    pi.Issuer,
		},
	}
	return e.Evaluate(ctx, input)
}

// EvaluateManifest evaluates manifest capabilities and attestation against a policy.
// WARNING: manifest.Attestation has no Issuer field, so allowlist entries requiring
// a specific issuer will NOT match via this function. Callers needing allowlist
// support MUST use EvaluateInput instead.
func EvaluateManifest(ctx context.Context, e *eval.Evaluator, caps manifest.Capabilities, att *manifest.Attestation) (*eval.PolicyResult, error) {
	pi := PolicyInput{Capabilities: caps}
	if att != nil {
		pi.SignedBy = att.SignedBy
		// NOTE: att has no Issuer field -- issuer will be empty string.
		// Allowlist entries with non-empty issuer will NOT match.
	}
	return EvaluateInput(ctx, e, pi)
}

// ListPresets returns all available preset names.
func ListPresets() []string {
	return preset.List()
}

// toAnySlice converts []string to []any for OPA input.
func toAnySlice(ss []string) []any {
	if ss == nil {
		return []any{}
	}
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}
