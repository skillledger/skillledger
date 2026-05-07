// Package verify implements the SkillLedger install-time verification pipeline.
// It orchestrates signature verification, transparency log lookup, and policy
// evaluation to determine whether a skill artifact should be trusted.
package verify

import (
	"context"

	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/skillledger/skillledger/internal/signer"
	"github.com/skillledger/skillledger/internal/tlog"
)

// SignatureVerifier verifies a Sigstore bundle against an artifact digest.
type SignatureVerifier interface {
	Verify(bundlePath string, artifactDigest []byte) (*signer.VerifyResult, error)
}

// TlogLooker queries the transparency log for an artifact entry.
type TlogLooker interface {
	LookupEntry(ctx context.Context, artifactID string) (*tlog.LookupResponse, error)
}

// PolicyEvaluator evaluates a skill's capabilities against a policy.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input map[string]any) (*eval.PolicyResult, error)
}

// VerifyInput holds the inputs for a verification run.
type VerifyInput struct {
	ArtifactPath string `json:"artifact_path"`
	BundlePath   string `json:"bundle_path,omitempty"`
	LockfilePath string `json:"lockfile_path,omitempty"`
	ManifestPath string `json:"manifest_path,omitempty"`
	PolicyPreset string `json:"policy_preset,omitempty"`
	PolicyFile   string `json:"policy_file,omitempty"`
	SkipTlog     bool   `json:"skip_tlog,omitempty"`
}

// StepResult records the outcome of a single verification step.
type StepResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	Error  string `json:"error,omitempty"`
}

// VerifyResult is the aggregate result of all verification steps.
type VerifyResult struct {
	Passed     bool         `json:"passed"`
	Steps      []StepResult `json:"steps"`
	Violations []string     `json:"violations,omitempty"`
	Warnings   []string     `json:"warnings,omitempty"`
}

// Pipeline orchestrates the verification steps: signature check, transparency
// log lookup, and policy evaluation. Dependencies are injected via interfaces.
type Pipeline struct {
	sigVerifier   SignatureVerifier
	tlogLooker    TlogLooker
	policyEval    PolicyEvaluator
	skipTlog      bool
	proofVerifier *tlog.ProofVerifier
}

// PipelineOption configures the Pipeline.
type PipelineOption func(*Pipeline)

// WithSkipTlog configures whether to skip the transparency log lookup step.
func WithSkipTlog(skip bool) PipelineOption {
	return func(p *Pipeline) { p.skipTlog = skip }
}

// WithProofVerifier configures an optional Merkle inclusion proof verifier (B-01).
// When set, the tlog step will cryptographically verify that the entry is
// included in the log's Merkle tree, rather than trusting server-asserted values.
func WithProofVerifier(pv *tlog.ProofVerifier) PipelineOption {
	return func(p *Pipeline) { p.proofVerifier = pv }
}

// NewPipeline creates a verification pipeline with the given dependencies
// and options. All three dependencies must be provided; use nil-safe mocks
// for testing individual steps.
func NewPipeline(sv SignatureVerifier, tl TlogLooker, pe PolicyEvaluator, opts ...PipelineOption) *Pipeline {
	p := &Pipeline{
		sigVerifier: sv,
		tlogLooker:  tl,
		policyEval:  pe,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}
