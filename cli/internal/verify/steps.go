package verify

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/signer"
)

// computeAndCompareHash opens the artifact file, computes its SHA-256 digest,
// and compares it to the expected hash from the lockfile. It returns the raw
// digest bytes for use by sigstore-go verification.
func computeAndCompareHash(artifactPath, expectedSHA256 string) ([]byte, error) {
	f, err := os.Open(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("opening artifact: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("computing artifact hash: %w", err)
	}

	digest := h.Sum(nil)
	hexDigest := hex.EncodeToString(digest)

	if subtle.ConstantTimeCompare([]byte(hexDigest), []byte(expectedSHA256)) != 1 {
		return nil, fmt.Errorf("artifact hash mismatch: expected %s, got %s", expectedSHA256, hexDigest)
	}

	log.Debug().
		Str("artifact", artifactPath).
		Str("sha256", hexDigest).
		Msg("artifact hash verified")

	return digest, nil
}

// verifySignature runs the signature verification step using the injected
// SignatureVerifier. On failure, it returns a failing StepResult and the error.
// On success, it returns the signer identity for downstream policy evaluation.
func (p *Pipeline) verifySignature(ctx context.Context, bundlePath string, artifactDigest []byte) (StepResult, *signer.VerifyResult, error) {
	log.Debug().Str("bundle", bundlePath).Msg("verifying signature")

	vr, err := p.sigVerifier.Verify(bundlePath, artifactDigest)
	if err != nil {
		return StepResult{
			Name:   "signature",
			Passed: false,
			Error:  err.Error(),
		}, nil, err
	}

	detail := fmt.Sprintf("Signed by %s (issuer: %s)", vr.SignerIdentity, vr.Issuer)
	log.Debug().
		Str("identity", vr.SignerIdentity).
		Str("issuer", vr.Issuer).
		Msg("signature verification passed")

	return StepResult{
		Name:   "signature",
		Passed: true,
		Detail: detail,
	}, vr, nil
}

// verifyTlog runs the transparency log lookup step. It queries the log for
// the artifact entry and compares the SHA-256 from the log with the expected
// hash from the lockfile (T-07-05: catches substituted log entries).
func (p *Pipeline) verifyTlog(ctx context.Context, artifactID, expectedSHA256 string) (StepResult, error) {
	log.Debug().Str("artifact_id", artifactID).Msg("looking up transparency log entry")

	entry, err := p.tlogLooker.LookupEntry(ctx, artifactID)
	if err != nil {
		return StepResult{
			Name:   "transparency-log",
			Passed: false,
			Error:  err.Error(),
		}, err
	}

	// T-07-05: Compare log entry SHA-256 with lockfile to catch substitution.
	if subtle.ConstantTimeCompare([]byte(entry.SHA256), []byte(expectedSHA256)) != 1 {
		errMsg := fmt.Sprintf("SHA-256 mismatch between log entry and lockfile: log=%s, lockfile=%s", entry.SHA256, expectedSHA256)
		return StepResult{
			Name:   "transparency-log",
			Passed: false,
			Error:  errMsg,
		}, fmt.Errorf("%s", errMsg)
	}

	detail := fmt.Sprintf("Found at log index %d", entry.LogIndex)

	// B-01: Merkle inclusion proof verification (optional, requires ProofVerifier).
	if p.proofVerifier != nil {
		leafData, err := json.Marshal(map[string]string{
			"artifact_id":     artifactID,
			"sha256":          expectedSHA256,
			"content_address": "sha256-" + expectedSHA256,
		})
		if err != nil {
			return StepResult{
				Name:   "transparency-log",
				Passed: false,
				Error:  fmt.Sprintf("marshaling leaf data for proof: %s", err),
			}, fmt.Errorf("marshaling leaf data: %w", err)
		}

		if err := p.proofVerifier.VerifyInclusion(ctx, uint64(entry.LogIndex), leafData); err != nil {
			return StepResult{
				Name:   "transparency-log",
				Passed: false,
				Error:  fmt.Sprintf("Merkle proof verification failed: %s", err),
			}, err
		}
		detail = fmt.Sprintf("Found at log index %d (Merkle proof verified)", entry.LogIndex)
	}

	log.Debug().
		Int64("log_index", entry.LogIndex).
		Str("sha256", entry.SHA256).
		Msg("transparency log lookup passed")

	return StepResult{
		Name:   "transparency-log",
		Passed: true,
		Detail: detail,
	}, nil
}

// verifyPolicy evaluates the skill's declared capabilities against the loaded
// policy. The policy engine returns allow/warn/deny decisions. Warn results
// pass verification but populate warnings; deny results fail verification.
func (p *Pipeline) verifyPolicy(ctx context.Context, caps manifest.Capabilities, signerIdentity, issuer string) (StepResult, []string, []string, error) {
	log.Debug().Msg("evaluating policy")

	input := map[string]any{
		"capabilities": map[string]any{
			"filesystem": toAnySlice(caps.Filesystem),
			"network":    toAnySlice(caps.Network),
			"secrets":    toAnySlice(caps.Secrets),
			"tools":      toAnySlice(caps.Tools),
		},
		"attestation": map[string]any{
			"signed_by": signerIdentity,
			"issuer":    issuer,
		},
	}

	result, err := p.policyEval.Evaluate(ctx, input)
	if err != nil {
		return StepResult{
			Name:   "policy",
			Passed: false,
			Error:  err.Error(),
		}, nil, nil, err
	}

	switch result.Decision {
	case "allow":
		log.Debug().Msg("policy evaluation: allow")
		return StepResult{
			Name:   "policy",
			Passed: true,
			Detail: "All capability checks passed",
		}, nil, nil, nil

	case "warn":
		detail := fmt.Sprintf("Passed with %d warning(s)", len(result.Warnings))
		log.Debug().Int("warnings", len(result.Warnings)).Msg("policy evaluation: warn")
		return StepResult{
			Name:   "policy",
			Passed: true,
			Detail: detail,
		}, nil, result.Warnings, nil

	case "deny":
		detail := fmt.Sprintf("Denied with %d violation(s)", len(result.Violations))
		errMsg := strings.Join(result.Violations, "; ")
		log.Debug().Int("violations", len(result.Violations)).Msg("policy evaluation: deny")
		return StepResult{
			Name:   "policy",
			Passed: false,
			Detail: detail,
			Error:  errMsg,
		}, result.Violations, nil, fmt.Errorf("policy denied: %s", errMsg)

	default:
		// Fail-closed on unknown decision.
		errMsg := fmt.Sprintf("unknown policy decision: %s", result.Decision)
		return StepResult{
			Name:   "policy",
			Passed: false,
			Error:  errMsg,
		}, nil, nil, fmt.Errorf("%s", errMsg)
	}
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
