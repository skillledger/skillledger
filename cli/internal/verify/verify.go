package verify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/manifest"
)

// maxManifestSize is the maximum size of a manifest file in bytes (1MB).
// Applied before parsing to prevent denial of service (T-07-07).
const maxManifestSize = 1 << 20

// Verify runs the full verification pipeline: hash check, signature verification,
// transparency log lookup, and policy evaluation. It stops on the first hard
// failure (fail-closed per VRFY-02). Signature failure prevents policy evaluation
// (T-07-06) because the signer identity would be untrusted.
func (p *Pipeline) Verify(ctx context.Context, input VerifyInput) (*VerifyResult, error) {
	log.Info().Str("artifact", input.ArtifactPath).Msg("starting verification")

	result := &VerifyResult{Passed: true}

	// --- Resolve default paths ---
	bundlePath := input.BundlePath
	if bundlePath == "" {
		bundlePath = input.ArtifactPath + ".sigstore.json"
	}

	lockfilePath := input.LockfilePath
	if lockfilePath == "" {
		lockfilePath = filepath.Join(filepath.Dir(filepath.Dir(input.ArtifactPath)), "skill-lock.json")
	}

	manifestPath := input.ManifestPath
	if manifestPath == "" {
		manifestPath = filepath.Join(filepath.Dir(filepath.Dir(input.ArtifactPath)), "skillledger.yaml")
	}

	// --- Read lockfile (required -- fail-closed without it) ---
	lf, err := builder.ReadLockfile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	// --- Step 0: Hash verification (T-07-04) ---
	digest, err := computeAndCompareHash(input.ArtifactPath, lf.SHA256)
	if err != nil {
		result.Passed = false
		result.Steps = append(result.Steps, StepResult{
			Name:   "hash-check",
			Passed: false,
			Error:  err.Error(),
		})
		log.Info().Bool("passed", false).Msg("verification complete")
		return result, nil
	}
	result.Steps = append(result.Steps, StepResult{
		Name:   "hash-check",
		Passed: true,
		Detail: fmt.Sprintf("SHA-256 matches lockfile: %s", lf.SHA256),
	})

	// --- Step 1: Signature verification (T-07-06: must pass before policy) ---
	sigStep, sigResult, err := p.verifySignature(ctx, bundlePath, digest)
	result.Steps = append(result.Steps, sigStep)
	if err != nil {
		result.Passed = false
		log.Info().Bool("passed", false).Msg("verification complete")
		return result, nil
	}

	// --- Step 2: Transparency log lookup (skippable) ---
	if !p.skipTlog {
		tlogStep, err := p.verifyTlog(ctx, lf.ArtifactID, lf.SHA256)
		result.Steps = append(result.Steps, tlogStep)
		if err != nil {
			result.Passed = false
			log.Info().Bool("passed", false).Msg("verification complete")
			return result, nil
		}
	}

	// --- Step 3: Policy evaluation ---
	// T-07-07: enforce manifest size limit before parsing.
	manifestData, err := readFileLimited(manifestPath, maxManifestSize)
	if err != nil {
		result.Passed = false
		result.Steps = append(result.Steps, StepResult{
			Name:   "policy",
			Passed: false,
			Error:  fmt.Sprintf("reading manifest: %s", err),
		})
		log.Info().Bool("passed", false).Msg("verification complete")
		return result, nil
	}

	m, validationErrors, err := manifest.ParseAndValidate(manifestData)
	if err != nil {
		result.Passed = false
		result.Steps = append(result.Steps, StepResult{
			Name:   "policy",
			Passed: false,
			Error:  fmt.Sprintf("parsing manifest: %s", err),
		})
		log.Info().Bool("passed", false).Msg("verification complete")
		return result, nil
	}
	if len(validationErrors) > 0 {
		result.Passed = false
		result.Steps = append(result.Steps, StepResult{
			Name:   "policy",
			Passed: false,
			Error:  fmt.Sprintf("manifest validation failed: %s", validationErrors[0].Message),
		})
		log.Info().Bool("passed", false).Msg("verification complete")
		return result, nil
	}

	policyStep, violations, warnings, err := p.verifyPolicy(ctx, m.Capabilities, sigResult.SignerIdentity, sigResult.Issuer)
	result.Steps = append(result.Steps, policyStep)

	if violations != nil {
		result.Violations = violations
	}
	if warnings != nil {
		result.Warnings = warnings
	}

	if err != nil {
		result.Passed = false
	}

	log.Info().Bool("passed", result.Passed).Int("steps", len(result.Steps)).Msg("verification complete")
	return result, nil
}

// readFileLimited reads a file up to maxBytes. Returns an error if the file
// exceeds the limit.
func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds size limit (%d > %d bytes)", path, info.Size(), maxBytes)
	}
	return os.ReadFile(path)
}
