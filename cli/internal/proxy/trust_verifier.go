// Package proxy -- trust_verifier.go implements TrustVerifier, a session-scoped
// component that bridges v1 install-time verification with v2 runtime enforcement.
// Skills earn trust tiers (verified/partial/unverified) based on their SLSA
// verification status, which downstream plans use to gate runtime permissions.
package proxy

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/afero"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/verify"
)

// TrustTier represents the verification trust level of a skill.
type TrustTier string

const (
	// TrustVerified means the skill has valid SLSA provenance, signature, and tlog entry.
	TrustVerified TrustTier = "verified"
	// TrustPartial means some verification steps passed but not all.
	TrustPartial TrustTier = "partial"
	// TrustUnverified means no verification was attempted, all checks failed, or
	// verification is still in-flight. This is the fail-closed default.
	TrustUnverified TrustTier = "unverified"
)

// VerificationResult holds the outcome of a skill's trust verification.
type VerificationResult struct {
	Tier           TrustTier          `json:"tier"`
	SignerIdentity string             `json:"signer_identity,omitempty"`
	Issuer         string             `json:"issuer,omitempty"`
	Steps          []verify.StepResult `json:"steps,omitempty"`
	Error          string             `json:"error,omitempty"`
	VerifiedAt     time.Time          `json:"verified_at"`
	InFlight       bool               `json:"-"` // not serialized; true while verification goroutine is running
}

// TrustVerifier manages async skill verification using the v1 verify.Pipeline
// and caches trust tier results per SkillID for the proxy session.
// It is safe for concurrent use by multiple goroutines.
type TrustVerifier struct {
	mu          sync.RWMutex
	cache       map[string]*VerificationResult
	pipeline    *verify.Pipeline
	fs          afero.Fs
	lockfileDir string
	ctx         context.Context
	cancel      context.CancelFunc
	logger      zerolog.Logger
}

// NewTrustVerifier creates a TrustVerifier with the given v1 verification pipeline,
// filesystem for lockfile access, and lockfile directory path.
// The ctx parameter controls goroutine lifecycle -- cancel it to stop in-flight verifications.
func NewTrustVerifier(ctx context.Context, pipeline *verify.Pipeline, fs afero.Fs, lockfileDir string, logger zerolog.Logger) *TrustVerifier {
	derivedCtx, cancel := context.WithCancel(ctx)
	return &TrustVerifier{
		cache:       make(map[string]*VerificationResult),
		pipeline:    pipeline,
		fs:          fs,
		lockfileDir: lockfileDir,
		ctx:         derivedCtx,
		cancel:      cancel,
		logger:      logger,
	}
}

// GetTier returns the trust tier for a skill. On first call for a given skillID,
// it launches async verification and returns TrustUnverified (fail-closed).
// Subsequent calls return the cached tier once verification completes.
func (tv *TrustVerifier) GetTier(skillID string) TrustTier {
	// Fast path: read lock check.
	tv.mu.RLock()
	if result, ok := tv.cache[skillID]; ok {
		tv.mu.RUnlock()
		if result.InFlight {
			return TrustUnverified
		}
		return result.Tier
	}
	tv.mu.RUnlock()

	// Slow path: acquire write lock, double-check, then launch verification.
	tv.startVerification(skillID)
	return TrustUnverified
}

// GetResult returns the full cached verification result for a skill,
// or nil if no result exists (skill never queried).
func (tv *TrustVerifier) GetResult(skillID string) *VerificationResult {
	tv.mu.RLock()
	defer tv.mu.RUnlock()
	result, ok := tv.cache[skillID]
	if !ok {
		return nil
	}
	// Return a copy to prevent external mutation.
	cpy := *result
	return &cpy
}

// ResolveArtifactHash reads the skill-lock.json for a skill and returns the
// artifact ID, SHA256 hash, and lockfile path.
func (tv *TrustVerifier) ResolveArtifactHash(skillID string) (artifactID, sha256, lockfilePath string, err error) {
	lockfilePath = filepath.Join(tv.lockfileDir, skillID, "skill-lock.json")
	lf, err := builder.ReadLockfile(tv.fs, lockfilePath)
	if err != nil {
		return "", "", "", fmt.Errorf("no lockfile for skill %q: %w", skillID, err)
	}
	return lf.ArtifactID, lf.SHA256, lockfilePath, nil
}

// Close cancels the verifier context, stopping any in-flight verification goroutines.
func (tv *TrustVerifier) Close() {
	tv.cancel()
}

// startVerification acquires a write lock, performs a double-check, and if the
// skill is not yet in cache, marks it as in-flight and launches a verification goroutine.
func (tv *TrustVerifier) startVerification(skillID string) {
	tv.mu.Lock()
	// Double-check under write lock.
	if _, ok := tv.cache[skillID]; ok {
		tv.mu.Unlock()
		return
	}
	// Mark as in-flight with unverified tier.
	tv.cache[skillID] = &VerificationResult{
		Tier:     TrustUnverified,
		InFlight: true,
	}
	tv.mu.Unlock()

	go tv.runVerification(skillID)
}

// runVerification executes the v1 verify pipeline for a skill and writes the
// result to the cache. Runs in a goroutine.
func (tv *TrustVerifier) runVerification(skillID string) {
	logger := tv.logger.With().Str("skill_id", skillID).Logger()

	// Resolve artifact info from lockfile.
	artifactID, _, lockfilePath, err := tv.ResolveArtifactHash(skillID)
	if err != nil {
		logger.Debug().Err(err).Msg("no lockfile found, skill permanently unverified")
		tv.writeResult(skillID, &VerificationResult{
			Tier:       TrustUnverified,
			Error:      fmt.Sprintf("no lockfile for skill %q", skillID),
			VerifiedAt: time.Now(),
		})
		return
	}

	// Check if artifact file exists on disk for full verification.
	artifactPath := filepath.Join(tv.lockfileDir, skillID, artifactID+".tar.gz")
	_, statErr := tv.fs.Stat(artifactPath)
	hasArtifact := statErr == nil

	// Build verification input.
	input := verify.VerifyInput{
		LockfilePath: lockfilePath,
	}
	if hasArtifact {
		input.ArtifactPath = artifactPath
	} else {
		// No artifact on disk -- best possible tier is TrustPartial.
		// We skip the hash check by not providing ArtifactPath; the pipeline
		// will fail at hash-check step but we handle the error gracefully.
		logger.Debug().Str("artifact_id", artifactID).Msg("artifact not on disk, signature-only verification")
	}

	// Run the v1 verification pipeline.
	vr, err := tv.pipeline.Verify(tv.ctx, input)
	if err != nil {
		// Pipeline returned a hard error (e.g., lockfile unreadable from OsFs, context cancelled).
		logger.Debug().Err(err).Msg("verification pipeline error")
		tv.writeResult(skillID, &VerificationResult{
			Tier:       TrustUnverified,
			Error:      err.Error(),
			VerifiedAt: time.Now(),
		})
		return
	}

	// Assign tier from pipeline result.
	tier := AssignTier(vr)

	// If no artifact was present, cap at TrustPartial (can't fully verify without hash check).
	if !hasArtifact && tier == TrustVerified {
		tier = TrustPartial
	}

	result := &VerificationResult{
		Tier:       tier,
		Steps:      vr.Steps,
		VerifiedAt: time.Now(),
	}

	tv.writeResult(skillID, result)
	logger.Info().Str("tier", string(tier)).Int("steps", len(vr.Steps)).Msg("verification complete")
}

// writeResult writes a completed verification result to the cache under write lock.
func (tv *TrustVerifier) writeResult(skillID string, result *VerificationResult) {
	result.InFlight = false
	tv.mu.Lock()
	tv.cache[skillID] = result
	tv.mu.Unlock()
}

// AssignTier derives a TrustTier from a v1 VerifyResult.
//   - nil result -> TrustUnverified
//   - vr.Passed == true -> TrustVerified
//   - vr.Passed == false but some steps passed -> TrustPartial
//   - vr.Passed == false and no steps passed -> TrustUnverified
func AssignTier(vr *verify.VerifyResult) TrustTier {
	if vr == nil {
		return TrustUnverified
	}
	if vr.Passed {
		return TrustVerified
	}
	// Check if any steps passed (partial verification).
	for _, step := range vr.Steps {
		if step.Passed {
			return TrustPartial
		}
	}
	return TrustUnverified
}
