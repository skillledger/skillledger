package signer

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyResult holds the outputs of a successful verification.
type VerifyResult struct {
	SignerIdentity string    // OIDC identity (email or workflow URI) from certificate SAN
	Issuer         string    // OIDC issuer URL
	SignedAt       time.Time // timestamp from Rekor log entry
}

// Verifier validates Sigstore bundles with time-based key rotation support.
// It uses observer timestamps from Rekor to prove that signatures were created
// during the signing certificate's validity window, enabling verification after
// key rotation (SIGN-04).
type Verifier struct {
	expectedIssuer string
	expectedSAN    string
}

// VerifierOption configures the Verifier.
type VerifierOption func(*Verifier)

// WithExpectedIssuer sets the expected OIDC issuer for certificate identity matching.
// This prevents accepting bundles signed by unexpected identity providers (T-04-08).
func WithExpectedIssuer(issuer string) VerifierOption {
	return func(v *Verifier) { v.expectedIssuer = issuer }
}

// WithExpectedSAN sets the expected Subject Alternative Name for certificate identity matching.
// This prevents accepting bundles from unexpected signer identities (T-04-08).
func WithExpectedSAN(san string) VerifierOption {
	return func(v *Verifier) { v.expectedSAN = san }
}

// NewVerifier creates a Verifier with the given options.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify validates a Sigstore bundle at bundlePath against the given artifact digest.
// The artifactDigest should be the raw SHA-256 digest bytes.
//
// Verification includes:
//   - Signed certificate timestamps (SCT) from certificate transparency logs
//   - Transparency log entry from Rekor with inclusion proof (T-04-07)
//   - Observer timestamps for time-based key rotation support (SIGN-04)
//   - Certificate identity matching if expectedIssuer and expectedSAN are set (T-04-08)
func (v *Verifier) Verify(bundlePath string, artifactDigest []byte) (*VerifyResult, error) {
	// Load bundle from disk (T-04-07: untrusted input from disk)
	log.Debug().Str("path", bundlePath).Msg("loading Sigstore bundle")
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("loading bundle from %s: %w", bundlePath, err)
	}

	// Fetch TUF-managed trusted root for verification material
	log.Debug().Msg("fetching Sigstore trusted root via TUF")
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	// Create verifier with time-based validation (SIGN-04):
	// - WithSignedCertificateTimestamps(1): require at least 1 SCT
	// - WithTransparencyLog(1): require Rekor inclusion proof (SIGN-03, T-04-06)
	// - WithObserverTimestamps(1): use Rekor's SignedEntryTimestamp to prove
	//   the signature was created during certificate validity window,
	//   enabling verification after key rotation
	log.Debug().Msg("creating verifier with time-based key rotation support")
	sev, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Sigstore verifier: %w", err)
	}

	// Build verification policy
	var policyOpts []verify.PolicyOption

	// Certificate identity matching (T-04-08)
	if v.expectedIssuer != "" && v.expectedSAN != "" {
		log.Debug().
			Str("issuer", v.expectedIssuer).
			Str("san", v.expectedSAN).
			Msg("configuring certificate identity matching")

		certID, err := verify.NewShortCertificateIdentity(v.expectedIssuer, "", v.expectedSAN, "")
		if err != nil {
			return nil, fmt.Errorf("creating certificate identity: %w", err)
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
	}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", artifactDigest),
		policyOpts...,
	)

	// Verify the bundle against policy
	log.Debug().Msg("verifying bundle against policy")
	result, err := sev.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("verifying Sigstore bundle: %w", err)
	}

	// Extract verification results
	vr := &VerifyResult{}

	if result.VerifiedIdentity != nil {
		if san := result.VerifiedIdentity.SubjectAlternativeName; san.SubjectAlternativeName != "" {
			vr.SignerIdentity = san.SubjectAlternativeName
		}
		if iss := result.VerifiedIdentity.Issuer; iss.Issuer != "" {
			vr.Issuer = iss.Issuer
		}
	}

	if len(result.VerifiedTimestamps) > 0 {
		vr.SignedAt = result.VerifiedTimestamps[0].Timestamp
	}

	log.Debug().
		Str("identity", vr.SignerIdentity).
		Str("issuer", vr.Issuer).
		Time("signed_at", vr.SignedAt).
		Msg("verification successful")

	return vr, nil
}
