package signer

import (
	"fmt"
	"os"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/rs/zerolog/log"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// SignResult holds the outputs of a successful signing operation.
type SignResult struct {
	BundlePath string // path to written .sigstore.json bundle
	BundleJSON []byte // raw bundle JSON bytes
	LogIndex   int64  // Rekor transparency log index
}

// Signer orchestrates Sigstore signing with ephemeral Ed25519 keypair,
// Fulcio certificate issuance, and Rekor transparency log recording.
type Signer struct {
	identityToken string
	fulcioURL     string
	rekorURL      string
}

// Option configures the Signer.
type Option func(*Signer)

// WithIdentityToken sets the OIDC identity token for Fulcio certificate issuance.
// If not set, the signer falls back to the SIGSTORE_ID_TOKEN environment variable.
func WithIdentityToken(token string) Option {
	return func(s *Signer) { s.identityToken = token }
}

// WithFulcioURL overrides the default Fulcio CA URL.
func WithFulcioURL(url string) Option {
	return func(s *Signer) { s.fulcioURL = url }
}

// WithRekorURL overrides the default Rekor transparency log URL.
func WithRekorURL(url string) Option {
	return func(s *Signer) { s.rekorURL = url }
}

// NewSigner creates a Signer with the given options.
// Defaults to public Sigstore infrastructure (fulcio.sigstore.dev, rekor.sigstore.dev).
func NewSigner(opts ...Option) *Signer {
	s := &Signer{
		fulcioURL: "https://fulcio.sigstore.dev",
		rekorURL:  "https://rekor.sigstore.dev",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// resolveToken returns the OIDC identity token, checking the option value first,
// then falling back to the SIGSTORE_ID_TOKEN environment variable.
func (s *Signer) resolveToken() (string, error) {
	if s.identityToken != "" {
		return s.identityToken, nil
	}
	if token := os.Getenv("SIGSTORE_ID_TOKEN"); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("no OIDC token: set SIGSTORE_ID_TOKEN env var or use WithIdentityToken option")
}

// Sign creates a Sigstore bundle from an in-toto statement using an ephemeral
// Ed25519 keypair. The bundle includes a Fulcio-issued certificate and a Rekor
// transparency log entry.
//
// The OIDC identity token must be available via WithIdentityToken or the
// SIGSTORE_ID_TOKEN environment variable.
func (s *Signer) Sign(statement *intoto.Statement) (*SignResult, error) {
	// T-04-04: Resolve OIDC token late, immediately before signing
	oidcToken, err := s.resolveToken()
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("serializing in-toto statement")
	statementJSON, err := SerializeStatement(statement)
	if err != nil {
		return nil, fmt.Errorf("serializing statement for signing: %w", err)
	}

	// Create DSSE content with in-toto payload type
	content := &sign.DSSEData{
		Data:        statementJSON,
		PayloadType: "application/vnd.in-toto+json",
	}

	// T-04-05: Generate ephemeral Ed25519 keypair (never persisted to disk)
	log.Debug().Msg("generating ephemeral Ed25519 keypair")
	keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{
		Algorithm: protocommon.PublicKeyDetails_PKIX_ED25519,
	})
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}

	// Create Fulcio certificate provider
	log.Debug().Str("url", s.fulcioURL).Msg("configuring Fulcio certificate provider")
	fulcio := sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: s.fulcioURL,
	})

	// Create Rekor transparency log provider
	log.Debug().Str("url", s.rekorURL).Msg("configuring Rekor transparency log")
	rekor := sign.NewRekor(&sign.RekorOptions{
		BaseURL: s.rekorURL,
	})

	// T-04-06: Create signed bundle with Rekor inclusion for non-repudiation
	log.Debug().Msg("creating Sigstore bundle")
	bundle, err := sign.Bundle(content, keypair, sign.BundleOptions{
		CertificateProvider: fulcio,
		CertificateProviderOptions: &sign.CertificateProviderOptions{
			IDToken: oidcToken,
		},
		TransparencyLogs: []sign.Transparency{rekor},
	})
	if err != nil {
		return nil, fmt.Errorf("creating Sigstore bundle: %w", err)
	}

	// Serialize bundle to JSON
	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("serializing bundle: %w", err)
	}

	// Extract Rekor log index from transparency log entry
	// Use -1 as sentinel to distinguish "no entry" from valid index 0
	var logIndex int64 = -1
	if vm := bundle.GetVerificationMaterial(); vm != nil {
		if entries := vm.GetTlogEntries(); len(entries) > 0 {
			logIndex = entries[0].GetLogIndex()
		}
	}
	if logIndex < 0 {
		return nil, fmt.Errorf("Sigstore bundle has no Rekor transparency log entry: non-repudiation requires log inclusion")
	}

	log.Debug().Int64("log_index", logIndex).Msg("signing complete")

	return &SignResult{
		BundleJSON: bundleJSON,
		LogIndex:   logIndex,
	}, nil
}

// SignAndWrite creates a Sigstore bundle and writes it to disk alongside the artifact.
// The bundle is written to artifactPath + ".sigstore.json".
func (s *Signer) SignAndWrite(statement *intoto.Statement, artifactPath string) (*SignResult, error) {
	result, err := s.Sign(statement)
	if err != nil {
		return nil, err
	}

	bundlePath := artifactPath + ".sigstore.json"
	if err := os.WriteFile(bundlePath, result.BundleJSON, 0600); err != nil {
		return nil, fmt.Errorf("writing bundle to %s: %w", bundlePath, err)
	}

	result.BundlePath = bundlePath
	log.Debug().Str("path", bundlePath).Msg("bundle written to disk")

	return result, nil
}
