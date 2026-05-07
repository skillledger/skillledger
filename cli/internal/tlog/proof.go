// Package tlog provides an HTTP client for the SkillLedger transparency log
// service. This file adds Merkle inclusion proof verification (B-01) using
// the transparency-dev libraries already in the CLI's dependency tree.
package tlog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
	tlog "golang.org/x/mod/sumdb/note"
)

// ProofVerifier verifies Merkle inclusion proofs against the transparency log.
// It connects directly to the log personality server (not the FastAPI service)
// to fetch checkpoints and tiles for cryptographic proof verification.
type ProofVerifier struct {
	logURL   string
	verifier tlog.Verifier
	origin   string
	http     *http.Client
}

// ProofVerifierOption configures a ProofVerifier.
type ProofVerifierOption func(*ProofVerifier)

// WithProofLogURL sets the direct log server URL for proof verification.
func WithProofLogURL(u string) ProofVerifierOption {
	return func(pv *ProofVerifier) { pv.logURL = u }
}

// WithProofHTTPClient sets the HTTP client for proof verification requests.
func WithProofHTTPClient(h *http.Client) ProofVerifierOption {
	return func(pv *ProofVerifier) { pv.http = h }
}

// NewProofVerifier creates a proof verifier with the given checkpoint verifier key.
// verifierKey is the note verifier key string (e.g., "skillledger-log+...+...").
// Returns nil, nil if verifierKey is empty (proof verification disabled).
func NewProofVerifier(verifierKey string, opts ...ProofVerifierOption) (*ProofVerifier, error) {
	if verifierKey == "" {
		return nil, nil
	}

	v, err := tlog.NewVerifier(verifierKey)
	if err != nil {
		return nil, fmt.Errorf("creating note verifier: %w", err)
	}

	pv := &ProofVerifier{
		logURL:   "http://localhost:2025",
		verifier: v,
		origin:   v.Name(),
		http:     &http.Client{},
	}
	for _, opt := range opts {
		opt(pv)
	}
	return pv, nil
}

// VerifyInclusion verifies that an entry at the given log index is included in
// the log's Merkle tree. It fetches the checkpoint, builds an inclusion proof
// from tiles, and cryptographically verifies the proof.
//
// leafData should be the serialized log entry (the same bytes that were submitted
// to the log's /add endpoint).
func (pv *ProofVerifier) VerifyInclusion(ctx context.Context, logIndex uint64, leafData []byte) error {
	log.Debug().Uint64("index", logIndex).Msg("verifying Merkle inclusion proof")

	u, err := url.Parse(pv.logURL)
	if err != nil {
		return fmt.Errorf("parsing log URL: %w", err)
	}

	fetcher, err := client.NewHTTPFetcher(u, pv.http)
	if err != nil {
		return fmt.Errorf("creating HTTP fetcher: %w", err)
	}

	// Fetch and verify the signed checkpoint.
	cp, _, _, err := client.FetchCheckpoint(ctx, fetcher.ReadCheckpoint, pv.verifier, pv.origin)
	if err != nil {
		return fmt.Errorf("fetching/verifying checkpoint: %w", err)
	}

	if cp.Size <= logIndex {
		return fmt.Errorf("checkpoint tree size %d does not contain index %d", cp.Size, logIndex)
	}

	// Build inclusion proof from tiles.
	pb, err := client.NewProofBuilder(ctx, cp.Size, fetcher.ReadTile)
	if err != nil {
		return fmt.Errorf("creating proof builder: %w", err)
	}

	inclusionProof, err := pb.InclusionProof(ctx, logIndex)
	if err != nil {
		return fmt.Errorf("building inclusion proof: %w", err)
	}

	// Hash the leaf and verify.
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(leafData)

	if err := proof.VerifyInclusion(hasher, logIndex, cp.Size, leafHash, inclusionProof, cp.Hash); err != nil {
		return fmt.Errorf("Merkle inclusion proof verification FAILED: %w", err)
	}

	log.Debug().
		Uint64("index", logIndex).
		Uint64("tree_size", cp.Size).
		Msg("Merkle inclusion proof verified")

	return nil
}
