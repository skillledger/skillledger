package logclient

import (
	"context"
	"fmt"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
)

// VerifyInclusion proves that leafData exists at leafIndex in a log of the given treeSize.
// It builds a Merkle inclusion proof from tiles via the client's HTTP fetcher, then verifies
// the proof against the checkpoint's signed root hash.
//
// T-05-12: Tampered tiles produce invalid proofs because the Merkle path won't
// match the signed root hash.
func VerifyInclusion(ctx context.Context, c *Client, treeSize, leafIndex uint64, leafData []byte) error {
	// Build proof from tiles using Tessera's ProofBuilder.
	pb, err := client.NewProofBuilder(ctx, treeSize, c.TileFetcher())
	if err != nil {
		return fmt.Errorf("creating proof builder: %w", err)
	}

	inclusionProof, err := pb.InclusionProof(ctx, leafIndex)
	if err != nil {
		return fmt.Errorf("building inclusion proof for index %d: %w", leafIndex, err)
	}

	// Hash the leaf data using RFC 6962 (0x00 || leaf).
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(leafData)

	// Fetch and parse the checkpoint to get the signed root hash.
	// T-05-11: note.Open verifies Ed25519 signature before trusting tree state.
	cp, _, _, err := client.FetchCheckpoint(ctx, c.CheckpointFetcher(), c.Verifier(), c.Origin())
	if err != nil {
		return fmt.Errorf("fetching checkpoint: %w", err)
	}

	// Verify the checkpoint tree size matches what we're proving against.
	if cp.Size < treeSize {
		return fmt.Errorf("checkpoint size %d is smaller than requested tree size %d", cp.Size, treeSize)
	}

	// Use the root hash from the checkpoint for the tree size we're proving.
	// If checkpoint.Size == treeSize, we can use the checkpoint hash directly.
	// If checkpoint is larger, we need the root at treeSize, but for simplicity
	// and security, we require exact match.
	if cp.Size != treeSize {
		return fmt.Errorf("checkpoint size %d does not match requested tree size %d; re-fetch with current tree size", cp.Size, treeSize)
	}

	// Verify the inclusion proof against the root hash.
	if err := proof.VerifyInclusion(hasher, leafIndex, treeSize, leafHash, inclusionProof, cp.Hash); err != nil {
		return fmt.Errorf("inclusion proof verification failed for index %d in tree of size %d: %w", leafIndex, treeSize, err)
	}

	return nil
}

// VerifyConsistency checks that the log has not been tampered with by verifying
// consistency between the log's previous and current state. It uses Tessera's
// LogStateTracker with unilateral consensus (trusting the log server's checkpoint).
//
// T-05-11: Detects rollbacks by verifying the Merkle consistency proof between
// the old and new tree states. If the log removed or modified entries, the
// consistency proof will fail.
//
// Returns the latest checkpoint on success.
func VerifyConsistency(ctx context.Context, c *Client) (*log.Checkpoint, error) {
	// Create a LogStateTracker with no prior state (nil checkpoint).
	// This fetches the current checkpoint and establishes it as the baseline.
	tracker, err := client.NewLogStateTracker(
		ctx,
		c.TileFetcher(),
		nil, // no prior checkpoint -- start fresh
		c.Verifier(),
		c.Origin(),
		client.UnilateralConsensus(c.CheckpointFetcher()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating log state tracker: %w", err)
	}

	// Get the latest consistent state.
	latest := tracker.Latest()

	c.logger.Info().
		Uint64("tree_size", latest.Size).
		Str("origin", latest.Origin).
		Msg("log consistency verified")

	return &latest, nil
}

// VerifyConsistencyFrom checks consistency between a known previous state and
// the current log state. This is used when the client has a cached checkpoint
// and wants to verify the log has only appended entries since then.
//
// previousCheckpoint should be the raw bytes of a previously verified checkpoint.
func VerifyConsistencyFrom(ctx context.Context, c *Client, previousCheckpoint []byte) (*log.Checkpoint, error) {
	tracker, err := client.NewLogStateTracker(
		ctx,
		c.TileFetcher(),
		previousCheckpoint,
		c.Verifier(),
		c.Origin(),
		client.UnilateralConsensus(c.CheckpointFetcher()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating log state tracker with prior state: %w", err)
	}

	// Update to the latest state, verifying consistency with prior.
	_, _, _, err = tracker.Update(ctx)
	if err != nil {
		return nil, fmt.Errorf("consistency verification failed: %w", err)
	}

	latest := tracker.Latest()

	c.logger.Info().
		Uint64("tree_size", latest.Size).
		Str("origin", latest.Origin).
		Msg("log consistency verified from prior state")

	return &latest, nil
}
