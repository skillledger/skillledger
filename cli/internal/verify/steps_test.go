package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/skillledger/skillledger/internal/signer"
	"github.com/skillledger/skillledger/internal/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock implementations ---

type mockSigVerifier struct {
	result *signer.VerifyResult
	err    error
}

func (m *mockSigVerifier) Verify(bundlePath string, digest []byte) (*signer.VerifyResult, error) {
	return m.result, m.err
}

type mockTlogLooker struct {
	response *tlog.LookupResponse
	err      error
}

func (m *mockTlogLooker) LookupEntry(ctx context.Context, id string) (*tlog.LookupResponse, error) {
	return m.response, m.err
}

type mockPolicyEval struct {
	result *eval.PolicyResult
	err    error
}

func (m *mockPolicyEval) Evaluate(ctx context.Context, input map[string]any) (*eval.PolicyResult, error) {
	return m.result, m.err
}

// --- Step tests ---

func TestVerifySignature_Success(t *testing.T) {
	mock := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
			SignedAt:        time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
	}

	p := NewPipeline(mock, nil, nil)
	step, vr, err := p.verifySignature(context.Background(), "/fake/bundle.json", []byte("digest"))

	require.NoError(t, err)
	assert.True(t, step.Passed)
	assert.Equal(t, "signature", step.Name)
	assert.Contains(t, step.Detail, "dev@example.com")
	assert.Contains(t, step.Detail, "https://accounts.google.com")
	assert.NotNil(t, vr)
	assert.Equal(t, "dev@example.com", vr.SignerIdentity)
}

func TestVerifySignature_Failure(t *testing.T) {
	mock := &mockSigVerifier{
		err: fmt.Errorf("bundle signature invalid"),
	}

	p := NewPipeline(mock, nil, nil)
	step, vr, err := p.verifySignature(context.Background(), "/fake/bundle.json", []byte("digest"))

	require.Error(t, err)
	assert.False(t, step.Passed)
	assert.Equal(t, "signature", step.Name)
	assert.Contains(t, step.Error, "bundle signature invalid")
	assert.Nil(t, vr)
}

func TestVerifyTlog_Success(t *testing.T) {
	sha := "abc123def456"
	mock := &mockTlogLooker{
		response: &tlog.LookupResponse{
			ArtifactID: "test-skill@1.0.0",
			SHA256:     sha,
			LogIndex:   42,
			Publisher:  "dev@example.com",
		},
	}

	p := NewPipeline(nil, mock, nil)
	step, err := p.verifyTlog(context.Background(), "test-skill@1.0.0", sha)

	require.NoError(t, err)
	assert.True(t, step.Passed)
	assert.Equal(t, "transparency-log", step.Name)
	assert.Contains(t, step.Detail, "42")
}

func TestVerifyTlog_HashMismatch(t *testing.T) {
	mock := &mockTlogLooker{
		response: &tlog.LookupResponse{
			ArtifactID: "test-skill@1.0.0",
			SHA256:     "aaaaaa",
			LogIndex:   42,
		},
	}

	p := NewPipeline(nil, mock, nil)
	step, err := p.verifyTlog(context.Background(), "test-skill@1.0.0", "bbbbbb")

	require.Error(t, err)
	assert.False(t, step.Passed)
	assert.Equal(t, "transparency-log", step.Name)
	assert.Contains(t, step.Error, "mismatch")
}

func TestVerifyTlog_NotFound(t *testing.T) {
	mock := &mockTlogLooker{
		err: fmt.Errorf("artifact not found in transparency log"),
	}

	p := NewPipeline(nil, mock, nil)
	step, err := p.verifyTlog(context.Background(), "test-skill@1.0.0", "abc123")

	require.Error(t, err)
	assert.False(t, step.Passed)
	assert.Equal(t, "transparency-log", step.Name)
	assert.Contains(t, step.Error, "not found")
}

func TestVerifyPolicy_Allow(t *testing.T) {
	mock := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(nil, nil, mock)
	step, violations, warnings, err := p.verifyPolicy(
		context.Background(),
		stubCaps(),
		"dev@example.com",
		"https://accounts.google.com",
	)

	require.NoError(t, err)
	assert.True(t, step.Passed)
	assert.Equal(t, "policy", step.Name)
	assert.Contains(t, step.Detail, "All capability checks passed")
	assert.Nil(t, violations)
	assert.Nil(t, warnings)
}

func TestVerifyPolicy_Deny(t *testing.T) {
	mock := &mockPolicyEval{
		result: &eval.PolicyResult{
			Decision:   "deny",
			Violations: []string{"network access to *.evil.com denied", "secret access denied"},
		},
	}

	p := NewPipeline(nil, nil, mock)
	step, violations, warnings, err := p.verifyPolicy(
		context.Background(),
		stubCaps(),
		"dev@example.com",
		"https://accounts.google.com",
	)

	require.Error(t, err)
	assert.False(t, step.Passed)
	assert.Equal(t, "policy", step.Name)
	assert.Contains(t, step.Error, "network access to *.evil.com denied")
	assert.Len(t, violations, 2)
	assert.Nil(t, warnings)
}

func TestVerifyPolicy_Warn(t *testing.T) {
	mock := &mockPolicyEval{
		result: &eval.PolicyResult{
			Decision: "warn",
			Warnings: []string{"broad filesystem access"},
		},
	}

	p := NewPipeline(nil, nil, mock)
	step, violations, warnings, err := p.verifyPolicy(
		context.Background(),
		stubCaps(),
		"dev@example.com",
		"https://accounts.google.com",
	)

	require.NoError(t, err)
	assert.True(t, step.Passed)
	assert.Equal(t, "policy", step.Name)
	assert.Contains(t, step.Detail, "1 warning(s)")
	assert.Nil(t, violations)
	assert.Len(t, warnings, 1)
	assert.Equal(t, "broad filesystem access", warnings[0])
}

func TestComputeAndCompareHash_Match(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test artifact content for hashing")
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	require.NoError(t, os.WriteFile(artifactPath, content, 0644))

	h := sha256.Sum256(content)
	expectedHex := hex.EncodeToString(h[:])

	digest, err := computeAndCompareHash(artifactPath, expectedHex)

	require.NoError(t, err)
	assert.Equal(t, h[:], digest)
}

func TestComputeAndCompareHash_Mismatch(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test artifact content")
	artifactPath := filepath.Join(dir, "artifact.tar.gz")
	require.NoError(t, os.WriteFile(artifactPath, content, 0644))

	digest, err := computeAndCompareHash(artifactPath, "0000000000000000000000000000000000000000000000000000000000000000")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
	assert.Nil(t, digest)
}

// --- Helpers ---

func stubCaps() manifest.Capabilities {
	return manifest.Capabilities{
		Filesystem: []string{"read:/tmp"},
		Network:    []string{"https://api.example.com"},
	}
}
