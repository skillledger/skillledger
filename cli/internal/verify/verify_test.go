package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/policy/eval"
	"github.com/skillledger/skillledger/internal/signer"
	"github.com/skillledger/skillledger/internal/tlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFixture creates temp files needed for pipeline integration tests.
// Returns a cleanup-free temp dir (managed by t.TempDir), the artifact path,
// and the computed SHA-256 hex string.
type testFixture struct {
	dir          string
	artifactPath string
	bundlePath   string
	lockfilePath string
	manifestPath string
	sha256Hex    string
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()

	dir := t.TempDir()

	// Create nested structure: dir/dist/artifact.tar.gz
	distDir := filepath.Join(dir, "dist")
	require.NoError(t, os.MkdirAll(distDir, 0755))

	// Artifact
	artifactContent := []byte("test skill artifact binary content for verification")
	artifactPath := filepath.Join(distDir, "artifact.tar.gz")
	require.NoError(t, os.WriteFile(artifactPath, artifactContent, 0644))

	// Compute SHA-256
	h := sha256.Sum256(artifactContent)
	sha256Hex := hex.EncodeToString(h[:])

	// Bundle (mock -- content doesn't matter since sig verification is mocked)
	bundlePath := artifactPath + ".sigstore.json"
	require.NoError(t, os.WriteFile(bundlePath, []byte(`{"mock":"bundle"}`), 0644))

	// Lockfile
	lf := builder.Lockfile{
		SkillLedger:    1,
		ArtifactID:     "com.example.test@1.0.0",
		Version:        "1.0.0",
		SHA256:         sha256Hex,
		ContentAddress: "sha256:" + sha256Hex,
		BuiltAt:        "2026-04-20T00:00:00Z",
		Source: builder.LockfileSource{
			Repository: "https://github.com/example/test",
		},
	}
	lfData, err := json.Marshal(lf)
	require.NoError(t, err)
	lockfilePath := filepath.Join(dir, "skill-lock.json")
	require.NoError(t, os.WriteFile(lockfilePath, lfData, 0644))

	// Manifest (valid YAML that passes ParseAndValidate)
	manifestYAML := `skillledger: 1
id: com.example.test
version: "1.0.0"
kind: generic
source:
  repository: https://github.com/example/test
capabilities:
  filesystem:
    - "read:/tmp"
  network:
    - "outbound:api.example.com"
`
	manifestPath := filepath.Join(dir, "skillledger.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifestYAML), 0644))

	return &testFixture{
		dir:          dir,
		artifactPath: artifactPath,
		bundlePath:   bundlePath,
		lockfilePath: lockfilePath,
		manifestPath: manifestPath,
		sha256Hex:    sha256Hex,
	}
}

func successMocks() (*mockSigVerifier, *mockTlogLooker, *mockPolicyEval, string) {
	sha := "" // will be set per test
	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
			SignedAt:        time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}
	return sig, nil, pol, sha
}

func TestPipelineVerify_AllPass(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
			SignedAt:        time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		},
	}
	tl := &mockTlogLooker{
		response: &tlog.LookupResponse{
			ArtifactID: "com.example.test@1.0.0",
			SHA256:     fix.sha256Hex,
			LogIndex:   99,
			Publisher:  "dev@example.com",
		},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.True(t, result.Passed)
	assert.Len(t, result.Steps, 4) // hash-check, signature, tlog, policy
	assert.True(t, result.Steps[0].Passed, "hash-check should pass")
	assert.True(t, result.Steps[1].Passed, "signature should pass")
	assert.True(t, result.Steps[2].Passed, "tlog should pass")
	assert.True(t, result.Steps[3].Passed, "policy should pass")
}

func TestPipelineVerify_SignatureFails(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		err: fmt.Errorf("invalid signature"),
	}
	tl := &mockTlogLooker{
		response: &tlog.LookupResponse{SHA256: fix.sha256Hex, LogIndex: 1},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.False(t, result.Passed)
	// Should have hash-check + signature only; tlog and policy NOT reached
	assert.Len(t, result.Steps, 2)
	assert.Equal(t, "hash-check", result.Steps[0].Name)
	assert.Equal(t, "signature", result.Steps[1].Name)
	assert.False(t, result.Steps[1].Passed)
}

func TestPipelineVerify_TlogFails(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
		},
	}
	tl := &mockTlogLooker{
		err: fmt.Errorf("transparency log unavailable"),
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.False(t, result.Passed)
	// hash-check + signature + tlog; policy NOT reached
	assert.Len(t, result.Steps, 3)
	assert.True(t, result.Steps[1].Passed, "signature should pass")
	assert.False(t, result.Steps[2].Passed, "tlog should fail")
	assert.Equal(t, "transparency-log", result.Steps[2].Name)
}

func TestPipelineVerify_PolicyDenies(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
		},
	}
	tl := &mockTlogLooker{
		response: &tlog.LookupResponse{
			ArtifactID: "com.example.test@1.0.0",
			SHA256:     fix.sha256Hex,
			LogIndex:   42,
		},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{
			Decision:   "deny",
			Violations: []string{"network access denied", "secret access denied"},
		},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.False(t, result.Passed)
	assert.Len(t, result.Steps, 4) // all steps present
	assert.False(t, result.Steps[3].Passed, "policy should fail")
	assert.Len(t, result.Violations, 2)
	assert.Contains(t, result.Violations[0], "network access denied")
}

func TestPipelineVerify_PolicyWarns(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
		},
	}
	tl := &mockTlogLooker{
		response: &tlog.LookupResponse{
			ArtifactID: "com.example.test@1.0.0",
			SHA256:     fix.sha256Hex,
			LogIndex:   42,
		},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{
			Decision: "warn",
			Warnings: []string{"broad filesystem access"},
		},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.True(t, result.Passed, "warn should still pass")
	assert.Len(t, result.Warnings, 1)
	assert.Equal(t, "broad filesystem access", result.Warnings[0])
	assert.Empty(t, result.Violations)
}

func TestPipelineVerify_SkipTlog(t *testing.T) {
	fix := newTestFixture(t)

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{
			SignerIdentity: "dev@example.com",
			Issuer:         "https://accounts.google.com",
		},
	}
	// tlog mock should NOT be called
	tl := &mockTlogLooker{
		err: fmt.Errorf("should not be called"),
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(sig, tl, pol, WithSkipTlog(true))
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.True(t, result.Passed)
	// hash-check + signature + policy (no tlog)
	assert.Len(t, result.Steps, 3)
	for _, step := range result.Steps {
		assert.NotEqual(t, "transparency-log", step.Name, "tlog step should be skipped")
	}
}

func TestPipelineVerify_HashMismatch(t *testing.T) {
	fix := newTestFixture(t)

	// Rewrite the lockfile with wrong SHA-256
	lf := builder.Lockfile{
		SkillLedger:    1,
		ArtifactID:     "com.example.test@1.0.0",
		Version:        "1.0.0",
		SHA256:         "0000000000000000000000000000000000000000000000000000000000000000",
		ContentAddress: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		BuiltAt:        "2026-04-20T00:00:00Z",
		Source: builder.LockfileSource{
			Repository: "https://github.com/example/test",
		},
	}
	lfData, err := json.Marshal(lf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fix.lockfilePath, lfData, 0644))

	sig := &mockSigVerifier{
		result: &signer.VerifyResult{SignerIdentity: "dev@example.com", Issuer: "https://accounts.google.com"},
	}
	tl := &mockTlogLooker{
		response: &tlog.LookupResponse{SHA256: "0000", LogIndex: 1},
	}
	pol := &mockPolicyEval{
		result: &eval.PolicyResult{Decision: "allow"},
	}

	p := NewPipeline(sig, tl, pol)
	result, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: fix.artifactPath,
		BundlePath:   fix.bundlePath,
		LockfilePath: fix.lockfilePath,
		ManifestPath: fix.manifestPath,
	})

	require.NoError(t, err)
	assert.False(t, result.Passed)
	assert.Len(t, result.Steps, 1) // only hash-check
	assert.Equal(t, "hash-check", result.Steps[0].Name)
	assert.False(t, result.Steps[0].Passed)
	assert.Contains(t, result.Steps[0].Error, "hash mismatch")
}

func TestPipelineVerify_MissingLockfile(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "dist", "artifact.tar.gz")

	sig := &mockSigVerifier{}
	tl := &mockTlogLooker{}
	pol := &mockPolicyEval{}

	p := NewPipeline(sig, tl, pol)
	_, err := p.Verify(context.Background(), VerifyInput{
		ArtifactPath: artifactPath,
		LockfilePath: filepath.Join(dir, "nonexistent-lock.json"),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading lockfile")
}
