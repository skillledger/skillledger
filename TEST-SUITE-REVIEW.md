---
phase: test-suite-review
reviewed: 2026-05-07T12:00:00Z
depth: deep
files_reviewed: 61
findings:
  critical: 3
  warning: 7
  info: 3
  total: 13
status: issues_found
---

# Go Test Suite Review

**Reviewed:** 2026-05-07
**Depth:** deep (cross-file, cross-package analysis)
**Files Reviewed:** 61 test files across 20+ packages
**Status:** issues_found

## Summary

The test suite is substantial (61 test files) with good coverage of most subsystems. The security-critical paths -- verification pipeline, policy evaluation, DSL-to-Rego compilation, signing/provenance, IOC matching, and proxy scanners -- all have meaningful tests. However, there are significant gaps in negative testing of security-critical flows, test isolation problems with environment variables, and several packages that lack any test coverage for their CLI command handlers. The verify pipeline tests are entirely mock-based (reasonable for unit tests) but there are no integration tests that exercise the actual Sigstore/Rekor verification chain, meaning a misconfiguration in the Verifier could ship undetected.

## Strengths

- **Builder determinism** (`builder_test.go:62-91`): Thorough testing that builds from identical sources produce byte-identical artifacts with matching SHA-256 hashes. This is the core value proposition and it is well tested.
- **Archive metadata zeroing** (`archive_test.go:61-81`): Correctly verifies UID/GID/Uname/Gname zeroed and mode clamped to 0644 for all entries -- critical for reproducible builds.
- **Gzip OS byte** (`archive_test.go:103-108`): Tests RFC 1952 byte 9 is 0xFF (unknown), preventing OS-specific variation.
- **Symlink exclusion** (`collector_test.go:99-124`): Tests on real filesystem with OsFs -- symlinks properly rejected to prevent supply-chain substitution via symlink attacks.
- **Policy fail-closed** (`evaluator_test.go:95-106`): Verifies empty Rego policy defaults to "deny" -- critical security property.
- **Injection prevention** (`compiler_test.go:217-224`): Tests that newline injection in DSL-to-Rego compilation is rejected.
- **Verification pipeline short-circuit** (`verify_test.go:153-181`): Confirms that signature failure stops pipeline before tlog/policy evaluation, preventing information leakage about later steps.
- **Hash mismatch early rejection** (`verify_test.go:327-370`): Tests that tampered artifacts are caught at hash-check before any network calls.
- **IOC domain matching** (`ioc_test.go:196-208`): Correctly tests that "notevil.com" does NOT match IOC entry "evil.com" -- prevents partial string match bypass.
- **Verifier partial-config rejection** (`verifier_test.go:54-72`): Tests CR-01 fix -- setting only issuer or only SAN errors, preventing silent identity verification bypass.
- **Proxy secret redaction** (`secret_scanner_test.go:63-75`): Tests that detected secrets are redacted in findings.
- **Mid-session rug-pull detection** (`pinning_test.go:494-566`): Tests critical supply-chain attack vector of MCP tool modification mid-session.
- **Concurrent access tests** (`trust_verifier_test.go:284-331`, `entropy_test.go:202-219`): Race condition testing with goroutines.
- **Allowlist glob matching** (`allowlist_test.go:66-161`): Tests both matching and non-matching publisher identities.
- **Provenance input validation** (`provenance_test.go:126-179`): Tests empty digest, short digest, invalid hex, empty name, empty repository, empty ref, empty builtAt -- thorough negative testing.
- **Trust tier assignment** (`trust_verifier_test.go:81-131`): Tests all trust tier outcomes (verified, partial, unverified, nil, no-steps).
- **Runtime policy presets** (`presets_test.go:122-379`): Comprehensive trust-tier-aware runtime preset tests covering strict/moderate/permissive with verified/partial/unverified tiers.

## Critical Issues

### CR-01: Test Isolation Failure in Builder -- os.Setenv Without t.Setenv

**File:** `cli/internal/builder/builder_test.go:170-179`
**Issue:** `TestBuild_SourceDateEpoch` uses `os.Setenv`/`os.Unsetenv` directly instead of `t.Setenv`. This is not parallel-safe: if another test in the same package runs concurrently and calls `builder.ResolveEpoch()`, it reads the polluted `SOURCE_DATE_EPOCH`. The manual cleanup with `defer` is also fragile -- if the test panics before the defer runs (e.g., from a require.NoError failure), the environment stays dirty for all subsequent tests. This is especially dangerous because `SOURCE_DATE_EPOCH` directly controls artifact build timestamps, meaning a leaking env var could cause subsequent determinism tests to produce wrong results silently.

**Fix:**
```go
func TestBuild_SourceDateEpoch(t *testing.T) {
    sourceDir := t.TempDir()
    outputDir := t.TempDir()

    writeManifest(t, sourceDir)
    writeSourceFiles(t, sourceDir)

    t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

    b := builder.NewBuilder()
    result, err := b.Build(sourceDir, outputDir)
    require.NoError(t, err)

    lf, err := builder.ReadLockfile(afero.NewOsFs(), result.LockfilePath)
    require.NoError(t, err)

    assert.Equal(t, "2023-11-14T22:13:20Z", lf.BuiltAt)
}
```

### CR-02: No Test for Verifier Without Identity Constraints (Silent Pass-Through)

**File:** `cli/internal/signer/verifier_test.go` (entire file)
**Issue:** When `NewVerifier()` is called with zero options (no expected issuer/SAN), the `Verify` method at `verifier.go:102` skips certificate identity matching entirely -- any signer from any issuer is accepted. There is no test that exercises this path to verify the security implications. The test `TestVerifier_InvalidBundlePath` tests file loading failure, not actual verification behavior. The CR-01 partial-config tests are good, but they only cover the "one-but-not-both" case. The "neither-set" case -- which is the most dangerous -- has no test confirming it either (a) deliberately accepts any identity, or (b) fails closed.

A deployment that forgets to set issuer/SAN constraints will silently accept bundles from any OIDC identity. For a supply-chain security tool, this default-open behavior must be explicitly tested and documented, or changed to fail-closed.

**Fix:** Add a test that either:
- Confirms unconstrained verification is intended and returns the actual signer identity so callers can make decisions, OR
- Changes the default to fail-closed (require identity constraints) and tests that behavior

### CR-03: Verification Pipeline Has No Test for Missing or Tampered Bundle File

**File:** `cli/internal/verify/verify_test.go` and `cli/internal/verify/steps_test.go`
**Issue:** The test `TestPipelineVerify_MissingLockfile` tests a missing lockfile. However, there is no test for: (a) a missing bundle file (`*.sigstore.json`), (b) a corrupted bundle file (valid JSON but invalid Sigstore structure), or (c) a bundle signed for a different artifact digest. Since signature verification is the first security gate after hash-check, these negative test cases are critical. The mock-based tests in `steps_test.go` test the mock returning an error, but never exercise the actual code path that loads and parses bundles from disk.

**Fix:** Add tests:
```go
func TestPipelineVerify_MissingBundleFile(t *testing.T) {
    fix := newTestFixture(t)
    // Delete the bundle file
    os.Remove(fix.bundlePath)
    // Verify pipeline returns error mentioning bundle
}

func TestPipelineVerify_CorruptBundleJSON(t *testing.T) {
    fix := newTestFixture(t)
    os.WriteFile(fix.bundlePath, []byte("{invalid"), 0644)
    // Verify pipeline returns error, does not panic
}
```

## Warnings

### WR-01: Dead Helper Function `successMocks` Never Called

**File:** `cli/internal/verify/verify_test.go:99-112`
**Issue:** `successMocks()` is defined but never called anywhere in the test file. It returns a nil `*mockTlogLooker` and an empty `sha` string -- if it were ever used, the nil tlog looker would cause a panic in the pipeline. This is dead test code that misleads readers into thinking these mocks are being used for test setup.

**Fix:** Delete the `successMocks` function entirely, or fix and use it to DRY up the per-test mock construction.

### WR-02: Scanner Test Accepts Empty SHA-256 for Empty Skills

**File:** `cli/internal/scanner/scanner_test.go:213-230`
**Issue:** `TestScanner_EmptySkill` asserts `assert.Empty(t, results[0].SHA256)` for a skill with zero files and marks it as "clean". An empty SHA-256 means the scanner produces no integrity fingerprint for empty skills -- all empty skills are indistinguishable. If an attacker removes all files from a skill directory, the scanner would classify it as "clean" with no way to detect the modification. The test codifies this potentially dangerous behavior.

**Fix:** Either change scanner behavior to hash over an empty byte slice (producing the well-known SHA-256 of empty: `e3b0c44298...`), or change the test to verify the "empty skill" case produces a warning or distinct status rather than "clean".

### WR-03: Ecosystem Discovery Tests Are Platform-Dependent

**File:** `cli/internal/ecosystem/discovery_test.go:111-137`
**Issue:** `TestMCPAdapter_ParseConfig` seeds MCP config at both macOS and Linux paths but then notes "we accept 0 or 2 results" because the adapter calls `homeDir()` which resolves the real OS home directory against the in-memory filesystem. The `if len(skills) > 0` guard means this test literally cannot fail on any platform -- it is a no-op assertion.

**Fix:** Inject the home directory path into the adapter so the test is deterministic, or restructure the adapter to accept a filesystem and base path rather than calling `os.UserHomeDir()` internally.

### WR-04: Builder Tests Use Real Filesystem Instead of Afero

**File:** `cli/internal/builder/builder_test.go:43-60` (and most tests in this file)
**Issue:** Despite the CLAUDE.md convention that "All filesystem operations [use] `afero.Fs` for testability", `builder_test.go` uses `os.WriteFile`, `os.ReadFile`, `t.TempDir()`, and `os.Stat` throughout instead of afero. The `lockfile_test.go` also mixes `afero.NewOsFs()` with `os.ReadFile`. While `t.TempDir()` auto-cleans, this inconsistency means CI permission issues in temp directories could cause false test failures, and the tests don't validate the afero abstraction layer that production code uses.

**Fix:** Refactor `Builder` to accept `afero.Fs` (if not already), then use `afero.NewMemMapFs()` in tests for consistency.

### WR-05: No Tests for CLI Command Handlers

**File:** `cli/internal/cmd/` directory (31 files, 2 test files)
**Issue:** The `cmd/` directory has 31 command handler files but only 2 test files (`serviceurl_test.go`, `version_test.go`). The security-critical commands -- `verify.go`, `sign.go`, `publish.go`, `audit.go`, `policy.go` -- have zero test coverage at the command level. While the underlying packages have unit tests, the command handlers contain flag parsing, input validation, argument handling, and error formatting that is completely untested. A typo in flag binding, a missing `MarkFlagRequired`, or incorrect flag-to-function parameter mapping would go undetected.

**Fix:** Add smoke tests for each security-critical command that exercise flag parsing and verify proper error messages for missing required flags.

### WR-06: Trust Verifier Tests Use `time.Sleep` for Synchronization

**File:** `cli/internal/proxy/trust_verifier_test.go:211-214, 271, 325`
**Issue:** Multiple tests use `time.Sleep(100-500ms)` to wait for async verification goroutines to complete. This is inherently flaky -- on slow CI runners or under resource contention, the goroutine may not complete in time, causing intermittent test failures.

**Fix:** Use a channel, `sync.WaitGroup`, or polling loop with timeout to synchronize with the verification goroutine rather than fixed-duration sleeps. Alternatively, expose a `WaitForCompletion(skillID)` method on TrustVerifier for test use.

### WR-07: Lockfile Tampering Not Tested in Verification Pipeline

**File:** `cli/internal/verify/verify_test.go`
**Issue:** The verification pipeline reads `artifact_id` from the lockfile and uses it for tlog lookup. There is no test that verifies what happens when a lockfile has a valid SHA-256 hash but a mismatched `artifact_id` or `version`. An attacker who tampers with the lockfile's `artifact_id` field could redirect the tlog lookup to a different (legitimate) artifact entry, potentially bypassing the tlog verification step. The hash-check step verifies the artifact content, but the tlog step uses the lockfile's `artifact_id` as a lookup key without verifying it matches the artifact.

**Fix:** Add a test where the lockfile's `artifact_id` does not match the manifest's `id@version`, and verify the pipeline rejects it.

## Info

### IN-01: Only One Test Exercises JCS Canonicalization of Lockfiles

**File:** `cli/internal/builder/lockfile_test.go:113-130`
**Issue:** Only `TestLockfile_Canonical` verifies that written lockfiles are already in JCS canonical form. Since canonical serialization is a critical property for deterministic builds, consider adding a property-based test that writes a lockfile, shuffles JSON keys, and re-canonicalizes to verify round-trip stability.

**Fix:** Add additional canonicalization tests or a fuzz test.

### IN-02: YARA Engine Tests Require Real Filesystem

**File:** `cli/internal/yara/engine_test.go`
**Issue:** All YARA engine tests write rule files to `t.TempDir()` on the real filesystem rather than using afero. The YARA library likely requires real files for rule compilation, so this is unavoidable, but it should be documented.

**Fix:** Add a comment: `// YARA engine requires real filesystem for rule compilation; afero not applicable here.`

### IN-03: Inconsistent Test Style Between Packages

**File:** `cli/internal/credentials/credentials_test.go`
**Issue:** This file uses raw `if` + `t.Errorf` (stdlib style), while every other test file uses testify `assert`/`require`. This is a style inconsistency that does not affect correctness but makes the codebase less consistent.

**Fix:** Migrate `credentials_test.go` to testify for consistency.

## Missing Test Scenarios

### Security-Critical Gaps

1. **Path traversal in builder/collector**: No test that a source file path like `../../etc/passwd` is rejected or normalized during collection. The collector walks the filesystem but there is no test for directory traversal attempts that could include files outside the source tree.

2. **Policy DSL standard compiler injection**: The `CompileRuntime` function has injection prevention tests, but the standard `Compile` function has none. A malicious YAML policy file with embedded Rego escape sequences could inject arbitrary policy rules via the `message` or `except` fields.

3. **IOC feed content validation**: `FetchUpdatesWithClient` adds entries to the database from a remote feed without field validation (e.g., empty SHA-256, duplicate entries, excessively long descriptions). No tests verify input sanitization on fetched IOC data.

4. **Concurrent builder builds**: No test verifies that two concurrent `Build()` calls to the same output directory do not corrupt each other's output (file locking or mutual exclusion).

5. **Scanner partial file read failures**: No test for what happens when `FileOpener.Open()` returns an error for one file in a multi-file skill. Does the scanner skip the file, mark the skill as compromised, or abort?

6. **Empty or nil manifest capabilities in policy evaluation**: No test verifies behavior when `Capabilities` struct has nil slices vs empty slices for filesystem/network/secrets/tools.

7. **Proxy CONNECT handler with expired or invalid CA certificate**: No test for HTTPS interception when the proxy CA certificate is expired or malformed.

### Coverage Gaps

8. **CLI commands**: `audit.go`, `build.go`, `sign.go`, `verify.go`, `publish.go`, `policy.go`, `init.go`, `validate.go`, `login.go`, `logout.go`, `token.go`, `whoami.go`, `billing.go`, `usage.go` -- all zero test coverage.

9. **Proxy commands**: `proxy_start.go`, `proxy_stop.go`, `proxy_status.go`, `proxy_logs.go`, etc. -- zero test coverage.

10. **Tlog publish function**: `tlog/publish.go` -- not visible in `client_test.go` publish tests; unclear if `Publish()` top-level function edge cases (context cancellation, network timeout) are tested.

## Score: 6/10

The test suite has good breadth and covers the majority of packages. The core security properties (deterministic builds, fail-closed policy, hash verification, symlink rejection, provenance input validation, mid-session rug-pull detection) are well-tested. However, the absence of CLI command tests, the reliance on mocks without integration tests for the Sigstore verification chain, several platform-dependent or timing-dependent tests, and missing negative test cases for supply-chain attack vectors (path traversal, lockfile tampering, unconstrained identity verification, DSL injection) prevent a higher score. For a supply-chain security tool, the test suite must be held to a higher standard -- the tool's threat model demands that these gaps be filled before the tool can be trusted to protect others' supply chains.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (test-suite-reviewer)_
_Depth: deep_
