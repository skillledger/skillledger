---
component: cli/internal/verify
reviewed: 2026-05-07T00:00:00Z
depth: deep
files_reviewed: 6
files_reviewed_list:
  - cli/internal/verify/pipeline.go
  - cli/internal/verify/steps.go
  - cli/internal/verify/verify.go
  - cli/internal/verify/pipeline_test.go
  - cli/internal/verify/steps_test.go
  - cli/internal/verify/verify_test.go
findings:
  critical: 3
  warning: 4
  minor: 2
  total: 9
status: issues_found
---

# Verification Pipeline: Security Code Review

**Reviewed:** 2026-05-07
**Depth:** Deep (cross-file, call-chain tracing)
**Files Reviewed:** 6
**Status:** Issues Found

## Summary

The verification pipeline has a sound overall architecture: fail-closed default, sequential step ordering (hash -> signature -> tlog -> policy), and proper short-circuiting on failure. However, the review uncovered three critical issues -- a transparency log bypass, a nil-dereference crash path, and a TOCTOU race in manifest size checking -- along with several warnings around missing input validation that could lead to denial or confusion in production scenarios.

---

## Strengths

- **Fail-closed on unknown policy decision** (`steps.go:170-177`): The `default` case in `verifyPolicy` correctly denies on any unrecognized policy decision string. This is the right behavior for a security-critical pipeline.
- **Pipeline ordering is correct** (`verify.go:50-124`): Hash check -> signature -> tlog -> policy, and signature failure prevents policy evaluation (which would use an untrusted signer identity). Each step short-circuits on error.
- **SHA-256 cross-check between tlog and lockfile** (`steps.go:91-98`): Catches log entry substitution attacks (T-07-05).
- **Manifest size limit** (`verify.go:17,90`): DoS protection via `readFileLimited` before parsing (T-07-07).
- **Lockfile is required** (`verify.go:44-48`): Missing lockfile returns an error, not a skip. Fail-closed.
- **Test coverage is thorough**: Tests cover all pass/fail paths, skip-tlog, hash mismatch, missing lockfile, policy warn/deny/allow, and unknown policy decision.

---

## Critical Issues

### CR-01: Transparency Log Step Can Be Silently Bypassed via SkipTlog

**File:** `cli/internal/verify/verify.go:78`, `cli/internal/verify/pipeline.go:37,62,69-71`

**Issue:** The `skipTlog` flag completely eliminates the transparency log check with no compensating control. When `SkipTlog` is true, the pipeline silently skips step 2 and reports a passing result with no record that a critical verification step was omitted. There is no warning in the output, no annotation on the `VerifyResult`, and no policy guard that prevents `--skip-tlog` from being combined with a "strict" preset.

In `cmd/verify.go:59`, `skipTlog` is a user-supplied CLI flag with no restrictions. An attacker who compromises a CI environment variable or hook script can inject `--skip-tlog` and the pipeline will pass verification on an artifact that was never published to the transparency log -- the exact supply-chain attack the tlog is designed to prevent.

**Why it matters:** The transparency log is the core anti-substitution mechanism. If it can be silently bypassed via a flag with no audit trail or policy constraint, the entire value proposition of SkillLedger is undermined.

**Fix:**
1. When tlog is skipped, add an explicit step to `result.Steps` recording the skip, and add a warning to `result.Warnings`.
2. Add a `TlogSkipped bool` field to `VerifyResult` so downstream consumers (CI gates, SARIF reports) can detect and reject skip-tlog runs.
3. In the `strict` policy preset, deny verification when tlog is skipped.

```go
// verify.go:78 -- replace the current block
if p.skipTlog {
    result.Steps = append(result.Steps, StepResult{
        Name:   "transparency-log",
        Passed: true,
        Detail: "SKIPPED by --skip-tlog flag (offline mode)",
    })
    result.Warnings = append(result.Warnings, "transparency log verification was skipped")
    result.TlogSkipped = true
} else {
    tlogStep, err := p.verifyTlog(ctx, lf.ArtifactID, lf.SHA256)
    result.Steps = append(result.Steps, tlogStep)
    if err != nil {
        result.Passed = false
        log.Info().Bool("passed", false).Msg("verification complete")
        return result, nil
    }
}
```

### CR-02: Nil Pointer Dereference When sigVerifier Returns nil VerifyResult Without Error

**File:** `cli/internal/verify/verify.go:124`, `cli/internal/verify/steps.go:53`

**Issue:** `verifySignature` returns `(*signer.VerifyResult, error)`. The code at `verify.go:124` accesses `sigResult.SignerIdentity` and `sigResult.Issuer` without a nil check. If the `SignatureVerifier` implementation returns `(nil, nil)` -- which is a valid Go return and possible from a buggy or mocked implementation -- this will panic with a nil pointer dereference.

The real `signer.Verifier.Verify` can produce an empty `VerifyResult` with zero-value fields (`SignerIdentity: ""`) at `verifier.go:128-137` when `result.VerifiedIdentity` is nil, which does not crash but causes the policy step to receive an empty signer identity, potentially bypassing identity-based policy rules.

**Why it matters:** In a security pipeline, a nil-dereference crash on an edge case is a denial-of-service. More subtly, an empty signer identity being silently accepted by the policy engine could allow unsigned artifacts to pass identity-based policy rules.

**Fix:**
```go
// verify.go, after line 75 (after signature step succeeds)
if sigResult == nil {
    result.Passed = false
    result.Steps = append(result.Steps, StepResult{
        Name:   "signature",
        Passed: false,
        Error:  "signature verification returned no result",
    })
    return result, nil
}
if sigResult.SignerIdentity == "" {
    result.Passed = false
    result.Steps = append(result.Steps, StepResult{
        Name:   "signature",
        Passed: false,
        Error:  "signature verification succeeded but no signer identity was extracted",
    })
    return result, nil
}
```

### CR-03: TOCTOU Race in readFileLimited

**File:** `cli/internal/verify/verify.go:144-153`

**Issue:** `readFileLimited` calls `os.Stat` to check the file size, then calls `os.ReadFile` to read the file. Between these two calls, an attacker with local filesystem access can replace the small file with a large one (or a symlink to `/dev/zero`). The stat check passes, but `os.ReadFile` reads the (now large) file, defeating the DoS protection.

Additionally, `os.ReadFile` follows symlinks. An attacker could create a symlink at the manifest path pointing to an arbitrary file on disk (e.g., `/etc/shadow`), and the file contents would be read and potentially exposed in error messages from `manifest.ParseAndValidate`.

**Why it matters:** The manifest size limit is a stated security control (T-07-07). A TOCTOU race makes it bypassable. The symlink issue additionally risks information disclosure.

**Fix:** Use `io.LimitedReader` instead of stat-then-read:
```go
func readFileLimited(path string, maxBytes int64) ([]byte, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    // Check that we opened a regular file, not a symlink target or device
    info, err := f.Stat()
    if err != nil {
        return nil, err
    }
    if !info.Mode().IsRegular() {
        return nil, fmt.Errorf("file %s is not a regular file", path)
    }

    lr := io.LimitReader(f, maxBytes+1)
    data, err := io.ReadAll(lr)
    if err != nil {
        return nil, err
    }
    if int64(len(data)) > maxBytes {
        return nil, fmt.Errorf("file %s exceeds size limit (%d bytes max)", path, maxBytes)
    }
    return data, nil
}
```

---

## Warnings

### WR-01: No Validation of Lockfile Fields Before Use

**File:** `cli/internal/verify/verify.go:45-51`

**Issue:** After `builder.ReadLockfile` returns, the code immediately uses `lf.SHA256` (line 51) and `lf.ArtifactID` (line 79) without validating that these fields are non-empty or well-formed. A lockfile with `"sha256": ""` would cause `computeAndCompareHash` to compare against an empty string, which will always fail -- but with a confusing error message (`hash mismatch: expected , got abc123...`). A lockfile with an empty `ArtifactID` would send an empty string to the tlog lookup, which depending on the server implementation could return unexpected results.

**Fix:** Validate lockfile fields immediately after reading:
```go
if lf.SHA256 == "" || len(lf.SHA256) != 64 {
    return nil, fmt.Errorf("lockfile has invalid or empty SHA256 field")
}
if lf.ArtifactID == "" {
    return nil, fmt.Errorf("lockfile has empty ArtifactID field")
}
```

### WR-02: NewPipeline Accepts Nil Dependencies Without Error

**File:** `cli/internal/verify/pipeline.go:76-86`

**Issue:** `NewPipeline` accepts nil values for `sigVerifier`, `tlogLooker`, and `policyEval`. If any of these is nil, calling `Verify` will panic with a nil pointer dereference at `steps.go:53`, `steps.go:81`, or `steps.go:132`. The comment says "use nil-safe mocks for testing individual steps" but the constructor should defend against nil in production use.

**Fix:** Either validate non-nil at construction time, or add nil guards at each step:
```go
func NewPipeline(sv SignatureVerifier, tl TlogLooker, pe PolicyEvaluator, opts ...PipelineOption) (*Pipeline, error) {
    if sv == nil || pe == nil {
        return nil, fmt.Errorf("sigVerifier and policyEval must not be nil")
    }
    // tl may be nil if skipTlog is set, but validate at Verify time
    ...
}
```

### WR-03: computeAndCompareHash Uses os.Open Instead of afero.Fs

**File:** `cli/internal/verify/steps.go:21`

**Issue:** The project convention (CLAUDE.md) states: "All filesystem operations through `afero.Fs` for testability." However, `computeAndCompareHash` uses `os.Open` directly, making it impossible to test with an in-memory filesystem and inconsistent with the rest of the codebase. Additionally, `readFileLimited` in `verify.go:144` uses `os.Stat` and `os.ReadFile` directly.

**Fix:** Accept `afero.Fs` as a parameter and use `fs.Open()` instead of `os.Open()`. The `Pipeline` struct should hold an `afero.Fs` field.

### WR-04: VerifyInput.SkipTlog Field is Unused -- Dual Source of Truth

**File:** `cli/internal/verify/pipeline.go:37`, `cli/internal/verify/pipeline.go:62`

**Issue:** `VerifyInput` has a `SkipTlog` field (line 37), and `Pipeline` has its own `skipTlog` field (line 62) set via `WithSkipTlog`. In `verify.go`, the pipeline uses `p.skipTlog` (line 78), completely ignoring `input.SkipTlog`. In `cmd/verify.go:129,139`, both are set independently. This is a dual source of truth: a caller could set `input.SkipTlog = true` but forget `WithSkipTlog(true)`, and tlog would NOT be skipped, silently violating the caller's intent.

**Fix:** Remove `SkipTlog` from `VerifyInput` and only use the `WithSkipTlog` pipeline option. Or, have `Verify()` read from `input.SkipTlog` and remove the pipeline field.

---

## Minor

### MN-01: Unused Function successMocks

**File:** `cli/internal/verify/verify_test.go:99-112`

**Issue:** `successMocks()` is defined but never called. It returns a `sha` variable initialized to `""` which would need to be set per test, making it unclear how it was intended to be used.

**Fix:** Remove the dead code.

### MN-02: Hash Comparison Is Not Constant-Time

**File:** `cli/internal/verify/steps.go:35`

**Issue:** The SHA-256 comparison `hexDigest != expectedSHA256` uses a non-constant-time string comparison. While timing attacks on local hash comparisons are low-risk (the attacker would need to observe sub-microsecond timing differences over a local function call), this is inconsistent with the project's security posture (the project uses `hmac.compare_digest` for API key comparison in the Python service).

**Fix:** Use `subtle.ConstantTimeCompare([]byte(hexDigest), []byte(expectedSHA256))` from `crypto/subtle`.

---

## Score: 6/10

The pipeline's architecture is sound -- correct step ordering, fail-closed on unknown decisions, proper short-circuiting. But the three critical findings are real security gaps: the silent tlog bypass (CR-01) undermines the core supply-chain security guarantee, the nil-dereference path (CR-02) is a crash/bypass vector, and the TOCTOU race (CR-03) makes a stated security control bypassable. The warnings around missing input validation (WR-01, WR-02) represent defense-in-depth gaps that should exist in security-critical code.
