# Signing & Provenance Code Review: `cli/internal/signer/`

**Reviewed:** 2026-05-07
**Depth:** deep (cross-file call-chain analysis)
**Files Reviewed:** 6
**Reviewer:** Claude (cryptography specialist)

---

## Strengths

1. **Fail-closed on missing Rekor entry** (`signer.go:146-148`): The signer refuses to return a result if the bundle lacks a transparency log entry. This is correct for non-repudiation.

2. **Ephemeral keypair never persisted** (`signer.go:98-105`): Ed25519 keypair is generated in-memory via sigstore-go, never written to disk. Good key hygiene.

3. **DSSE envelope with correct payload type** (`signer.go:93-96`): Uses `application/vnd.in-toto+json` which is the canonical DSSE content type for in-toto statements.

4. **Provenance input validation** (`provenance.go:28-45`): All required fields are validated, including hex format and length of the artifact digest.

5. **Observer timestamps for key rotation** (`verifier.go:88-92`): Requiring SCTs, tlog entries, and observer timestamps enables verification after signing certificate expiry. Correct Sigstore usage.

6. **Partial identity constraint validation** (`verifier.go:62-65`): The XOR check that rejects issuer-only or SAN-only configurations prevents a silent downgrade of identity verification.

7. **Bundle file written with 0600 permissions** (`signer.go:167`): Restricts read access to the owner.

---

## Issues

### Critical -- crypto bugs, verification bypasses

#### CR-01: Proxy creates verifier with NO identity constraints -- any signer accepted

**File:** `cli/internal/cmd/proxy_start.go:159`
**Issue:** The proxy (runtime trust verification for MCP servers) creates `signer.NewVerifier()` with zero options. This means the Sigstore bundle verification accepts signatures from ANY Fulcio-issued certificate -- any Google account, any GitHub Actions workflow, any GitLab CI pipeline. An attacker who signs a malicious skill with their own OIDC identity will pass signature verification in the proxy path.

The `verify` CLI command at least allows `--expected-issuer` and `--expected-identity` flags (verify.go:86-91), but the proxy -- which is the *runtime* enforcement path -- has no mechanism to pass identity constraints at all.

**Why it matters:** This is a verification bypass. The proxy is the enforcement point for installed skills at runtime. If it accepts any valid Sigstore signature regardless of signer identity, an attacker can sign a substituted skill with their own credentials and it will pass all checks.

**Fix:** The proxy must accept and propagate expected issuer/SAN constraints, either from the lockfile metadata or from proxy configuration:
```go
// proxy_start.go - must propagate identity constraints
sigVerifier := signer.NewVerifier(
    signer.WithExpectedIssuer(expectedIssuer),
    signer.WithExpectedSAN(expectedSAN),
)
```

#### CR-02: verify CLI silently drops identity check when only one of issuer/identity is provided

**File:** `cli/internal/cmd/verify.go:86`
**Issue:** The condition `if expectedIssuer != "" && expectedIdentity != ""` means that if a user passes `--expected-issuer` without `--expected-identity` (or vice versa), the flag is silently ignored and verification proceeds with NO identity constraints. The signer package correctly rejects this case (verifier.go:62-65), but the CLI command never reaches that check -- it simply doesn't pass the option at all.

**Why it matters:** A user who types `skillledger verify --expected-issuer https://accounts.google.com artifact.tar.gz` believes they are restricting verification to Google-issued certificates. In reality, any signer is accepted. This is a fail-open behavior that contradicts the project's fail-closed requirement.

**Fix:** Use `||` to detect partial configuration and error early at the CLI level:
```go
if (expectedIssuer != "") != (expectedIdentity != "") {
    return fmt.Errorf("both --expected-issuer and --expected-identity must be provided together")
}
if expectedIssuer != "" {
    verifierOpts = append(verifierOpts,
        signer.WithExpectedIssuer(expectedIssuer),
        signer.WithExpectedSAN(expectedIdentity),
    )
}
```

#### CR-03: Provenance `invocationId` is not unique -- derived from artifact digest prefix

**File:** `provenance.go:77`
**Issue:** `invocationId` is set to `input.ArtifactDigest[:12]`, which is just the first 12 hex characters of the artifact hash. The SLSA spec defines `invocationId` as a unique identifier for the build invocation. Since the artifact digest is deterministic for the same content, rebuilding the same artifact produces the same `invocationId`. This means two distinct build invocations (different times, different environments) that produce the same artifact are indistinguishable in provenance records, breaking SLSA audit trail requirements.

**Why it matters:** SLSA provenance is supposed to let you trace which specific build produced an artifact. If two builds of the same source produce the same `invocationId`, you cannot distinguish them in audit logs or determine which build environment was compromised.

**Fix:** Use a proper unique identifier -- a UUID or a combination of timestamp + builder ID + random nonce:
```go
"invocationId": fmt.Sprintf("%s-%s", input.BuiltAt, uuid.New().String()[:8]),
```

### Important -- provenance gaps, error handling

#### WR-01: No validation that `BuiltAt` is a valid RFC 3339 timestamp

**File:** `provenance.go:37-39`
**Issue:** The code checks that `BuiltAt` is non-empty but never validates it is a valid RFC 3339 timestamp. An arbitrary string like `"yesterday"` or `"2026-13-99"` will be embedded into the SLSA provenance `startedOn` field. Downstream verifiers or SLSA evaluators that parse this timestamp will fail or behave unpredictably.

**Fix:**
```go
if _, err := time.Parse(time.RFC3339, input.BuiltAt); err != nil {
    return nil, fmt.Errorf("build timestamp must be valid RFC3339: %w", err)
}
```

#### WR-02: No validation that `Repository` is a valid URL

**File:** `provenance.go:32-33`
**Issue:** `Repository` is checked for emptiness but not for URL validity. A string like `"not a url"` will be embedded as the source URI in the SLSA provenance. The `resolvedDependencies[].uri` field in SLSA v1 provenance should be a valid URI per the spec. Malformed URIs may cause failures in downstream SLSA verification tools.

**Fix:**
```go
if _, err := url.Parse(input.Repository); err != nil {
    return nil, fmt.Errorf("repository must be a valid URL: %w", err)
}
```

#### WR-03: `BuilderVersion` not validated -- empty string silently accepted

**File:** `provenance.go:13-21` (struct definition) and `provenance.go:27-98` (no check)
**Issue:** All other fields except `Directory` and `BuilderVersion` are validated for non-emptiness. `BuilderVersion` is embedded into provenance as the builder version but is never checked. An empty string produces a provenance record with `"version": {"skillledger": ""}`, which is misleading. This inconsistency suggests either `BuilderVersion` should be validated or there should be a documented reason it is optional.

**Fix:** Add validation:
```go
if input.BuilderVersion == "" {
    return nil, fmt.Errorf("builder version is required")
}
```

#### WR-04: `SignAndWrite` uses `os.WriteFile` instead of `afero.Fs`

**File:** `signer.go:167`
**Issue:** The project convention (documented in CLAUDE.md) states: "All filesystem operations through `afero.Fs` for testability." The `SignAndWrite` method directly uses `os.WriteFile`, making it impossible to test without touching the real filesystem. The `Sign` method is testable in isolation, but `SignAndWrite` is not.

**Fix:** Accept an `afero.Fs` parameter or inject it via the `Signer` struct, consistent with the rest of the codebase.

#### WR-05: `Verifier.Verify` returns empty `VerifyResult` fields without error when identity is absent

**File:** `verifier.go:128-141`
**Issue:** When no identity constraints are set (both `expectedIssuer` and `expectedSAN` are empty), `result.VerifiedIdentity` may be nil depending on the sigstore-go implementation. In that case, `vr.SignerIdentity` and `vr.Issuer` will be empty strings, and `vr.SignedAt` will be the zero time. The caller (steps.go:62) formats this as `"Signed by  (issuer: )"` -- a confusing empty-identity message that gives no useful information. More importantly, downstream policy evaluation (steps.go:127-128) receives empty strings for `signed_by` and `issuer`, which may cause policy rules to match incorrectly.

**Fix:** Log a warning when identity fields are empty, and consider requiring identity constraints for policy evaluation:
```go
if vr.SignerIdentity == "" {
    log.Warn().Msg("verified signature but signer identity is unknown -- consider setting --expected-issuer and --expected-identity")
}
```

### Minor -- style

#### IN-01: Unused `json` import in test is fine but inconsistent

**File:** `provenance_test.go:4`
**Issue:** The `encoding/json` import is used for `json.Unmarshal` in `TestProvenance_Serialization` to verify the output is valid JSON. This works but is inconsistent with the production code which uses `protojson` for all serialization.

#### IN-02: Comment says "Ed25519" but algorithm choice is configurable

**File:** `signer.go:21, 99`
**Issue:** The struct doc and inline comment both say "ephemeral Ed25519 keypair," but the algorithm is specified via a constant (`protocommon.PublicKeyDetails_PKIX_ED25519`). If this constant is ever changed, the comments become misleading.

#### IN-03: Test helper uses non-realistic `Ref` value

**File:** `provenance_test.go:18`
**Issue:** `Ref: "abc123def456"` is only 12 characters, not a full 40-character git commit SHA. While the code does not validate `Ref` format, this test value could mask issues if ref validation is later added.

---

## Score: 5/10

The core signing flow is structurally sound -- ephemeral keys, DSSE envelopes, Rekor inclusion enforcement. However, there are significant verification gaps. The proxy runtime path (CR-01) accepts any signer identity, the CLI silently drops partial identity constraints (CR-02), and provenance `invocationId` is not unique across builds (CR-03). For a supply-chain security tool where the entire value proposition is "verify that artifacts come from trusted sources," these identity verification gaps are serious. The provenance generation also lacks input validation for timestamps and URLs that will be consumed by downstream SLSA verifiers.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (cryptography specialist)_
_Depth: deep_
