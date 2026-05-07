# SkillLedger Codebase Review

**Date:** 2026-05-07
**Reviewers:** 22 parallel specialized agents
**Scope:** Full codebase (708 files, 122K lines)
**Components:** Go CLI, Python Service, Dashboard, Transparency Log, CI/CD, Hooks, Infrastructure

---

## Executive Summary

SkillLedger has solid architectural foundations — clean package separation, correct use of cryptographic primitives, and good framework patterns. However, a security-critical supply-chain tool requires a higher bar than "architecturally sound." This review found **systemic security gaps** that undermine the tool's core promise: several verification paths are fail-open, the transparency log client performs no cryptographic verification, and the policy engine is vulnerable to injection.

**Composite Score: 5.4/10** (22 reviewers, all complete)

| Component | Score | Reviewer Count |
|-----------|-------|----------------|
| CLI Commands | 6/10 | 1 |
| Deterministic Builder | 7/10 | 1 |
| Signer & Provenance | 5/10 | 1 |
| Verify Pipeline | 6/10 | 1 |
| Policy Engine | 5/10 | 1 |
| Ecosystem Adapters | 5/10 | 1 |
| Tlog Client | **3/10** | 1 |
| IOC + YARA | 6/10 | 1 |
| Scanner + SBOM | 5/10 | 1 |
| Schema/Canon/Manifest/Output | 7/10 | 1 |
| Python Auth + Config | 6/10 | 1 |
| Python Models + DB | 5/10 | 1 |
| Python Routers | 5/10 | 1 |
| Python Tests | 6/10 | 1 |
| Python Migrations | 5/10 | 1 |
| Shell Hooks | 5/10 | 1 |
| GitHub Actions CI/CD | **3/10** | 1 |
| Docker Deployment | 5/10 | 1 |
| Transparency Log Server | 6/10 | 1 |
| Spec + Schemas | 6/10 | 1 |
| Dashboard Frontend | 6/10 | 1 |
| Go Tests | 6/10 | 1 |
| Go CLI (broad) | 6/10 | 1 |
| Python Service (broad) | 5/10 | 1 |
| Infra (broad) | 5/10 | 1 |

---

## P0: BLOCKERS — Must Fix Before Any Production Use

These findings defeat the core security guarantees SkillLedger claims to provide.

### B-01: Transparency Log Client Has No Cryptographic Verification
- **Location:** `cli/internal/tlog/` (entire package)
- **Score Impact:** 3/10 (lowest)
- **Confirmed by:** 2 reviewers (tlog client + broad CLI)
- **Issue:** The CLI's tlog client is a plain JSON HTTP client. It fetches server-asserted values (sha256, log_index) with zero Merkle proof verification. No checkpoint signatures, no inclusion proofs, no consistency proofs. A proper Tessera-integrated client exists at `log/internal/logclient/` but the CLI verification pipeline never uses it.
- **Impact:** A compromised FastAPI service can forge any log entry. The entire transparency log is security theater at the CLI level.
- **Fix:** Wire the CLI verification pipeline to use `log/internal/logclient/` with proper proof verification, or port its proof logic into `cli/internal/tlog/`.

### B-02: Policy Engine Vulnerable to Rego Injection
- **Location:** `cli/internal/policy/dsl/compiler.go:83-87`
- **Confirmed by:** 1 reviewer (policy engine)
- **Issue:** YAML map keys (category names) and `message` fields are interpolated directly into Rego code without sanitization. A crafted `skillledger.yaml` can inject arbitrary Rego that forces "allow" on everything.
- **Impact:** Complete policy bypass via malicious manifest. The policy engine's equivalent of SQL injection.
- **Fix:** Validate category names against `^[a-z_]+$` regex. Escape newlines in message fields. Or use Rego AST construction instead of string interpolation.

### B-03: IOC Database Only Checks Composite Hash, Not Individual Files
- **Location:** `cli/internal/scanner/scanner.go:159-164`
- **Confirmed by:** 1 reviewer (scanner + SBOM)
- **Issue:** IOC checker only receives the composite skill-level hash (hash of concatenated file hashes). Individual file hashes are computed but never checked against IOC entries. A malicious file injected into a legitimate skill won't match.
- **Impact:** Primary malware detection mechanism is effectively useless for the most common attack vector (single-file injection).
- **Fix:** Check each individual file hash against the IOC database in addition to the composite hash.

### B-04: GitHub Actions Script Injection in Every Composite Action
- **Location:** `.github/actions/build/action.yml:54`, `sign/action.yml:31,36`, `verify/action.yml:31,37,38`
- **Score Impact:** 3/10 (tied lowest)
- **Confirmed by:** 2 reviewers (CI/CD + broad infra)
- **Issue:** All composite actions interpolate untrusted inputs (`${{ inputs.skill-dir }}`, `${{ inputs.artifact-path }}`, etc.) directly into shell scripts via GitHub expression syntax.
- **Impact:** Any repository calling these actions can inject arbitrary commands into the CI runner. Ironic for a supply-chain security tool.
- **Fix:** Pass all inputs through environment variables instead of `${{ }}` interpolation.

### B-05: Path Traversal in Artifact Filename
- **Location:** `cli/internal/builder/archive.go:89-93`
- **Confirmed by:** 1 reviewer (builder)
- **Issue:** `ContentAddressedName` uses `id` and `version` from user-controlled YAML directly in the filename. `id = "../../../tmp/evil"` writes artifact outside `outputDir`.
- **Fix:** `filepath.Base(id)` or reject IDs containing `/`, `\`, or `..`.

---

## P1: CRITICAL — Security Vulnerabilities Requiring Immediate Attention

### Authentication & Authorization

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-01 | `service/.../config.py:25` | JWT secret defaults to `""` — complete auth bypass | **4 reviewers** |
| C-02 | `service/.../main.py:45-76` | CORS middleware configured but never added to app | **3 reviewers** |
| C-03 | `service/.../auth_router.py:163` | OTP hash comparison not constant-time (timing oracle) | 2 reviewers |
| C-04 | `dashboard/.../auth.ts:32-45` | SAML callback accepts arbitrary tokens — no server validation | 1 reviewer |
| C-05 | `cli/.../cmd/proxy_start.go:159` | Proxy verifier accepts any Fulcio certificate — no identity check | 1 reviewer |
| C-06 | `cli/.../cmd/verify.go:86` | `--expected-issuer` alone silently drops constraint (fail-open) | 2 reviewers |

### Verification Pipeline

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-07 | `cli/.../verify/verify.go:78` | `--skip-tlog` silently disables tlog — no audit trail | 1 reviewer |
| C-08 | `cli/.../verify/steps.go:35,91` | Hash comparison uses `!=` not `subtle.ConstantTimeCompare` | 1 reviewer |
| C-09 | `cli/.../verify/verify.go:144-153` | TOCTOU race between `os.Stat` and `os.ReadFile` | 2 reviewers |
| C-10 | `cli/.../verify/steps.go:21` | Verification bypasses `afero.Fs`, uses `os.Open` directly | 1 reviewer |

### Transparency Log

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-11 | `log/.../main.go:61` | No authentication on `/add` endpoint | 2 reviewers |
| C-12 | `log/.../entry.go:36-38` | `content_address` only checks `sha256-` prefix, not hash format | 1 reviewer |
| C-13 | `log/.../entry.go:29-43` | `publisher` field not validated — anonymous entries accepted | 1 reviewer |
| C-14 | `cli/.../tlog/lookup.go:27` | Path traversal — `artifactID` in URL without `url.PathEscape()` | 2 reviewers |

### Infrastructure

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-15 | `docker-compose.yml:30-31,63` | Hardcoded default admin key + JWT secret in dev compose | 2 reviewers |
| C-16 | `log/Dockerfile` | Log service (trust anchor!) runs as root | 2 reviewers |
| C-17 | `.github/workflows/skillledger-ci.yml:71` | API key passed as CLI argument — visible in process list | 2 reviewers |
| C-18 | All GH workflows | No third-party actions pinned to SHA (ironic for SLSA-3 tool) | 2 reviewers |
| C-19 | All hooks | `SKILLLEDGER_SERVICE_URL` env var hijacking — redirect to malicious server | 1 reviewer |
| C-20 | All hooks | `SKILLLEDGER_SKIP_TLOG` env var bypass | 1 reviewer |

### Data Layer

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-21 | All FK declarations | No `ondelete` cascade — entity deletion crashes with IntegrityError | 1 reviewer |
| C-22 | `service/.../db.py:25-28` | `get_session()` no rollback on exception — silent data loss | 2 reviewers |
| C-23 | `service/.../webhooks.py:47-67` | Stripe webhook idempotency TOCTOU race | 2 reviewers |

### Detection

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-24 | `cli/.../yara/engine.go:54-66` | TOCTOU in YARA symlink validation — reads unresolved path | 1 reviewer |
| C-25 | `cli/.../ioc/ioc.go:101-111` | IOC hash lookup case-sensitive — detection bypass | 1 reviewer |
| C-26 | `cli/.../scanner/scanner.go:132-145` | No symlink detection or path traversal validation in scanner | 1 reviewer |
| C-31 | `cli/.../ecosystem/adapter.go:136-160` | Symlink traversal in `collectFiles` — reads arbitrary files (builder has fix, adapters don't) | 1 reviewer |
| C-32 | `cli/.../ecosystem/adapter.go:218-227` | Unsanitized MCP server names from untrusted JSON — null bytes, path separators | 1 reviewer |

### Schema & Validation

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-33 | All schemas | No `maxLength`/`maxItems` on any field — DoS via unbounded manifests | 1 reviewer |
| C-34 | `capabilities.schema.json:12,28` | Capability scope patterns allow path traversal (`write:../../../etc/passwd`) | 1 reviewer |
| C-35 | `core.schema.json:16` | `id` pattern allows single-char IDs — collision/squatting risk | 1 reviewer |

### Other

| ID | Location | Issue | Reviewers |
|----|----------|-------|-----------|
| C-27 | `cli/.../provenance.go:77` | `invocationId` from artifact digest — non-unique, violates SLSA spec | 1 reviewer |
| C-28 | `cli/.../cmd/proxy_policy.go:122-162` | `proxy policy set` and `preset` report success but write nothing | 1 reviewer |
| C-29 | `dashboard/.../billing/page.tsx:283` | Open redirect via `billingInfo.portal_url` — no domain validation | 1 reviewer |
| C-30 | `cli/.../manifest/parse.go:53-56` | `ParseAndValidate` returns `(nil, errors, nil)` — nil-deref crash | 1 reviewer |

---

## P2: IMPORTANT — Should Fix Before Production

### Missing Functionality
- No rate limiting on log `/add` endpoint
- No pagination on `GET /publishers`
- No email format validation on registration (use `EmailStr`)
- No connection pool configuration (`pool_pre_ping`, tuning)
- SBOM missing `version` field, `bom-ref` identifiers
- Dashboard: no RBAC checks — viewer sees admin actions
- Dashboard: token refresh failure doesn't force logout
- Dashboard: fixed `limit: 200` silently truncates violations

### Error Handling
- Multiple `io.ReadAll` without `LimitReader` across Go HTTP clients
- `ResolveEpoch` silently swallows invalid `SOURCE_DATE_EPOCH`
- `sync.Once` validator — permanent failure on init error
- Text mode output swallows `fmt.Fprintf` write errors
- No error handling on Stripe API calls in billing router
- EE module import crashes webhook handler if not installed

### Convention Violations
- Verify pipeline uses `os.Open`/`os.ReadFile` instead of `afero.Fs` (4 locations)
- Signer uses `os.WriteFile` instead of `afero.Fs`
- `config.py:21` `_resolve_database_url()` at import time, not instantiation
- `main.py:76` module-level `app = create_app()` defeats factory pattern
- `saml_config.py:6` PostgreSQL-specific JSON import breaks SQLite fallback

### Missing Indexes
- `api_keys.publisher_id` — full table scan on every auth request
- `refresh_tokens.user_id`, `user_api_keys.user_id`, `org_memberships.org_id`

### Test Gaps (Python)
- No test for revoked API key rejection
- No test for inactive publisher rejection
- No test for expired JWT rejection
- No test for refresh-token-as-access-token (type confusion)
- `test_ingest.py` and `test_threat_library.py` are identical duplicate files
- Massive fixture duplication across 18 test files
- 16 missing test scenarios identified (see Python Tests section)

### Test Gaps (Go)
- **31 CLI command files, only 2 have tests** — zero coverage on `verify`, `sign`, `publish`, `audit`, `policy`
- No test for zero identity constraints in verifier (default-open path)
- No test for corrupted/missing Sigstore bundle files
- No test for `artifact_id` tampering in lockfile
- `builder_test.go` uses `os.Setenv` (not `t.Setenv`) — parallel test isolation broken
- Builder tests use real filesystem despite `afero.Fs` convention
- No test for path traversal in collector
- No test for DSL compiler injection
- No test for concurrent build safety

---

## P3: MINOR — Polish Items

- Inconsistent `fmt.Println` vs `fmt.Fprintln` across commands
- Multiple `headerStyle` declarations
- Unused `secrets` import in `publisher.py`
- Mixed `Optional[str]` vs `str | None` annotation styles
- Duplicate date-formatting functions across 4 dashboard files
- `gzip.DefaultCompression` not pinned — cross-Go-version determinism risk
- SARIF rule ordering from map iteration is non-deterministic
- Pre-rendered ANSI icons corrupt piped output
- `IocHash.reported_at` stored as string instead of DateTime

---

## Cross-Cutting Themes

### 1. Fail-Open vs Fail-Closed
The project claims fail-closed verification, but multiple paths silently degrade:
- `--skip-tlog` with no audit trail
- `--expected-issuer` without `--expected-identity` drops the check
- Empty JWT secret allows token forging
- Proxy verifier accepts any certificate
- IOC only checks composite hash

### 2. Symlink Protection Inconsistency
The builder has `LstatIfPossible` symlink detection, but it was never applied to:
- Ecosystem adapters (`collectFiles`)
- Scanner (`scanSkill`)
- YARA engine (reads unresolved path after checking resolved)
This is a systematic pattern where defense was implemented once but not propagated.

### 3. Environment Variable Attack Surface
Hooks and CLI accept env vars that can redirect verification to attacker servers (`SKILLLEDGER_SERVICE_URL`) or disable checks (`SKILLLEDGER_SKIP_TLOG`). For a tool whose threat model includes compromised CI, this is a fundamental design issue.

### 4. TOCTOU Races
At least 5 TOCTOU vulnerabilities found across the codebase:
- Builder: Walk stat vs Open
- Verify: stat vs ReadFile
- YARA: symlink check vs file read
- Audit: path validation vs file creation
- Webhooks: SELECT vs INSERT idempotency

### 5. Supply-Chain Irony
A supply-chain security tool that:
- Doesn't pin its own CI dependencies to SHA
- Has script injection in every composite action
- Passes API keys as CLI arguments
- Uses beta auth middleware in production

### 6. Schema as First Line of Defense — Missing
Schemas accept unbounded strings, path traversal in capabilities, shell metacharacters in env keys, single-char IDs, and leading-zero versions. For a tool that accepts manifests from untrusted sources, the schema should reject structurally invalid inputs before they reach Go code.

### 7. Consistency Gaps
- Admin key uses `hmac.compare_digest` but OTP comparison uses `!=`
- Admin key in plaintext memory while all other keys are hashed
- `get_admin_or_publisher` never falls back to publisher (misleading name)
- Some packages use `afero.Fs`, verification pipeline uses raw `os`

---

## Recommended Fix Priority

**Week 1 (Blockers):**
1. Wire CLI tlog to use proper Merkle proof verification (B-01)
2. Sanitize Rego compilation inputs (B-02)
3. Check individual file hashes against IOC database (B-03)
4. Fix GH Actions script injection — use env vars (B-04)
5. Sanitize artifact filename construction (B-05)

**Week 2 (Auth + Verification):**
6. Fail-closed on empty JWT secret (C-01)
7. Add CORS middleware (C-02)
8. Constant-time OTP comparison (C-03)
9. Validate SAML callback tokens server-side (C-04)
10. Add identity constraints to proxy verifier (C-05)
11. Fix `--expected-issuer` / `--expected-identity` coupling (C-06)

**Week 3 (Infrastructure + Data):**
12. Add auth to log `/add` endpoint (C-11)
13. Log container non-root (C-16)
14. Pin GH Actions to SHA (C-18)
15. Remove hardcoded dev secrets (C-15)
16. Add `ondelete` cascades (C-21)
17. Fix `get_session()` rollback (C-22)

**Week 4 (Hardening):**
18. `--skip-tlog` audit trail + policy guard (C-07)
19. Constant-time hash comparison in verify (C-08)
20. URL-encode `artifactID` in tlog lookups (C-14)
21. Fix IOC hash case sensitivity (C-25)
22. Add symlink/path traversal checks to scanner (C-26)
23. Rate limiting on log endpoint
24. Missing DB indexes

---

## Methodology

22 specialized code review agents dispatched in parallel:

**Go CLI (10):** Commands, Builder, Signer, Verify Pipeline, Policy Engine, Ecosystem Adapters, Tlog Client, IOC+YARA, Scanner+SBOM, Schema/Canon/Manifest/Output

**Python Service (5):** Auth+Config, Models+DB, Routers, Tests, Migrations+App Factory

**Infrastructure (7):** Shell Hooks, GitHub Actions, Docker Deployment, Tlog Server, Spec+Schemas, Dashboard, Go Tests

Plus 3 broad-scope validators (Go CLI, Python Service, Infra) for cross-validation.

Multiple independent reviewers flagged the same issues, increasing confidence:
- JWT empty secret: 4 reviewers
- CORS never applied: 3 reviewers
- Script injection in GH Actions: 2 reviewers
- Log `/add` no auth: 2 reviewers
- Log container root: 2 reviewers
- Tlog no proof verification: 2 reviewers
