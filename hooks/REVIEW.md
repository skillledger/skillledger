---
reviewed: 2026-05-07T10:00:00Z
depth: deep
files_reviewed: 6
files_reviewed_list:
  - hooks/claude-code-hook.sh
  - hooks/generic-hook.sh
  - hooks/install.sh
  - hooks/mcp-hook.sh
  - hooks/npm-hook.sh
  - hooks/openclaw-hook.sh
findings:
  critical: 3
  warning: 6
  info: 3
  total: 12
status: issues_found
---

# Hooks: Shell Script Security Review

**Reviewed:** 2026-05-07
**Depth:** deep (shell-security-focused)
**Files Reviewed:** 6
**Status:** issues_found
**Score:** 5/10

## Summary

All six hook scripts follow the basic shell safety pattern (`set -euo pipefail`, proper quoting, array-based argument construction). However, for a supply-chain security tool, the hooks have significant gaps: environment variables can redirect verification to attacker-controlled servers, disable transparency log checks entirely, and the install script silently overwrites existing hooks -- violating its own stated requirement. The near-total code duplication across four ecosystem hooks amplifies maintenance risk for any fix applied.

## Strengths

- `set -euo pipefail` present in all 6 scripts (fail-closed foundation)
- Proper quoting of `$ARTIFACT` and array expansion via `"${ARGS[@]}"` -- no word-splitting injection
- Required positional argument via `${1:?...}` pattern with clear usage message
- `command -v` check with `exit 1` on missing binary
- `SCRIPT_DIR` computed safely in install.sh via `cd ... && pwd`

## Critical Issues

### CR-01: Environment variable `SKILLLEDGER_SERVICE_URL` allows verification endpoint hijack

**File:** `hooks/claude-code-hook.sh:13`, `hooks/generic-hook.sh:15`, `hooks/mcp-hook.sh:14`, `hooks/npm-hook.sh:18`, `hooks/openclaw-hook.sh:13`
**Issue:** An attacker who controls the process environment (CI/CD runner, shared system, compromised `.env`) can set `SKILLLEDGER_SERVICE_URL` to a server they control. The hook will then verify the artifact against the attacker's transparency log, which can return forged results. The default is `http://localhost:8000` (plain HTTP), so even without env manipulation, any local process can MITM the verification.
**Fix:**
```bash
# Require HTTPS in non-dev mode
if [[ "$SERVICE_URL" != https://* ]] && [[ "${SKILLLEDGER_ALLOW_HTTP:-false}" != "true" ]]; then
    echo "ERROR: SKILLLEDGER_SERVICE_URL must use https:// (set SKILLLEDGER_ALLOW_HTTP=true for local dev)" >&2
    exit 1
fi
```

### CR-02: `SKILLLEDGER_SKIP_TLOG=true` disables transparency log verification via env var

**File:** `hooks/claude-code-hook.sh:14,23-25`, `hooks/generic-hook.sh:16,25-27`, `hooks/mcp-hook.sh:15,24-26`, `hooks/npm-hook.sh:19,28-30`, `hooks/openclaw-hook.sh:14,23-25`
**Issue:** Any process that can set an environment variable can bypass the transparency log check entirely. Combined with CR-01, this lets an attacker neuter the entire verification pipeline with two env vars. For a security-critical hook, allowing silent bypass via environment is a design flaw.
**Fix:** At minimum, print a loud warning when tlog is skipped. Better: require a local config file or flag file (not an env var) to enable offline mode.
```bash
if [ "$SKIP_TLOG" = "true" ]; then
    echo "WARNING: Transparency log verification DISABLED by SKILLLEDGER_SKIP_TLOG" >&2
    echo "WARNING: This reduces verification to signature-only. Ensure this is intentional." >&2
    ARGS+=(--skip-tlog)
fi
```

### CR-03: install.sh silently overwrites existing hooks (violates stated requirement)

**File:** `hooks/install.sh:35,38`
**Issue:** `ln -sf` (line 35) forces symlink creation, and `cp` (line 38) overwrites without prompting. CLAUDE.md states hooks must not "overwrite existing hooks without consent." A user with a custom pre-install hook will lose it silently.
**Fix:**
```bash
if [ -e "$dst" ]; then
    echo "Hook already exists: $dst" >&2
    read -rp "Overwrite? [y/N] " confirm
    if [[ "$confirm" != [yY] ]]; then
        echo "Skipped $name" >&2
        return 0
    fi
fi
```

## Warnings

### WR-01: No validation on SKILLLEDGER_POLICY value

**File:** `hooks/claude-code-hook.sh:12`, `hooks/generic-hook.sh:14`, `hooks/mcp-hook.sh:13`, `hooks/npm-hook.sh:17`, `hooks/openclaw-hook.sh:12`
**Issue:** No allowlist check on the policy preset. An empty `SKILLLEDGER_POLICY=""` passes the `${..:-moderate}` default (empty string is not unset), resulting in `--preset ""` being sent to the CLI. This may cause unexpected behavior or a confusing error message from the underlying tool.
**Fix:**
```bash
POLICY="${SKILLLEDGER_POLICY:-moderate}"
case "$POLICY" in
    strict|moderate|permissive) ;;
    *) echo "ERROR: Invalid policy: $POLICY. Use strict, moderate, or permissive." >&2; exit 1 ;;
esac
```

### WR-02: No artifact path validation (existence, type, traversal)

**File:** `hooks/claude-code-hook.sh:11`, `hooks/generic-hook.sh:13`, `hooks/mcp-hook.sh:12`, `hooks/npm-hook.sh:16`, `hooks/openclaw-hook.sh:11`
**Issue:** The artifact path from `$1` is not checked for existence, file type, or path traversal. While `skillledger verify` presumably validates internally, defense-in-depth for a security tool means validating at the boundary.
**Fix:**
```bash
ARTIFACT="${1:?Usage: hook.sh <artifact-path>}"
if [ ! -f "$ARTIFACT" ]; then
    echo "ERROR: Artifact not found or not a regular file: $ARTIFACT" >&2
    exit 1
fi
ARTIFACT="$(cd "$(dirname "$ARTIFACT")" && pwd)/$(basename "$ARTIFACT")"
```

### WR-03: Default service URL uses plain HTTP

**File:** All hooks (SERVICE_URL assignment lines)
**Issue:** Default `http://localhost:8000` is unencrypted. If deployed to production without setting the env var, all verification traffic is sent over plain HTTP, enabling MITM attacks on the verification endpoint.
**Fix:** Either require explicit configuration (no default -- fail if unset), or default to HTTPS.

### WR-04: install.sh `--ecosystem` without value crashes with unhelpful error

**File:** `hooks/install.sh:16`
**Issue:** If `--ecosystem` is the last argument, `$2` is unset. Under `set -u`, this triggers a cryptic "unbound variable" error rather than a clear message.
**Fix:**
```bash
--ecosystem)
    if [[ -z "${2:-}" ]]; then
        echo "ERROR: --ecosystem requires a value" >&2; exit 1
    fi
    ECOSYSTEM="$2"; shift 2 ;;
```

### WR-05: install.sh npm instructions are incorrect and fragile

**File:** `hooks/install.sh:56-58`
**Issue:** Line 58 suggests `npm config set script-shell` which sets the _shell binary_, not a pre-install script. This is semantically wrong and would break all npm script execution. Line 56 embeds `${SCRIPT_DIR}` unquoted into printed instructions -- if the repo path contains spaces, copy-pasting the output will produce broken commands.
**Fix:** Remove the `npm config set script-shell` suggestion. Quote the path in printed instructions.

### WR-06: No signal trap for clean messaging on interrupt

**File:** All hooks
**Issue:** If a user Ctrl-C's during `skillledger verify`, the script exits non-zero (correct) but prints no message. For debugging, a trap would clarify the exit reason.
**Fix:**
```bash
trap 'echo "SkillLedger: Verification interrupted" >&2; exit 130' INT TERM
```

## Info

### IN-01: Near-total code duplication across ecosystem hooks

**File:** `hooks/claude-code-hook.sh`, `hooks/mcp-hook.sh`, `hooks/npm-hook.sh`, `hooks/openclaw-hook.sh`
**Issue:** Four files with ~95% identical code (differ only in usage message string). Bug fixes must be applied to all files independently.
**Fix:** Have ecosystem hooks source `generic-hook.sh` or call it, passing only the ecosystem name.

### IN-02: `exit $?` is redundant

**File:** `hooks/claude-code-hook.sh:28`, `hooks/mcp-hook.sh:29`, `hooks/npm-hook.sh:33`, `hooks/openclaw-hook.sh:28`
**Issue:** The last command's exit code is already the script's exit code. `exit $?` is harmless but unnecessary.
**Fix:** Remove or keep for readability.

### IN-03: No minimum bash version documented

**File:** All hooks (shebang line)
**Issue:** Scripts use `#!/usr/bin/env bash` but do not document minimum version. macOS ships bash 3.2; all constructs used here are 3.2-compatible, but this should be documented for future maintainers who might add bash 4+ features (associative arrays, `${var,,}`, etc.).
**Fix:** Add a comment: `# Requires: bash >= 3.2`

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (shell-security-reviewer)_
_Depth: deep_
