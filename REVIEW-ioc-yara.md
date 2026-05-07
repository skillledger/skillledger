# IOC Database & YARA Rule Engine: Code Review Report

**Reviewed:** 2026-05-07
**Depth:** deep (cross-file call-chain analysis)
**Files Reviewed:** 6
**Reviewer:** Claude (gsd-code-reviewer)

---

## Strengths

1. **Hash IOC lookup is O(1)** (`ioc.go:49-52`): Uses `map[string]Entry` keyed by SHA-256, correct data structure for hot-path matching.

2. **Domain suffix matching prevents partial matches** (`ioc.go:87`): The `"."+domain` suffix check correctly prevents `notevil.com` from matching IOC `evil.com`. Case normalization and trailing dot handling are also correct.

3. **HTTPS enforcement and host allowlist** (`ioc.go:121-134`): `FetchUpdates` validates scheme is `https` and hostname is in a hardcoded allowlist. Defense in depth.

4. **Response body size cap** (`ioc.go:163`): `io.LimitReader` caps the IOC update response at 1MB, preventing DoS via oversized payloads.

5. **Corrupt cache detection and cleanup** (`ioc.go:226-229`): D-07 handling deletes corrupt cache files and falls back to bundled data. Graceful degradation.

6. **Symlink escape detection** (`engine.go:54-63`): YARA rule loading resolves symlinks and validates the resolved path stays within the rules directory.

7. **YARA scan timeout** (`engine.go:28,161`): 30-second per-scan timeout via `ScanMem` prevents runaway rule evaluation.

8. **Scanner file size limit** (`scanner.go:86-88`): 50MB per-file limit on scan targets prevents memory exhaustion during YARA scanning.

9. **Comprehensive test coverage** (`ioc_test.go`): Tests cover HTTPS rejection, host allowlist, large responses, timeouts, domain matching edge cases (case, trailing dot, partial match), and cache fallback scenarios.

---

## Issues

### Critical -- detection bypass, injection

#### CR-01: TOCTOU Race in YARA Symlink Validation

**File:** `cli/internal/yara/engine.go:54-66`
**Issue:** The symlink check resolves the path on line 54 (`filepath.EvalSymlinks(fullPath)`) and validates it stays within the rules directory on line 62. But line 66 reads the *original unresolved* `fullPath`, not the `resolved` path. An attacker who controls the rules directory could swap a symlink target between the `EvalSymlinks` call and the `ReadFile` call, pointing it outside the allowed directory to a malicious YARA rule file.

This is a classic Time-Of-Check-Time-Of-Use vulnerability. The window is small but exploitable in automated scenarios where the attacker controls the filesystem.

**Why it matters:** The path traversal protection is the only defense against loading arbitrary YARA rules. Bypassing it allows an attacker to inject rules that either (a) suppress detection by overriding built-in rules, or (b) cause false positives to desensitize users.

**Fix:**
```go
// Line 66: read using the resolved path, not the original
data, err := os.ReadFile(resolved)
if err != nil {
    return nil, fmt.Errorf("reading rule file %s: %w", name, err)
}
```

#### CR-02: IOC Hash Lookup is Case-Sensitive -- Detection Bypass

**File:** `cli/internal/ioc/ioc.go:101-111`
**Issue:** `Match()` does an exact map lookup on the SHA-256 hash string. SHA-256 hex digests can be uppercase, lowercase, or mixed-case depending on the producer (e.g., `shasum` outputs lowercase, some tools output uppercase). If the IOC database stores `"abc123..."` but the scanner produces `"ABC123..."`, the lookup silently misses.

Contrast with `MatchDomain()` (line 84) which correctly normalizes to lowercase before comparison. The hash path lacks this normalization.

**Why it matters:** This is a detection bypass in a supply-chain security tool. A known-compromised artifact hash stored as lowercase in the IOC database will not match an uppercase hash from the scanner, causing the compromised artifact to be reported as clean.

**Fix:**
```go
func (d *Database) Match(sha256 string) (*scanner.IOCMatchInfo, bool) {
    e, ok := d.entries[strings.ToLower(sha256)]
    if !ok {
        return nil, false
    }
    return &scanner.IOCMatchInfo{
        SHA256:      e.SHA256,
        Description: e.Description,
        Severity:    e.Severity,
    }, true
}

func (d *Database) AddEntry(e Entry) {
    d.entries[strings.ToLower(e.SHA256)] = e
}
```
Also normalize in `Load()` (line 51) and `fetchAndMerge()` (lines 173, 185) when inserting into the map.

#### CR-03: No Validation of SHA-256 Format in IOC Entries

**File:** `cli/internal/ioc/ioc.go:71-73`, `ioc.go:172-173`, `ioc.go:184-185`
**Issue:** `AddEntry()` and the `fetchAndMerge()` deserialization accept any string as a SHA-256 hash, including empty strings, whitespace, or arbitrary data. An empty `SHA256` field inserts an entry keyed by `""`, which could match against skills that fail to compute a hash (since `result.SHA256` defaults to `""` when `allHashes` is empty, per `scanner.go:153-156`).

A malicious or compromised IOC feed could inject entries with crafted keys to cause false positives, or inject entries with invalid hashes that waste map space but never match.

**Why it matters:** The IOC database is a trust anchor for threat intelligence. Accepting unvalidated input undermines its integrity. An empty-string key collision is particularly dangerous because it would flag skills with no files as "compromised."

**Fix:**
```go
import "regexp"

var sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func (d *Database) AddEntry(e Entry) error {
    if !sha256Re.MatchString(e.SHA256) {
        return fmt.Errorf("invalid SHA-256 hash in IOC entry: %q", e.SHA256)
    }
    d.entries[strings.ToLower(e.SHA256)] = e
    return nil
}
```
Apply the same validation in `Load()` and `fetchAndMerge()`.

---

### Important -- missing checks, design issues

#### WR-01: No Size Limit on Individual YARA Rule Files

**File:** `cli/internal/yara/engine.go:66-69`
**Issue:** Each rule file is read with `os.ReadFile` with no size limit. A single multi-gigabyte `.yar` file would be loaded entirely into memory. Combined with the `strings.Builder` concatenation (lines 70-71), a malicious rules directory could exhaust memory before compilation even begins. The scan targets have a 50MB limit (scanner.go:88) but the rules themselves have no cap.

**Why it matters:** OOM during rule loading crashes the audit pipeline with no recovery.

**Fix:**
```go
const maxRuleFileSize = 1 << 20 // 1MB per rule file

info, err := e.Info()
if err != nil {
    return nil, fmt.Errorf("stat rule file %s: %w", name, err)
}
if info.Size() > maxRuleFileSize {
    return nil, fmt.Errorf("rule file %s exceeds size limit (%d bytes)", name, maxRuleFileSize)
}
```

#### WR-02: `FetchUpdatesWithClient` Exported Without URL Validation

**File:** `cli/internal/ioc/ioc.go:141-143`
**Issue:** `FetchUpdatesWithClient` is an exported method that bypasses all URL validation (HTTPS check, host allowlist). The comment says "Intended for testing" but it is a public API on the `Database` type. Any caller in the codebase -- or a downstream consumer if this package becomes a library -- can call it to fetch IOC data from an arbitrary HTTP endpoint, circumventing the security controls.

Currently only called from test files, but the exported surface creates unnecessary risk.

**Why it matters:** An attacker who gains code injection into any module that imports `ioc` can call `FetchUpdatesWithClient` with a malicious server URL to poison the IOC database (adding false entries to hide real compromises, or removing detection of known-bad hashes by overwriting them).

**Fix:** Make it unexported: rename to `fetchUpdatesWithClient`. If tests in other packages need it, use an `internal/testing` helper or `//go:build testing` constraint.

#### WR-03: Domain IOC Entries Accumulate Without Deduplication

**File:** `cli/internal/ioc/ioc.go:76-78`, `ioc.go:175`
**Issue:** `AddDomainEntry` appends to a slice and `fetchAndMerge` does `append(d.domainEntries, update.Domains...)` with no deduplication. Repeated `FetchUpdates` calls accumulate duplicate domain entries. Since `MatchDomain()` is a linear scan, each duplicate adds a redundant comparison, and memory grows without bound across sync cycles.

**Why it matters:** Over long-running processes (e.g., a daemon that periodically syncs IOCs), the domain list grows O(n*cycles), wasting memory and slowing domain checks.

**Fix:** Use `map[string]DomainEntry` keyed by normalized domain, or deduplicate on merge:
```go
func (d *Database) AddDomainEntry(e DomainEntry) {
    key := strings.ToLower(e.Domain)
    for i, existing := range d.domainEntries {
        if strings.ToLower(existing.Domain) == key {
            d.domainEntries[i] = e // update existing
            return
        }
    }
    d.domainEntries = append(d.domainEntries, e)
}
```

#### WR-04: `LoadCachedRules` Has No Path Validation

**File:** `cli/internal/yara/engine.go:139-151`
**Issue:** `LoadCachedRules` takes a `cacheDir` string and directly reads `filepath.Join(cacheDir, "yara.json")` with no validation. Unlike `NewEngine` which validates symlinks, this function performs no path traversal check. If an attacker can influence the `cacheDir` parameter (e.g., via environment variable or config file manipulation), they can point it to an arbitrary directory containing a crafted `yara.json` with malicious YARA rules.

**Why it matters:** The loaded rules are then compiled and executed against skill content. A malicious rule could contain expensive regex patterns (ReDoS) or, depending on the yargo engine capabilities, could be crafted to cause crashes.

**Fix:** At minimum, resolve symlinks and validate the path:
```go
func LoadCachedRules(cacheDir string) ([]YaraRuleItem, error) {
    resolved, err := filepath.EvalSymlinks(cacheDir)
    if err != nil {
        return nil, fmt.Errorf("resolving cache directory: %w", err)
    }
    data, err := os.ReadFile(filepath.Join(resolved, "yara.json"))
    // ...
}
```

#### WR-05: `fetchAndMerge` Ambiguous JSON Fallthrough Logic

**File:** `cli/internal/ioc/ioc.go:170-177`
**Issue:** The code tries to parse the response as `updateResponse` first. If parsing succeeds but both `Hashes` and `Domains` are empty (e.g., a legitimate empty update `{"hashes":[],"domains":[]}`), the condition `len(update.Hashes) > 0 || len(update.Domains) > 0` is false, so it falls through to the `[]Entry` backward-compat parse. That parse would succeed on `{"hashes":[],"domains":[]}` (as an empty array of Entry), silently doing nothing -- but via the wrong code path.

More critically, a JSON object like `{"unexpected":"data"}` would unmarshal without error to a zero-valued `updateResponse`, fall through, and then fail at the `[]Entry` parse with a confusing error message ("parsing IOC response") that doesn't indicate the object-format attempt.

**Why it matters:** A server sending an intentionally empty update (clearing the feed) gets misrouted through legacy parsing. Error messages on malformed responses are confusing and hide the real problem.

**Fix:**
```go
var update updateResponse
if err := json.Unmarshal(body, &update); err == nil {
    // Parsed as object -- use it regardless of entry count (empty is valid)
    for _, e := range update.Hashes {
        d.entries[strings.ToLower(e.SHA256)] = e
    }
    d.domainEntries = append(d.domainEntries, update.Domains...)
    return nil
}
```

---

### Minor -- style, observability

#### IN-01: Empty Bundled IOC Hash Data

**File:** `cli/internal/ioc/data/ioc-hashes.json`
**Issue:** The bundled hash IOC data is `[]`. All hash-based detection depends on live updates. If the update endpoint is unreachable, the IOC hash check provides zero value. The domain list has 18 entries but the hash list has none. For a supply-chain security tool, having zero bundled hash IOCs means offline installs have no hash-based protection.

#### IN-02: No Logging in YARA Engine

**File:** `cli/internal/yara/engine.go`
**Issue:** The YARA engine has no logging. The IOC package uses `zerolog` for debug and warning messages. Adding similar instrumentation (rule count loaded, compilation time, match results) would improve debuggability.

#### IN-03: `defaultScanTimeout` Not Documented as Per-Skill Bound

**File:** `cli/internal/yara/engine.go:28`
**Issue:** The 30-second timeout applies per `ScanMem` call. Since the scanner concatenates all files in a skill before calling `Scan` (scanner.go:149,168), a skill with many large files could hit this timeout. The timeout itself is reasonable but should be documented as a per-skill-scan bound.

#### IN-04: Domain IOC Linear Scan Will Not Scale

**File:** `cli/internal/ioc/ioc.go:85-91`
**Issue:** `MatchDomain` does a linear scan over all domain entries. With 18 bundled entries this is fine, but if the feed grows to thousands of domains, each hostname check becomes O(n). Hash IOCs correctly use a map.

---

## Score: 6/10

The code demonstrates solid security awareness -- HTTPS enforcement, size limits, host allowlists, symlink checks, scan timeouts. However, the TOCTOU race in YARA symlink validation (CR-01) undermines the path traversal protection, the case-sensitive hash comparison (CR-02) creates a detection bypass, and the lack of IOC entry validation (CR-03) allows empty-string hash collisions. For a tool whose core value proposition is detecting supply-chain attacks, detection bypass vulnerabilities are particularly severe. The exported `FetchUpdatesWithClient` (WR-02) and unbounded domain accumulation (WR-03) are design-level issues that should be addressed before this ships.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
