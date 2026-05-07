# SkillLedger Ecosystem Adapters: Code Review Report

**Reviewed:** 2026-05-07
**Scope:** All `.go` files in `cli/internal/ecosystem/`
**Reviewer:** Claude (Senior Code Reviewer)
**Depth:** Deep (cross-file analysis including builder comparison and caller analysis)

---

## Strengths

1. **adapter.go:80-133** -- `discoverSkillsInDir` is a well-factored shared helper. It correctly handles non-existent directories by returning `(nil, nil)` rather than an error, and applies `filepath.Clean` on input paths.

2. **adapter.go:59-76** -- `DiscoverAll` has deduplication logic (WR-05 fix) to prevent double-reporting when multiple adapters scan overlapping directories (e.g., ClaudeCode and Anthropic both scanning `~/.claude/skills/`).

3. **adapter.go:234-240** -- `homeDir()` resolves at call time rather than struct construction, avoiding stale cached values as documented.

4. **All adapters** -- Consistent use of `afero.Fs` for testability, matching the project convention from CLAUDE.md. Clean interface compliance -- every adapter is a stateless struct implementing `Kind()` and `Discover(afero.Fs)`.

5. **mcp.go:28-33** -- OS-aware config path selection for macOS vs Linux with `runtime.GOOS`.

6. **adapter.go:163-187** -- `extractMetadata` safely handles JSON parse failures by silently returning, which is appropriate for best-effort metadata enrichment.

---

## Issues

### Critical -- Path Traversal, Injection

#### CR-01: BLOCKER -- Symlink traversal in collectFiles allows reading arbitrary files outside skill directories

**File:** `cli/internal/ecosystem/adapter.go:136-160`

**Problem:** `collectFiles` uses `afero.ReadDir` to walk directories and never checks whether entries are symlinks. A malicious skill directory could contain a symlink pointing to `/etc/`, `~/.ssh/`, or any sensitive location. The function follows it silently, enumerates all files, and reports them as skill files.

These paths are then passed to the scanner. Tracing the call chain: `DiscoverAll` -> `discoverSkillsInDir` -> `collectFiles` produces `DiscoveredSkill.Files`, which flows to `scanner.Scan` (via `cli/internal/cmd/audit.go:136`), where `OsFileOpener.Open()` (`audit.go:31`) opens and hashes each file path using `os.Open`. This means file contents outside the skill directory are actually read and processed.

The project's own builder (`cli/internal/builder/collector.go:115-125`) explicitly detects and skips symlinks using `afero.Lstater.LstatIfPossible()`. The CLAUDE.md convention states: "Symlink detection via `afero.Lstater.LstatIfPossible()` (Walk resolves symlinks)." The ecosystem adapter was not given the same treatment.

**Why it matters:** An attacker who can place a symlink inside a skill directory (e.g., `.claude/skills/evil-skill/secrets -> ~/.ssh/`) causes the audit command to read, hash, and potentially report arbitrary files. For a supply-chain security tool, this is an information disclosure and path traversal vulnerability in the audit pipeline itself.

**Fix:**
```go
func collectFiles(fs afero.Fs, root, dir string) ([]string, error) {
    entries, err := afero.ReadDir(fs, dir)
    if err != nil {
        return nil, err
    }
    var files []string
    for _, entry := range entries {
        fullPath := filepath.Join(dir, entry.Name())
        // Skip symlinks to prevent traversal outside the skill directory.
        if lstater, ok := fs.(afero.Lstater); ok {
            if linfo, lstatCalled, lerr := lstater.LstatIfPossible(fullPath); lerr == nil && lstatCalled {
                if linfo.Mode()&os.ModeSymlink != 0 {
                    continue
                }
            }
        }
        if entry.IsDir() {
            sub, err := collectFiles(fs, root, fullPath)
            if err != nil {
                return nil, err
            }
            files = append(files, sub...)
        } else {
            rel, err := filepath.Rel(root, fullPath)
            if err != nil {
                rel = fullPath
            }
            files = append(files, rel)
        }
    }
    return files, nil
}
```

#### CR-02: BLOCKER -- Server names from untrusted MCP JSON config propagate unsanitized as skill IDs

**File:** `cli/internal/ecosystem/adapter.go:218-227`

**Problem:** In `discoverFromConfig`, server names are parsed from JSON config files (e.g., `claude_desktop_config.json`) and used directly as `skill.ID` and `skill.Name` with zero validation. The MCP config file is user-editable, but could also be modified by a malicious MCP server installer. A server name containing path separators (e.g., `../../etc/passwd`), shell metacharacters, or null bytes flows through the pipeline unsanitized.

While `discoverFromConfig` itself does not use the name in path construction, the `DiscoveredSkill.ID` field is consumed downstream by the scanner and report generators. If any downstream consumer uses `skill.ID` in a file path, log entry, or command, the unsanitized value becomes an injection vector.

**Why it matters:** Defense in depth requires sanitizing at the ingestion point, not hoping every downstream consumer validates. The builder package validates artifact IDs; the ecosystem package should validate skill IDs with the same rigor.

**Fix:**
```go
for name := range servers {
    sanitized := filepath.Base(name)
    if sanitized == "." || sanitized == ".." || strings.ContainsAny(sanitized, "/\\") {
        continue // skip malformed server names
    }
    skill := DiscoveredSkill{
        ID:   sanitized,
        Name: sanitized,
        // ...
    }
}
```

---

### Important -- Parsing Bugs, Missing Features

#### WR-01: WARNING -- Deduplication key in DiscoverAll is fragile and order-dependent

**File:** `cli/internal/ecosystem/adapter.go:68`

**Problem:** The deduplication key is `s.Path + "|" + strings.Join(s.Files, ",")`. Two issues:

1. **Order dependence:** File order from `collectFiles` depends on `afero.ReadDir` ordering, which is filesystem-implementation-specific. Two identical skills could produce different file orderings on different filesystems (e.g., MemMapFs vs OsFs), defeating deduplication entirely.

2. **Separator collision:** File names containing `|` or `,` (both legal in filenames) cause false-positive deduplication. Two different skills with different files could produce the same key string.

**Why it matters:** The AnthropicAdapter and ClaudeCodeAdapter both scan `~/.claude/skills/`. If file ordering differs between runs, the same skill could be reported twice, or worse, two genuinely different skills with unlucky filenames could be silently deduplicated.

**Fix:**
```go
sorted := make([]string, len(s.Files))
copy(sorted, s.Files)
sort.Strings(sorted)
key := s.Path + "\x00" + strings.Join(sorted, "\x00")
```

#### WR-02: WARNING -- MCP adapter missing Windows config path

**File:** `cli/internal/ecosystem/mcp.go:28-33`

**Problem:** The `switch` handles `darwin` and a `default` case using the Linux XDG path (`~/.config/Claude/`). On Windows, the Claude Desktop config is at `%APPDATA%\Claude\claude_desktop_config.json`. The default fallback produces an incorrect path on Windows, silently finding nothing.

**Why it matters:** Windows is a major platform for Claude Desktop. The adapter silently returns zero results rather than failing with a clear message, which means Windows users get no MCP server discovery with no indication of why.

**Fix:**
```go
switch runtime.GOOS {
case "darwin":
    configPath = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
case "windows":
    appData := os.Getenv("APPDATA")
    if appData == "" {
        return nil, nil
    }
    configPath = filepath.Join(appData, "Claude", "claude_desktop_config.json")
default:
    configPath = filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
}
```

#### WR-03: WARNING -- collectFiles has no recursion depth limit

**File:** `cli/internal/ecosystem/adapter.go:136-160`

**Problem:** `collectFiles` recurses into subdirectories without any depth limit. Combined with the symlink issue in CR-01, a symlink loop (e.g., `a/b -> a`) would cause infinite recursion and a stack overflow crash. Even without symlinks, a pathologically deep directory structure could crash the process.

**Why it matters:** Skill directories are untrusted input. A malicious skill package could include deeply nested directories or symlink loops specifically to crash the audit tool.

**Fix:** Add a `maxDepth` parameter:
```go
func collectFiles(fs afero.Fs, root, dir string, depth int) ([]string, error) {
    if depth <= 0 {
        return nil, fmt.Errorf("maximum directory depth exceeded at %s", dir)
    }
    // ... existing logic, passing depth-1 to recursive calls
}
```

#### WR-04: WARNING -- AnthropicAdapter silently suppressed by deduplication with ClaudeCodeAdapter

**File:** `cli/internal/ecosystem/anthropic.go:28` and `cli/internal/ecosystem/claudecode.go:27`

**Problem:** Both adapters scan `~/.claude/skills/`. The dedup key in `DiscoverAll` (line 68) includes `Path` but NOT `Kind`. Since `ClaudeCodeAdapter` runs first in the registry (line 45), it claims all skills under `~/.claude/skills/` as `claude-code-skill`. The `AnthropicAdapter` then finds the same skills but they are deduplicated, so `anthropic-skill` kind is never reported for global skills.

This means `AnthropicAdapter.Discover()` effectively does nothing in the default registry -- it is dead code for global skills. The adapter was presumably added to support Anthropic-specific skill semantics, but the dedup logic prevents it from ever producing results.

**Why it matters:** Users expecting to see `anthropic-skill` discoveries in their audit will get nothing. If policy rules target the `anthropic-skill` kind specifically, they will never match.

**Fix:** Either (a) remove the global path from `AnthropicAdapter` since `ClaudeCodeAdapter` covers it, or (b) include `Kind` in the dedup key if dual-reporting is intended.

---

### Minor -- Style, Consistency

#### MN-01: WARNING -- extractMetadata silently ignores TOML config files used by CodexAdapter

**File:** `cli/internal/ecosystem/adapter.go:163-187` and `cli/internal/ecosystem/codex.go:22`

**Problem:** `CodexAdapter` passes `config.toml` as a config file, but `extractMetadata` has no case for TOML files. The function silently does nothing, so Codex tool names and versions are never extracted from their configs.

**Why it matters:** Codex tools in audit reports will show directory names instead of their configured names, unlike every other ecosystem.

**Fix:** Either add TOML parsing to `extractMetadata` or remove `config.toml` from the Codex configFiles list and document TOML metadata as unsupported.

#### MN-02: WARNING -- homeDir() silently returns empty string with no logging

**File:** `cli/internal/ecosystem/adapter.go:234-240`

**Problem:** When `os.UserHomeDir()` fails, the function returns `""` silently. All callers check for empty and return `(nil, nil)`, meaning the entire global skill scan is silently skipped. For a security auditing tool, silently reducing scan scope is a false-negative risk.

**Why it matters:** A user running `skillledger audit` in an environment where `HOME` is unset (e.g., some CI environments, containers) will get no global skill results with no warning.

**Fix:** Add logging:
```go
func homeDir() string {
    home, err := os.UserHomeDir()
    if err != nil {
        log.Warn().Err(err).Msg("cannot resolve home directory; global skill discovery will be skipped")
        return ""
    }
    return home
}
```

#### MN-03: WARNING -- MCP test is non-deterministic and may pass vacuously

**File:** `cli/internal/ecosystem/discovery_test.go:111-137`

**Problem:** `TestMCPAdapter_ParseConfig` seeds both macOS and Linux config paths in a MemMapFs but relies on `homeDir()` resolving to the real home directory. The test accepts 0 or 2 results (line 127: "we accept 0 or 2 results"). A test that allows 0 results is not actually testing the MCP parsing path -- it passes even if parsing is completely broken.

**Why it matters:** This test provides false confidence. On a CI runner where the home directory does not match the seeded paths, the test passes trivially without exercising any code.

**Fix:** Test `discoverFromConfig` directly by exporting it or using an internal test, passing a known config path rather than depending on the real home directory.

---

## Score: 5/10

The adapter interface design is clean and well-factored with good shared helpers. However, for a supply-chain security tool, the symlink traversal vulnerability (CR-01) is a significant gap -- especially when the project's own builder already implements the correct mitigation. The unsanitized server names from untrusted JSON (CR-02) and the dead AnthropicAdapter (WR-04) indicate incomplete threat modeling and integration testing for the multi-adapter scanning flow.
