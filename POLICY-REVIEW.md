# Policy Engine Code Review: `cli/internal/policy/`

**Reviewed:** 2026-05-07
**Depth:** deep (cross-file, injection tracing, Rego compilation fidelity)
**Files Reviewed:** 14 source files + 8 embedded Rego files
**Reviewer:** Claude (adversarial review)

---

## Strengths

- **Fail-closed by default** (`evaluator.go:60-68`): Empty OPA result sets correctly default to `"deny"`. This is the single most important property for a security-critical policy engine.
- **Rego injection prevention on operator arguments** (`compiler.go:124-128`): The `parseOperator` function rejects backslashes, newlines, tabs, and quotes in DSL arguments, preventing injection through the operator value path.
- **Runtime expression field whitelist** (`compiler.go:146-151`): `allowedRuntimeFields` restricts which input paths can be referenced, limiting the runtime DSL's attack surface.
- **Deterministic output** (`compiler.go:39-43`): Categories are sorted before compilation, ensuring identical input always produces identical Rego output -- important for reproducibility guarantees.
- **Proper use of `%q` for Rego string literals** (`compiler.go:98`): Rule messages in Rego rule bodies use Go's `%q` verb which correctly escapes all special characters for valid Rego strings.
- **Comprehensive preset test coverage** (`presets_test.go`): Each preset is validated for OPA parseability AND behavioral correctness across trust tiers.

---

## Critical Issues

### CR-01: Rego Code Injection via Unsanitized Category Names

**File:** `cli/internal/policy/dsl/compiler.go:87`
**Classification:** BLOCKER

**Issue:** The `category` variable (a YAML map key from user-supplied policy) is interpolated directly into Rego code via `fmt.Fprintf(b, "    some cap in input.capabilities.%s\n", category)` with zero validation. An attacker who controls the policy YAML can inject arbitrary Rego by using a crafted map key.

Example malicious YAML:
```yaml
version: 1
rules:
  "filesystem\n    true\n}\ndeny := set()\ndecision := \"allow\" if {\n    true":
    - deny: contains("x")
      message: "injected"
```

This would compile to Rego where the injected text after the newlines becomes executable code outside the `some cap in input.capabilities.` expression. The injected `deny := set()` redefines the deny set as empty, and `decision := "allow"` forces the policy to allow everything, completely bypassing all other rules.

**Why it matters:** The DSL-to-Rego compiler is the trust boundary. If a malicious policy file can inject arbitrary Rego, the entire verification pipeline can be silently bypassed -- skills that should be denied get allowed. This is particularly dangerous when policies are loaded from files (`LoadPolicyFile`) which could be modified by an attacker with filesystem access.

**Fix:** Add category validation in the parser. Only allow known capability category names or at minimum restrict to `[a-zA-Z_][a-zA-Z0-9_]*`:

```go
// In parser.go Parse(), after line 29:
var validCategory = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

for category := range p.Rules {
    if !validCategory.MatchString(category) {
        return nil, fmt.Errorf("invalid rule category name: %q (must be alphanumeric/underscore)", category)
    }
}
```

Best approach: restrict to the known set `{"filesystem", "network", "secrets", "tools"}` since those are the only capability categories the Rego input structure supports.

---

### CR-02: Rego Injection via Multiline Message in Comment

**File:** `cli/internal/policy/dsl/compiler.go:83-85`
**Classification:** BLOCKER

**Issue:** The `escapedMsg` variable (line 83) only escapes double quotes but not newlines. It is then interpolated into a Rego comment on line 85: `fmt.Fprintf(b, "# Rule: %s - %s\n", category, escapedMsg)`. If the YAML `message` field contains a literal newline (valid in YAML double-quoted strings), the text after the newline is no longer a comment -- it becomes executable Rego code.

Example:
```yaml
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "legit\ndeny := set()"
```

Compiles to:
```rego
# Rule: filesystem - legit
deny := set()
deny contains msg if {
    some cap in input.capabilities.filesystem
    contains(cap, "write")
    msg := "legit\ndeny := set()"
}
```

The injected `deny := set()` on line 2 redefines the deny set as unconditionally empty at the module scope, nullifying all deny rules.

**Why it matters:** Even though `msg := %q` on line 98 properly escapes the message for the Rego string literal inside the rule body, the comment injection on line 85 happens BEFORE the rule body and modifies the module-level scope.

**Fix:** Strip or reject newlines/carriage returns in message fields:

```go
// In compiler.go, replace line 83-85:
safeComment := strings.ReplaceAll(rule.Message, "\n", " ")
safeComment = strings.ReplaceAll(safeComment, "\r", " ")
fmt.Fprintf(b, "# Rule: %s - %s\n", category, safeComment)
```

Or better, validate in the parser that messages contain no control characters:
```go
if strings.ContainsAny(r.Message, "\n\r\t") {
    return nil, fmt.Errorf("rule %s[%d]: message contains control characters", category, i)
}
```

---

## Warnings

### WR-01: Localhost Bypass in Runtime Strict Allows `localhost.evil.com`

**File:** `cli/internal/policy/preset/rego/runtime_strict.rego:13-19` (identical in `runtime_moderate.rego:13-19`, `runtime_permissive.rego:13-19`)
**Classification:** WARNING

**Issue:** The `is_localhost` helper uses `startswith(dest, "localhost")` which matches ANY hostname starting with "localhost", including `localhost.evil.com` or `localhost-proxy.attacker.com`. For unverified skills, this is the ONLY exception to the full network lockdown -- an attacker who controls `localhost.evil.com` can exfiltrate data from an unverified skill.

**Why it matters:** The unverified lockdown is the highest-security mode. The `is_localhost` exception is specifically designed to allow only local development traffic. A prefix match instead of an exact match + port defeats this purpose entirely. This affects all three runtime presets.

**Fix:** Use exact matching or match hostname + optional port:

```rego
is_localhost(dest) if {
    dest == "localhost"
}

is_localhost(dest) if {
    startswith(dest, "localhost:")
}

is_localhost(dest) if {
    dest == "127.0.0.1"
}

is_localhost(dest) if {
    startswith(dest, "127.0.0.1:")
}

is_localhost(dest) if {
    dest == "::1"
}

is_localhost(dest) if {
    startswith(dest, "::1:")
}
```

---

### WR-02: `parseResult` Silently Accepts Any Decision String From OPA

**File:** `cli/internal/policy/eval/evaluator.go:72-74`
**Classification:** WARNING

**Issue:** The `parseResult` function extracts the `decision` field as a raw string and passes it through without validating it is one of `"allow"`, `"deny"`, or `"warn"`. A malformed or intentionally crafted Rego policy that produces `decision := "allowed"` (typo) or `decision := "skip"` would result in a `PolicyResult` with an unrecognized decision value. If any caller checks `result.Decision != "deny"` (instead of `result.Decision == "allow"`), the unknown decision silently bypasses enforcement.

**Why it matters:** Fail-closed requires that only explicitly recognized "allow" values result in allowing an action. An unrecognized decision string is ambiguous and depends on how callers compare it.

**Fix:** Validate the decision value and fail closed on unknowns:

```go
if d, ok := val["decision"].(string); ok {
    switch d {
    case "allow", "deny", "warn":
        result.Decision = d
    default:
        result.Decision = "deny"
    }
}
```

---

### WR-03: DSL Compiled Rego Missing Default Empty Sets for `deny` and `warnings`

**File:** `cli/internal/policy/dsl/compiler.go:34-61`
**Classification:** WARNING

**Issue:** The compiled Rego output defines `default decision := "allow"` but never defines default empty values for the `deny` and `warnings` sets. If no rules match, OPA evaluates `count(deny)` against an undefined variable. OPA currently treats undefined in `count()` as 0, but this is an implementation detail, not a specification guarantee. Compare with the preset Rego files which explicitly define defaults: `strict.rego:30` has `warnings := set()`, `permissive.rego:7-8` has `deny := set()` and `warnings := set()`.

**Why it matters:** If OPA ever changes how it handles `count()` on undefined, or if a Rego linter flags this as an error, all DSL-compiled policies break. The inconsistency between DSL-compiled and preset Rego is itself a maintenance risk.

**Fix:** Add default set definitions to the compiled output after the header.

---

### WR-04: `LoadPresetWithAllowlist` Always Loads Allowlist Module Even When Empty

**File:** `cli/internal/policy/policy.go:74-86`
**Classification:** WARNING

**Issue:** Unlike `LoadPolicy` (line 46, checks `al.IsEmpty()`), `LoadPresetWithAllowlist` unconditionally loads the allowlist Rego module even when `entries` is empty. This creates an inconsistency: `LoadPolicy` with an empty allowlist produces a policy without allowlist checking, but `LoadPresetWithAllowlist` with an empty list produces a policy WITH allowlist checking (which happens to allow everything because `count(data.publishers.allowlist) == 0` is true). The behavioral outcome is the same today, but the two code paths diverge in what Rego modules are loaded, which could cause subtle differences if `allowlist.rego` evolves.

**Fix:** Add the same empty check as `LoadPolicy`:

```go
al := allowlist.Load(entries)
if al.IsEmpty() {
    return eval.NewEvaluator(regoSrc)
}
```

---

### WR-05: `except` List Items Not Validated for Injection Characters

**File:** `cli/internal/policy/dsl/compiler.go:90-96`
**Classification:** WARNING

**Issue:** Unlike operator arguments (validated at `compiler.go:126`), the `Except` list items from YAML are not checked for injection characters before being passed to `fmt.Sprintf("%q", ex)`. While Go's `%q` escaping is robust and prevents injection into the Rego string literal, the defense-in-depth principle calls for consistent input validation at the trust boundary. If a future refactor changes the quoting mechanism, the lack of validation becomes exploitable. Additionally, empty strings in `Except` are never rejected.

**Fix:** Apply the same validation as `parseOperator` during parsing:

```go
for _, ex := range rule.Except {
    if strings.ContainsAny(ex, "\\\n\r\t\"") {
        return nil, fmt.Errorf("rule %s[%d]: except value %q contains disallowed characters", category, i, ex)
    }
    if ex == "" {
        return nil, fmt.Errorf("rule %s[%d]: except list contains empty value", category, i)
    }
}
```

---

## Info

### IN-01: `any` Operator Name is Misleading

**File:** `cli/internal/policy/dsl/compiler.go:138-139`

**Issue:** The install-time DSL operator `any("outbound")` compiles to `startswith(cap, "outbound")` (prefix match). The runtime DSL has a separate `any` operator (`compiler.go:283-330`) that does set membership. The same keyword with different semantics across two DSL contexts is a recipe for policy authoring errors.

---

### IN-02: `common.rego` is Dead Code

**File:** `cli/internal/policy/preset/rego/common.rego`

**Issue:** Contains only a package declaration, an import, and comments. Not embedded via `//go:embed` in `presets.go`. Serves no functional purpose.

---

### IN-03: Test Helper `capabilitiesInput` Missing `issuer` Field

**File:** `cli/internal/policy/preset/presets_test.go:62-69`

**Issue:** Constructs attestation map with only `"signed_by"` but no `"issuer"`. Inconsistent with `testInput()` in `evaluator_test.go:39-51` which includes both fields.

---

## Score: 5/10

The policy engine has a well-structured architecture with proper fail-closed defaults and good OPA integration. The injection prevention on operator arguments shows security awareness. However, the two Rego injection vulnerabilities (CR-01 via category names, CR-02 via multiline messages) are serious -- they allow a crafted policy YAML to produce arbitrary Rego code, completely bypassing the intended security enforcement. For a supply-chain security tool, the policy compiler IS the trust boundary, and these injection vectors undermine its integrity. The localhost bypass (WR-01) further weakens the highest-security runtime mode. The category and message injection bugs must be fixed before this code ships.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (adversarial review)_
_Depth: deep_
