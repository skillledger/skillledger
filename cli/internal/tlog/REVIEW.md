# Transparency Log Client (`cli/internal/tlog/`) -- Code Review

**Reviewed:** 2026-05-07
**Depth:** deep
**Files Reviewed:** 5 (client.go, lookup.go, publish.go, client_test.go, lookup_test.go)
**Reviewer:** Claude (adversarial review)

---

## Strengths

- `client.go:96` -- Response body limited to 1 MB via `io.LimitReader`, preventing memory exhaustion from malicious server responses.
- `publish.go:36` -- SHA-256 input validated with strict regex before any network call.
- `client.go:79` -- Context propagation via `http.NewRequestWithContext` throughout.
- `client.go:84-86` -- API key only sent when non-empty; avoids leaking empty `Authorization` header.
- Functional options pattern (`WithServiceURL`, `WithHTTPClient`, `WithAPIKey`) makes the client testable and configurable.

---

## Critical Issues

### CR-01: No Merkle Inclusion Proof Verification -- Transparency Log Provides Zero Cryptographic Guarantees

**Files:** `lookup.go:26-62`, `client.go` (entire file)

**Problem:** The tlog client is a pure JSON REST wrapper. It fetches a `LookupResponse` containing `sha256`, `log_index`, and `published_at` -- all unsigned, server-asserted values. There is **no Merkle inclusion proof verification** anywhere in this package.

The verification pipeline (`verify/steps.go:78-111`) calls `LookupEntry`, gets back a JSON blob, and trusts whatever SHA-256 the server returns. It then compares that server-asserted SHA-256 against the lockfile -- but this only detects mismatches, not forgery. A compromised or malicious log server can return any `sha256` value it wants, and the client will accept it as a valid transparency log entry.

Compare with `log/internal/logclient/client.go` which uses Tessera's `HTTPFetcher`, `note.Verifier`, checkpoint signature verification, and `TileFetcherFunc` for actual proof building. The CLI client in `cli/internal/tlog/` has **none** of this.

**Why it matters:** This defeats the entire purpose of a transparency log. The CLAUDE.md states the core value is to "make it trivially easy to verify that a skill artifact was actually built from the source it claims." Without inclusion proofs, an attacker who compromises the FastAPI service can forge arbitrary log entries. The system degenerates to "trust the server" -- exactly what transparency logs are designed to prevent.

**Specifically missing:**
1. No checkpoint fetching or signature verification (no `note.Verifier`)
2. No Merkle inclusion proof request or verification
3. No consistency proof verification between checkpoints
4. No signed tree head validation
5. `LookupResponse` has no proof fields (no `proof_hashes`, `tree_size`, `root_hash`)

**Fix:** The `cli/internal/tlog/` client must either:
- (a) Use the existing `log/internal/logclient` which already has Tessera integration, or
- (b) Be extended to fetch checkpoints, verify signatures, and verify Merkle inclusion proofs using Tessera's `client.NewProofBuilder` and `proof.VerifyInclusion`.

At minimum, `LookupResponse` needs `InclusionProof [][]byte`, `TreeSize uint64`, and `RootHash []byte` fields, and `LookupEntry` must call `proof.VerifyInclusion()`.

---

### CR-02: Artifact ID Injected Directly Into URL Path -- Path Traversal / Request Smuggling

**File:** `lookup.go:27`

```go
url := c.serviceURL + "/log/lookup/" + artifactID
```

**Problem:** `artifactID` is concatenated directly into the URL path with no sanitization or encoding. An artifact ID containing characters like `../`, `?`, `#`, `%00`, or newlines (`\r\n`) could:
1. **Path traversal:** `../../admin/delete` would hit a different endpoint.
2. **Query injection:** `foo?admin=true` appends query parameters.
3. **Request smuggling:** Newline characters could corrupt the HTTP request.

The same pattern exists in `publish.go` but publish validates `ArtifactID != ""` without sanitizing path-unsafe characters.

**Fix:**
```go
import "net/url"

url := c.serviceURL + "/log/lookup/" + url.PathEscape(artifactID)
```

Also add validation in `Publish()` to reject artifact IDs containing `/`, `?`, `#`, `\n`, `\r`, or `%`.

---

## Important Issues

### WR-01: No HTTP Client Timeout -- Indefinite Hangs on Unresponsive Servers

**File:** `client.go:47-48`

```go
serviceURL: "https://api.skillledger.dev",
http:       http.DefaultClient,
```

**Problem:** `http.DefaultClient` has **no timeout**. If the log server accepts the TCP connection but never responds (slowloris, network partition, misconfigured proxy), the goroutine blocks indefinitely. In a CLI tool this hangs the user's terminal; in the verification pipeline during `skillledger verify`, it blocks the entire install-time check.

**Fix:**
```go
http: &http.Client{
    Timeout: 30 * time.Second,
},
```

---

### WR-02: No Replay Attack Prevention -- Stale Log Entries Accepted Indefinitely

**File:** `lookup.go:14-21`

**Problem:** `LookupResponse` contains a `PublishedAt` timestamp but the client never checks it. A compromised server (or cache) could replay an old, valid entry for a since-revoked artifact. Without checking that the log entry's timestamp is recent or that the tree head is fresh, there is no way to detect rollback attacks.

**Fix:** At minimum, `LookupEntry` should return the checkpoint/tree head alongside the entry so callers can verify freshness. Ideally, the client should maintain a last-known-good tree size and reject checkpoints that go backwards.

---

### WR-03: `PublishEntry` Accepts Publish Without Authentication Silently

**File:** `client.go:84-86`

```go
if c.apiKey != "" {
    httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
}
```

**Problem:** If `apiKey` is empty, the request is sent unauthenticated with no warning. `Publish()` in `publish.go:52-54` also treats API key as optional. For a security-critical publish operation, sending an unauthenticated request will just get a 401/403 from the server -- but the error message won't tell the user they forgot to configure their API key. This degrades the user experience for a security-critical workflow.

**Fix:** Either require `apiKey` in `PublishEntry` (return error if empty), or at minimum log a warning:
```go
if c.apiKey == "" {
    log.Warn().Msg("no API key configured; publish request will be unauthenticated")
}
```

---

### WR-04: `AddEntry` in `log/internal/logclient/client.go` Does Not Limit Response Body

**File:** `/Users/rishikeshranjan/code/rishiPersonal/skillLedger/log/internal/logclient/client.go:141`

```go
body, err := io.ReadAll(resp.Body)
```

**Problem:** Unlike `cli/internal/tlog/client.go:96` which uses `io.LimitReader`, the logclient's `AddEntry` reads the full response body without any size limit. A malicious or buggy log server could return a multi-gigabyte response.

**Fix:**
```go
body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
```

---

## Minor Issues

### IN-01: `LookupResponse.PublishedAt` Is String, Not `time.Time`

**File:** `lookup.go:20`

```go
PublishedAt string `json:"published_at"`
```

Using a raw string means callers must parse the timestamp themselves, and there is no validation that the value is a valid RFC3339 timestamp. This invites bugs in downstream consumers.

---

### IN-02: No Input Validation on `LookupEntry`'s `artifactID` Parameter

**File:** `lookup.go:26`

`LookupEntry` accepts any string for `artifactID` including empty string. Unlike `Publish()` which validates inputs, `LookupEntry` will happily send a GET to `/log/lookup/` (empty) or `/log/lookup/   ` (whitespace).

**Fix:** Add a guard: `if artifactID == "" { return nil, fmt.Errorf("artifact ID is required") }`

---

### IN-03: `Publish()` Creates a New Client Per Call

**File:** `publish.go:51-55`

Every call to `Publish()` creates a new `Client`, discarding connection pooling. For batch operations this is wasteful. Not a bug, but a design smell that could matter if batch publish is added later.

---

## Summary

The transparency log client is fundamentally incomplete for its stated security purpose. It is a thin HTTP wrapper around a JSON API that provides **no cryptographic verification** of log entries. The project already has a proper Tessera-integrated client in `log/internal/logclient/`, but the CLI verification pipeline (`cli/internal/tlog/`) does not use it. This means `skillledger verify` trusts whatever the server says -- completely undermining the transparency log's security guarantees.

The path traversal in artifact ID URL construction is a secondary but concrete vulnerability.

---

## Score: 3/10

The code is well-structured, well-tested for what it does, and handles HTTP edge cases properly (response limits, status codes, context propagation). But what it does is fundamentally insufficient: a transparency log client that doesn't verify proofs is security theater. The existing `log/internal/logclient` proves the team knows how to do this correctly -- the gap is that the CLI-facing client was never connected to it.

---

_Reviewed: 2026-05-07_
_Reviewer: Claude (adversarial review)_
_Depth: deep (cross-module trace)_
