# SkillLedger — Project Documentation

Everything you need to know about SkillLedger if you're landing here for the first time.

## What is SkillLedger?

SkillLedger is a supply-chain security toolchain for AI agent skills. It answers one question: **"Was this skill actually built from the source code it claims?"**

AI agents (Claude Code, ChatGPT, Copilot, etc.) use "skills" — installable plugins that extend what the agent can do. These skills are published by third parties and installed by developers and enterprises. The problem: there is no standard way to verify that a skill you download was actually built from the source code on GitHub. An attacker can publish a malicious skill under a legitimate-looking name, and nothing in the install pipeline catches it.

SkillLedger fixes this by providing:

1. **A universal artifact spec** — a `skillledger.yaml` manifest format that works across Claude Code skills, MCP servers, OpenClaw plugins, Anthropic skills, OpenAI tools, Codex tools, and OpenCode
2. **Deterministic builds** — `skillledger build` produces byte-identical artifacts from the same source (content-addressed, reproducible)
3. **Cryptographic signing** — Sigstore keyless signing with SLSA Level 3 provenance attestations
4. **A transparency log** — an append-only Merkle tree where signed artifacts are registered (you can't tamper with or delete entries)
5. **Install-time verification** — `skillledger verify` checks signature + provenance + transparency log + capability policy in one command, and blocks the install if anything fails
6. **Capability policies** — a DSL that lets enterprises define what skills are allowed to do (e.g., "no skill may read ~/.ssh")

The core insight: **runtime sandboxing cannot detect a supply-chain substitution attack.** By the time the skill runs, the swap has already happened. The real problem is build provenance, and SkillLedger is the first tool to bring Sigstore/SLSA patterns into the AI agent skill ecosystem.

## Why does this exist?

On February 3, 2026, CVE-2026-25253 was disclosed (CVSS 8.8). 341 of 2,857 skills on ClawHub (the OpenClaw plugin registry) were found to be compromised with Atomic Stealer malware. The attack exploited three weaknesses:

1. **No registry-to-source verification** — ClawHub accepted skill submissions without proof that the published tarball matched the source repository
2. **No install-time signatures** — The OpenClaw client installed skills by name without checking signatures
3. **No runtime capability bounds** — Installed skills ran with full shell access

Microsoft's Agent Governance Toolkit (AGT, released April 2, 2026) addresses weakness #3 — runtime governance. SkillLedger addresses weaknesses #1 and #2 — build provenance and install-time verification. They're complementary: if you catch the substitution at install time, you never need runtime policy to adjudicate it.

## How does it work?

### The full lifecycle

```
Source Code → Build → Sign → Publish → Verify → Install
     │          │       │        │         │
     │          │       │        │         └─ Check: signature, provenance,
     │          │       │        │            transparency log, policy
     │          │       │        │
     │          │       │        └─ Write entry to append-only Merkle tree
     │          │       │
     │          │       └─ Sigstore keyless signing (OIDC identity)
     │          │          + SLSA L3 provenance attestation
     │          │
     │          └─ Deterministic archive: sorted files, normalized
     │             timestamps, content-addressed filename
     │
     └─ skillledger.yaml manifest declaring:
        - identity, version, source repo
        - capability declarations (filesystem, network, secrets, tools)
        - ecosystem type (claude-code, mcp, openclaw, etc.)
```

### Step by step

**1. Developer writes a `skillledger.yaml` manifest** in their skill source tree. This declares the skill's identity, version, source repository, and capabilities (what filesystem paths it reads, what network calls it makes, what tools it uses). Think of it as Android's `AndroidManifest.xml` but for AI agent skills.

**2. `skillledger build` produces a deterministic artifact.** The build system collects source files in sorted order, applies ignore patterns (`.skillledgerignore`), normalizes all file metadata (timestamps set to epoch, permissions to 0644/0755), and archives them into a tar.gz. The same source tree always produces the exact same bytes. The artifact filename is content-addressed — it includes a hash of the contents. A `skill-lock.json` lockfile records the exact hash.

**3. `skillledger sign` signs the artifact.** Using Sigstore's keyless signing, the developer authenticates via their GitHub/Google OIDC identity. No keys to manage — your identity IS the key. The signing process generates an in-toto attestation with SLSA Level 3 provenance, linking the artifact to the exact source commit. The signature is recorded in Sigstore's public transparency log (Rekor).

**4. `skillledger publish` writes an entry to the SkillLedger transparency log.** This is a Tessera-based append-only Merkle tree. Once an entry is written, it cannot be modified or deleted. The publisher authenticates with an API key (issued by the log operator). The entry contains the artifact hash, content address, and publisher identity — not the artifact itself.

**5. `skillledger verify` runs the full check at install time.** Four checks in sequence, fail-closed:
   - **Signature verification** — Is the Sigstore signature valid? Was it signed by the claimed identity?
   - **Provenance verification** — Does the SLSA attestation link to the claimed source repository and commit?
   - **Transparency log lookup** — Is this artifact hash registered in the transparency log? Does the inclusion proof verify against the Merkle tree root?
   - **Policy evaluation** — Does the skill's declared capabilities comply with the configured policy? (e.g., "no network access", "no reading ~/.ssh")

If any check fails, the install is blocked. Fail-closed by default.

**6. Pre-install hooks automate verification.** Shell scripts that integrate with each ecosystem's native install mechanism. When you install a Claude Code skill, the hook runs `skillledger verify` automatically before the skill is installed. If verification fails, the install is blocked.

## How does it work in the backend?

### Three binaries, one database

SkillLedger runs as three cooperating processes:

```
┌──────────────────────────────────────────────────────┐
│                    Caddy (TLS)                        │
│                  ports 80 + 443                       │
└───────────────────────┬──────────────────────────────┘
                        │ reverse proxy
                        ▼
┌──────────────────────────────────────────────────────┐
│           skillledger-service (FastAPI)                │
│                 port 8000 (127.0.0.1)                 │
│                                                       │
│  Routes:                                              │
│  POST /log/publish   — authenticated artifact publish │
│  GET  /log/lookup/{id} — public artifact lookup       │
│  POST /publishers    — admin: create publisher        │
│  POST /publishers/{id}/keys — admin: generate API key │
│  GET  /publishers    — admin: list publishers         │
│  GET  /health        — health check                   │
│                                                       │
│  Auth: SHA-256 hashed Bearer tokens                   │
│  Admin: constant-time admin key comparison            │
└──────────┬───────────────────────────────┬────────────┘
           │                               │
           ▼                               ▼
┌─────────────────────┐      ┌─────────────────────────┐
│  PostgreSQL 16+     │      │  skillledger-log         │
│                     │      │  (Tessera personality)   │
│  Tables:            │      │  port 2025 (127.0.0.1)  │
│  - log_entries      │      │                          │
│  - publishers       │      │  Merkle tree storage:    │
│  - api_keys         │      │  POSIX filesystem        │
│                     │      │  (tiles on disk)         │
│  Stores: metadata   │      │                          │
│  NOT the Merkle tree│      │  Stores: the actual      │
│                     │      │  append-only log          │
└─────────────────────┘      └─────────────────────────┘
```

**skillledger-service** (Python/FastAPI) is the API gateway. It handles authentication (publisher API keys), request validation, and metadata storage. When a publisher submits an artifact entry, the service validates the request, forwards it to the log personality, and stores metadata in Postgres.

**skillledger-log** (Go) is the Tessera "personality" — a thin Go binary that embeds the Tessera library and runs an append-only Merkle tree. It uses POSIX filesystem storage (tiles stored as files in a directory). This is the actual transparency log. It receives entries from the service and writes them to the tree. It serves tile data for inclusion and consistency proofs.

**PostgreSQL** stores metadata only — publisher accounts, API keys, artifact entry records. It does NOT store the Merkle tree. The Merkle tree lives on the filesystem managed by Tessera.

**Caddy** (production only) provides automatic TLS termination and reverse-proxies to the FastAPI service. In development, you hit the service directly on port 8000.

### The transparency log (Tessera)

The transparency log is the core cryptographic primitive. It's an append-only data structure based on a Merkle tree:

- Every artifact entry gets a leaf in the tree
- The tree produces a root hash that commits to ALL entries
- You can prove any specific entry is in the tree (inclusion proof) without downloading the entire log
- You can prove the log hasn't been tampered with (consistency proof) by comparing root hashes over time
- The log uses a "tile" architecture — the tree is split into cacheable, CDN-friendly tiles

SkillLedger uses **Tessera v1.0.2** (not Trillian v1, which is in maintenance mode). Tessera is a library, not a microservice — it's embedded directly in the `skillledger-log` binary. Storage is POSIX filesystem for self-hosted deployments (a directory of tile files), with optional GCP/AWS backends for scale.

### The policy engine (OPA)

The policy engine lets enterprises define what capabilities skills are allowed to declare. It has three layers:

1. **DSL** — A YAML-based capability policy language with operators like `contains`, `any`, `except`, `warn`. Human-readable, purpose-built for skill capabilities.

2. **Compiler** — The DSL compiles to Rego (OPA's native policy language). This is SkillLedger's custom DSL-to-Rego compiler.

3. **OPA Evaluator** — The compiled Rego policy is evaluated by an embedded OPA engine (no OPA server needed — it's a Go library compiled into the CLI binary). The evaluator takes a skill's capability manifest and returns allow/deny/warn.

Three presets ship out of the box (strict, moderate, permissive) so users don't need to learn the DSL on day 1. Enterprises can also define publisher allowlists based on Sigstore certificate identities.

### Authentication flow

```
Publisher                    Service                     Log
   │                           │                          │
   │ POST /log/publish         │                          │
   │ Authorization: Bearer <key>                          │
   │ ─────────────────────────>│                          │
   │                           │                          │
   │                     hash(key) == api_keys.key_hash?  │
   │                     publisher.active == true?        │
   │                     api_key.revoked == false?        │
   │                           │                          │
   │                     if no: 401 Unauthorized          │
   │                           │                          │
   │                     if yes: validate entry           │
   │                           │ POST /add                │
   │                           │─────────────────────────>│
   │                           │                          │
   │                           │      log_index           │
   │                           │<─────────────────────────│
   │                           │                          │
   │                     store metadata in Postgres       │
   │                           │                          │
   │     { index, hash }       │                          │
   │ <─────────────────────────│                          │
```

API keys are generated as 64-character hex strings (32 bytes of `secrets.token_hex`). Only the SHA-256 hash is stored in the database. The first 8 characters are stored as `key_prefix` for identification. The full key is shown exactly once at creation time and never again.

Admin endpoints (create publisher, generate/revoke keys) require the admin bootstrap key, compared using `hmac.compare_digest` to prevent timing attacks.

### The build pipeline

```
Source tree
    │
    ▼
Collector
    │  - Walk files in sorted order
    │  - Apply .skillledgerignore patterns
    │  - Skip symlinks (via LstatIfPossible)
    │  - Enforce 50MB per-file size limit
    │  - Reject path traversal (../)
    │
    ▼
Archive
    │  - Create tar.gz with normalized metadata:
    │    - Timestamps: Unix epoch (0)
    │    - Permissions: 0644 (files), 0755 (dirs)
    │    - Owner: root/root
    │  - Files in lexicographic order
    │  - Deterministic gzip (no timestamps in header)
    │
    ▼
Content-addressed name
    │  sha256 hash of archive bytes → filename
    │  Format: sha256-<hash>
    │
    ▼
Lockfile (skill-lock.json)
    │  JCS-canonical JSON with:
    │  - artifact hash
    │  - content address
    │  - source commit
    │  - build timestamp (commit time, not wall time)
    │
    ▼
Output: deterministic .skillledger.tar.gz + skill-lock.json
```

The key insight: by normalizing all metadata and sorting file order, the same source tree always produces the same artifact bytes. This makes content-addressing meaningful — the hash IS the identity.

## What is needed to make this work?

### For developers (skill publishers)

- **Go 1.26+** — to build the CLI from source (or download a pre-built binary)
- **A GitHub/Google account** — for Sigstore keyless signing (OIDC identity)
- **cosign CLI** — for the signing step (installed separately, never imported as a Go library)
- **A `skillledger.yaml`** in your skill source directory

### For enterprises (skill consumers)

- **The `skillledger` CLI** — single static Go binary, no runtime dependencies
- **A policy** — pick a preset (strict/moderate/permissive) or write a custom policy YAML
- **Pre-install hooks** — run `hooks/install.sh` to install hooks for your ecosystems

### For self-hosting the transparency log

- **Docker + Docker Compose** — the entire stack runs with `docker compose up`
- **A server** — $50-200/month (Hetzner, DigitalOcean, etc.)
- **A domain name** — for production TLS (Caddy handles certificates automatically)
- **PostgreSQL 16+** — included in the Docker Compose setup

Minimum production requirements:
```
CPU:    2 cores
RAM:    2 GB
Disk:   20 GB (grows with log entries)
OS:     Linux (any distro with Docker)
```

### For CI/CD integration

- **GitHub Actions** — use the provided reusable workflow or composite actions
- **`SKILLLEDGER_API_KEY`** — stored as a GitHub repository secret
- **`id-token: write` permission** — required for Sigstore keyless signing in CI

## Repository structure

```
skillLedger/
│
├── cli/                          # The CLI binary (Go)
│   ├── cmd/skillledger/main.go   # Entrypoint
│   └── internal/
│       ├── builder/              # Deterministic artifact builder
│       │   ├── archive.go        # Tar.gz creation with normalized metadata
│       │   ├── builder.go        # Build orchestrator
│       │   ├── collector.go      # Source tree walker (ignore, symlink, size limits)
│       │   └── lockfile.go       # skill-lock.json read/write
│       ├── canon/                # JCS (JSON Canonicalization Scheme)
│       ├── cmd/                  # Cobra command definitions
│       │   ├── audit.go          # skillledger audit
│       │   ├── build.go          # skillledger build
│       │   ├── init.go           # skillledger init
│       │   ├── policy.go         # skillledger policy (check/compile/list)
│       │   ├── publish.go        # skillledger publish
│       │   ├── sign.go           # skillledger sign
│       │   ├── validate.go       # skillledger validate
│       │   └── verify.go         # skillledger verify
│       ├── ecosystem/            # Per-ecosystem skill discovery
│       │   ├── adapter.go        # Common interface + registry
│       │   ├── claudecode.go     # Claude Code skills
│       │   ├── mcp.go            # MCP servers
│       │   ├── openclaw.go       # OpenClaw plugins
│       │   ├── anthropic.go      # Anthropic skills
│       │   ├── openai.go         # OpenAI tools
│       │   ├── codex.go          # Codex tools
│       │   └── opencode.go       # OpenCode
│       ├── ioc/                  # Indicators of Compromise
│       │   ├── bundled.go        # Embedded IOC database
│       │   ├── ioc.go            # IOC matching engine
│       │   └── data/ioc-hashes.json  # Bundled known-bad hashes
│       ├── manifest/             # Artifact manifest types + parser
│       ├── output/               # Terminal output formatting
│       ├── policy/               # Policy engine
│       │   ├── dsl/              # DSL parser + AST + Rego compiler
│       │   ├── eval/             # OPA evaluator wrapper
│       │   ├── preset/           # Built-in presets (strict/moderate/permissive)
│       │   ├── allowlist/        # Publisher allowlist (cert-identity matching)
│       │   └── policy.go         # Public policy facade
│       ├── report/               # JSON + SARIF report generators
│       ├── sbom/                 # CycloneDX SBOM generation
│       ├── scanner/              # File hash scanner
│       ├── schema/               # JSON Schema validation
│       │   └── schemas/          # Embedded schema files
│       ├── signer/               # Sigstore signing + verification
│       │   ├── signer.go         # Sign with Sigstore keyless
│       │   ├── verifier.go       # Verify signatures
│       │   └── provenance.go     # SLSA L3 provenance generation
│       ├── tlog/                 # Transparency log client
│       │   ├── client.go         # HTTP client with auth
│       │   ├── publish.go        # Publish entries
│       │   └── lookup.go         # Lookup + inclusion proof
│       ├── verify/               # Install-time verification
│       │   ├── pipeline.go       # Verification pipeline orchestrator
│       │   ├── steps.go          # Individual verification steps
│       │   └── verify.go         # Public verify API
│       └── yara/                 # YARA rule engine
│
├── log/                          # Transparency log personality (Go)
│   ├── cmd/skillledger-log/      # Log binary entrypoint
│   └── internal/
│       ├── logclient/            # Tessera client
│       │   ├── client.go         # HTTP client for Tessera
│       │   └── proof.go          # Inclusion + consistency proofs
│       └── personality/          # Tessera personality
│           ├── personality.go    # HTTP handlers + Tessera integration
│           └── entry.go          # Entry validation
│
├── service/                      # Hosted service (Python/FastAPI)
│   ├── alembic/                  # Database migrations
│   │   └── versions/             # Migration files
│   ├── src/skillledger_service/
│   │   ├── models/               # SQLAlchemy models
│   │   │   ├── artifact.py       # LogEntryRecord model
│   │   │   └── publisher.py      # Publisher + APIKey models
│   │   ├── routers/
│   │   │   ├── log.py            # /log/publish and /log/lookup endpoints
│   │   │   └── publishers.py     # /publishers CRUD endpoints
│   │   ├── auth.py               # API key auth (hash, generate, validate)
│   │   ├── config.py             # Pydantic settings
│   │   ├── db.py                 # Async SQLAlchemy session factory
│   │   ├── health.py             # Health check endpoint
│   │   └── main.py               # FastAPI app factory
│   └── tests/                    # Test suite (20 tests)
│       ├── test_auth.py          # Auth middleware tests
│       ├── test_log.py           # Publish/lookup tests
│       ├── test_publishers.py    # Publisher CRUD tests
│       └── test_health.py        # Health check test
│
├── spec/                         # Artifact specification
│   ├── schemas/                  # JSON Schema definitions
│   │   ├── core.schema.json      # Core manifest schema
│   │   ├── capabilities.schema.json  # Capability manifest schema
│   │   └── profiles/             # Per-ecosystem profile schemas
│   └── examples/                 # Example skillledger.yaml files
│
├── hooks/                        # Pre-install verification hooks
│   ├── claude-code-hook.sh       # Claude Code pre-install hook
│   ├── mcp-hook.sh               # MCP server pre-install hook
│   ├── npm-hook.sh               # npm pre-install hook
│   ├── openclaw-hook.sh          # OpenClaw pre-install hook
│   ├── generic-hook.sh           # Generic hook for any ecosystem
│   └── install.sh                # Installer for all hooks
│
├── .github/
│   ├── actions/
│   │   ├── build/action.yml      # Composite: install CLI + build artifact
│   │   ├── sign/action.yml       # Composite: sign with cosign
│   │   └── verify/action.yml     # Composite: verify artifact
│   └── workflows/
│       └── skillledger-ci.yml    # Reusable workflow (build+sign+publish+verify)
│
├── docker-compose.yml            # Development deployment
├── docker-compose.prod.yml       # Production overlay (adds Caddy)
├── Caddyfile.prod                # Caddy reverse proxy configuration
├── Taskfile.yml                  # Task runner for build/test/lint
├── .golangci.yml                 # Go linter configuration
├── .pre-commit-config.yaml       # Pre-commit hooks
├── CLAUDE.md                     # AI assistant instructions
├── idea.md                       # Usage guide
└── project.md                    # This file
```

## Key technologies and why they were chosen

| Technology | What it does | Why this one |
|------------|-------------|--------------|
| **Go** | CLI binary | Single static binary, no runtime deps, Sigstore ecosystem is Go-native |
| **Python/FastAPI** | Hosted service | Async-first, auto OpenAPI docs, Pydantic validation, fast to ship |
| **Tessera v1.0.2** | Transparency log | Library (not microservice), POSIX storage, low ops cost. Trillian v1 is in maintenance mode |
| **sigstore-go v1.1.4** | Signing/verification | Official Go client. cosign has no API stability — never import as library |
| **OPA (embedded)** | Policy evaluation | Embedded in CLI binary via rego package. No external server needed |
| **CycloneDX** | SBOM format | Security-focused (vs SPDX which is license-focused). Better Go library |
| **Cobra + Viper** | CLI framework | Industry standard (kubectl, gh, cosign all use it) |
| **SQLAlchemy 2.0** | Python ORM | Async-first with asyncpg. Production-proven |
| **Caddy** | Reverse proxy | Automatic HTTPS with Let's Encrypt. Zero-config TLS |
| **PostgreSQL** | Metadata store | JSONB for attestation metadata. Reliable. Self-hostable |

## Glossary

| Term | Definition |
|------|-----------|
| **Artifact** | A built, packaged skill — the `.skillledger.tar.gz` file |
| **Content-addressed** | The artifact's identity is its content hash. Same content = same identity |
| **Capability manifest** | The `capabilities:` section of `skillledger.yaml` declaring what the skill accesses |
| **DSL** | Domain-Specific Language — SkillLedger's policy language for capability rules |
| **Fail-closed** | If verification can't confirm the skill is safe, the install is blocked (deny by default) |
| **Inclusion proof** | A Merkle proof that a specific entry exists in the transparency log |
| **IOC** | Indicator of Compromise — a hash or pattern matching a known-malicious artifact |
| **Keyless signing** | Signing without managing keys — your OIDC identity (GitHub, Google) IS the key |
| **Lockfile** | `skill-lock.json` — records the exact hash and provenance of a built artifact |
| **Merkle tree** | A hash tree where each leaf is a data entry and each node is the hash of its children. Append-only. Tamper-evident |
| **OPA** | Open Policy Agent — evaluates Rego policies. Embedded in the CLI |
| **Personality** | Tessera term for the application-specific layer that validates entries before adding them to the Merkle tree |
| **Provenance** | SLSA attestation linking an artifact to its source repository, commit, and build process |
| **Rego** | OPA's policy language. SkillLedger's DSL compiles down to Rego |
| **SBOM** | Software Bill of Materials — a list of all components in a skill (CycloneDX format) |
| **Sigstore** | Open-source signing infrastructure. Provides keyless signing, transparency logs, and certificate authorities |
| **SLSA** | Supply-chain Levels for Software Artifacts — a framework for supply-chain security. SkillLedger targets Level 3 |
| **Tessera** | Google's tile-based transparency log library. Successor to Trillian |
| **Tile** | A chunk of the Merkle tree stored as a file. Cacheable and CDN-friendly |
| **Transparency log** | An append-only, tamper-evident log. Once an entry is written, it cannot be modified or deleted |

## Current status

**v1.0 milestone: complete.** All 8 phases implemented:

| Phase | What it built | Status |
|-------|--------------|--------|
| 1. Foundation & Artifact Spec | Universal manifest format, JSON Schemas, ecosystem profiles | Complete |
| 2. Audit CLI | Skill scanner, SBOM generator, IOC matching, SARIF output, YARA rules | Complete |
| 3. Reproducible Build | Deterministic builder, content-addressing, lockfile | Complete |
| 4. Signing & Provenance | Sigstore signing, SLSA L3 provenance, verification | Complete |
| 5. Transparency Log | Tessera personality, FastAPI service, Docker Compose, log client | Complete |
| 6. Policy Engine | DSL parser, Rego compiler, OPA evaluator, presets, allowlists | Complete |
| 7. Verification | Fail-closed verification pipeline, pre-install hooks (Claude Code, MCP, npm) | Complete |
| 8. Hosted Service & CI/CD | Publisher auth, CRUD API, GitHub Actions, production deployment, remaining hooks | Complete |

**Test coverage:** Go CLI (20 packages, all passing), Python service (20 tests, all passing).

**Known gaps:**
- Live deployment at api.skillledger.in (infrastructure code is complete, needs DNS + server provisioning)
- CLI binary download checksum verification in CI actions (deferred — HTTPS only for now)
- Symlink detection in file collector uses `LstatIfPossible` which falls back to `Stat` on non-OS filesystems
