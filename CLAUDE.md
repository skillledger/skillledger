## Project

**SkillLedger** — Supply-chain security toolchain for AI agent skills.

A deterministic build-and-attestation toolchain for AI agent skill artifacts. SkillLedger lets developers build skills from source into content-addressed, signed artifacts with SLSA-3 provenance, and lets enterprises verify those artifacts at install time against a transparency log and capability policy. It covers every major agent skill ecosystem: Claude Code skills, MCP servers, OpenClaw plugins, Anthropic skills, OpenAI/Codex tools, OpenCode, and others.

**Core Value:** If you can catch a supply-chain substitution at install time, you never need runtime policy to adjudicate it. SkillLedger must make it trivially easy to verify that a skill artifact was actually built from the source it claims — across every agent ecosystem.

## Architecture

### Monorepo Structure

```
skillLedger/
├── cli/                    # Go CLI binary (skillledger)
│   ├── cmd/skillledger/    # Main entrypoint
│   └── internal/
│       ├── builder/        # Deterministic archive builder + collector
│       ├── canon/          # JCS canonical JSON serialization
│       ├── cmd/            # Cobra commands (audit, build, sign, verify, publish, init, validate, policy)
│       ├── ecosystem/      # Per-ecosystem adapters (claude-code, mcp, openclaw, anthropic, openai, codex, opencode)
│       ├── ioc/            # IOC (Indicators of Compromise) database with bundled + live data
│       ├── manifest/       # Artifact manifest types and parser
│       ├── output/         # CLI output formatting (terminal, JSON, policy)
│       ├── policy/         # Policy engine: DSL parser, AST, Rego compiler, OPA evaluator, presets, allowlists
│       ├── report/         # JSON and SARIF report generators
│       ├── sbom/           # CycloneDX SBOM generation
│       ├── scanner/        # File hash scanner
│       ├── schema/         # JSON Schema validation (embedded schemas)
│       ├── signer/         # Sigstore signing, provenance, verification
│       ├── tlog/           # Transparency log client (publish, lookup, proof verification)
│       ├── verify/         # Install-time verification pipeline (signature → provenance → tlog → policy)
│       └── yara/           # YARA rule engine for custom detection
├── log/                    # Transparency log personality (Go)
│   ├── cmd/skillledger-log/  # Log binary entrypoint
│   └── internal/
│       ├── logclient/      # Tessera client with proof verification
│       └── personality/    # Tessera personality (entry validation, HTTP endpoints)
├── service/                # Hosted service (Python/FastAPI)
│   ├── alembic/            # Database migrations
│   ├── src/skillledger_service/
│   │   ├── models/         # SQLAlchemy models (artifact, publisher, api_key)
│   │   ├── routers/        # FastAPI routers (log publish/lookup, publisher CRUD)
│   │   ├── auth.py         # API key auth middleware (SHA-256 hash, Bearer token)
│   │   ├── config.py       # Pydantic settings
│   │   ├── db.py           # Async SQLAlchemy engine
│   │   └── main.py         # FastAPI app factory
│   └── tests/              # pytest test suite (20 tests)
├── spec/                   # Artifact specification
│   ├── schemas/            # JSON Schema definitions (core + ecosystem profiles)
│   └── examples/           # Example skillledger.yaml manifests
├── hooks/                  # Pre-install verification hooks
│   ├── claude-code-hook.sh
│   ├── mcp-hook.sh
│   ├── npm-hook.sh
│   ├── openclaw-hook.sh
│   ├── generic-hook.sh
│   └── install.sh          # Hook installer for all ecosystems
├── .github/
│   ├── actions/            # Composite actions (build, sign, verify)
│   └── workflows/          # Reusable CI workflow (skillledger-ci.yml)
├── docker-compose.yml      # Dev deployment (service + log + postgres)
├── docker-compose.prod.yml # Production overlay (adds Caddy TLS)
└── Caddyfile.prod          # Caddy reverse proxy config
```

### Component Interaction

```
Developer                     Enterprise
    │                             │
    ▼                             ▼
skillledger build           skillledger verify
    │                             │
    ▼                             │
skillledger sign             ┌────┴────────┐
    │                        │  Check:      │
    ▼                        │  1. Signature│
skillledger publish          │  2. Provenance│
    │                        │  3. Tlog entry│
    ▼                        │  4. Policy   │
┌───────────────┐            └──────────────┘
│ Transparency  │                  │
│ Log (Tessera) │◄─────── lookup ──┘
│  + FastAPI    │
│  + Postgres   │
└───────────────┘
```

### Constraints

- **Stack:** Go for CLI tooling, Python (FastAPI) for hosted service
- **Crypto:** Compose existing tools — Sigstore/Cosign for signing, Tessera for transparency log, CycloneDX for SBOM. Don't reinvent.
- **Policy engine:** OPA (Open Policy Agent) with a custom DSL-to-Rego compiler
- **Deployment:** Self-hostable (Docker Compose) as the core path, hosted service on top

## Technology Stack

### CLI (Go 1.26)
- **Framework:** Cobra v1.10.2 + Viper v1.21.0
- **Signing:** sigstore-go v1.1.4 (never import cosign as library)
- **Attestation:** in-toto/attestation v1.2.0 (SLSA provenance)
- **Transparency log:** Tessera v1.0.2 (NOT Trillian v1 — maintenance mode)
- **SBOM:** CycloneDX/cyclonedx-go v0.10.0
- **Policy:** OPA v1.15.2 embedded via opa/v1/rego
- **Testing:** testify, afero (filesystem abstraction)
- **Logging:** zerolog
- **Output:** charmbracelet/lipgloss

### Service (Python 3.12+)
- **Framework:** FastAPI 0.128+
- **ORM:** SQLAlchemy 2.0 async + asyncpg
- **Validation:** Pydantic v2
- **Migrations:** Alembic
- **Server:** uvicorn

### Infrastructure
- PostgreSQL 16+ (metadata, NOT the Merkle tree)
- Docker Compose (self-hosted deployment)
- Caddy (production TLS reverse proxy)

### What NOT to Use
- cosign as a Go library (no API stability — use sigstore-go)
- Trillian v1 (maintenance mode — use Tessera)
- OPA server (embed via rego package instead)
- Pydantic v1 (50x slower)

## Conventions

### Go Code
- All filesystem operations through `afero.Fs` for testability
- Symlink detection via `afero.Lstater.LstatIfPossible()` (Walk resolves symlinks)
- Content addresses use `sha256-<hash>` prefix format
- CLI commands in `cli/internal/cmd/`, one file per subcommand
- Ecosystem adapters implement the `Adapter` interface in `cli/internal/ecosystem/`

### Python Code
- Async-first with `AsyncSession` for all DB operations
- Auth via `get_current_publisher` dependency (SHA-256 hashed Bearer tokens)
- Admin endpoints use `get_admin_or_publisher` with `hmac.compare_digest`
- Config via pydantic-settings with `SKILLLEDGER_` env prefix

### Security
- API keys stored as SHA-256 hashes only (never plaintext)
- Admin key comparison uses constant-time `hmac.compare_digest`
- Production services bind to 127.0.0.1 (Caddy-only access)
- Fail-closed verification (deny by default)
- Hook scripts use `set -euo pipefail`

### Testing
- Go: `go test ./...` from `cli/` directory
- Python: `python3 -m pytest tests/ -v` from `service/` directory
- All tests pass: Go (20 packages), Python (20 tests)

## CLI Commands

| Command | Purpose |
|---------|---------|
| `skillledger init` | Initialize a skillledger.yaml manifest |
| `skillledger validate` | Validate a manifest against JSON Schema |
| `skillledger audit` | Scan installed skills, generate SBOM, check IOCs |
| `skillledger build` | Deterministic content-addressed artifact build |
| `skillledger sign` | Sigstore keyless signing with SLSA provenance |
| `skillledger publish` | Publish signed artifact to transparency log |
| `skillledger verify` | Full verification pipeline (signature + provenance + tlog + policy) |
| `skillledger policy` | Policy management (check, compile, list presets) |

## Development

### Running Tests
```bash
# Go CLI tests
cd cli && go test ./...

# Python service tests
cd service && python3 -m pytest tests/ -v

# Validate GitHub Actions YAML
python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ['.github/actions/build/action.yml', '.github/actions/sign/action.yml', '.github/actions/verify/action.yml', '.github/workflows/skillledger-ci.yml']]"
```

### Running the Stack
```bash
# Development
docker compose up -d

# Production (with Caddy TLS)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Milestone Status

v1.0 milestone complete (8/8 phases). All code implemented across:
- Phase 1: Foundation & Artifact Spec
- Phase 2: Audit CLI
- Phase 3: Reproducible Build
- Phase 4: Signing & Provenance
- Phase 5: Transparency Log
- Phase 6: Policy Engine
- Phase 7: Verification
- Phase 8: Hosted Service & CI/CD Integration
