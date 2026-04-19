<!-- GSD:project-start source:PROJECT.md -->
## Project

**SkillLedger**

A deterministic build-and-attestation toolchain for AI agent skill artifacts. SkillLedger lets developers build skills from source into content-addressed, signed artifacts with SLSA-3 provenance, and lets enterprises verify those artifacts at install time against a transparency log and capability policy. It covers every major agent skill ecosystem: Claude Code skills, MCP servers, OpenClaw plugins, Anthropic skills, OpenAI/Codex tools, OpenCode, and others.

**Core Value:** If you can catch a supply-chain substitution at install time, you never need runtime policy to adjudicate it. SkillLedger must make it trivially easy to verify that a skill artifact was actually built from the source it claims — across every agent ecosystem.

### Constraints

- **Stack:** Go for CLI tooling, Python (FastAPI) for hosted service, monorepo structure (`/cli`, `/service`, `/spec`)
- **Crypto:** Compose existing tools — Sigstore/Cosign for signing, Trillian for transparency log, CycloneDX for SBOM. Don't reinvent.
- **Policy engine:** OPA (Open Policy Agent) with a custom DSL-to-Rego compiler
- **Spec location:** Artifact spec lives in `/spec` within this monorepo; fork to standalone repo when ready for CNCF/Sigstore governance
- **Deployment:** Self-hostable (Docker Compose) as the core path, hosted service on top
- **Budget:** <$30K total. Transparency log runs on ~$200/month Hetzner. Primary cost is builder time.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Recommended Stack
### CLI Core (Go)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Go | 1.26.x | Language | Current stable (1.26.2, Apr 2026). Single binary, no runtime deps, Sigstore ecosystem is Go-native. Deterministic builds with `CGO_ENABLED=0 -trimpath`. All dependencies support 1.26. OPA v1.15.2 is built with Go 1.26.2. | HIGH |
| spf13/cobra | v1.10.2 | CLI framework | Industry standard (used by kubectl, gh, cosign, opa). Subcommand tree maps to `skillledger audit/build/verify/publish`. Persistent flags, shell completions, pre/post-run hooks. | HIGH |
| spf13/viper | v1.21.0 | Configuration | Pairs with Cobra. 12-factor env binding, YAML/TOML config files, flag overrides. For `~/.skillledger/config.yaml` and per-project `.skillledger.yaml`. Heading toward v2 but v1.21 is stable. | HIGH |
### Signing and Attestation (Go)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| sigstore/sigstore-go | v1.1.4 | Signing and verification library | Official Go client for Sigstore. Minimal dependency tree, stable API, passes sigstore-conformance suite. Supports protobuf bundle format, Rekor integration, TSA. Custom `Keypair` interface for extensibility. **Do NOT import cosign as a library** -- no API stability, no semver, massive deps. | HIGH |
| sigstore/cosign | v3.0.6 (CLI only) | Signing CLI for user workflows | Use as external CLI tool for keyless signing and CI/CD pipelines. v3 supports bundle format by default, `--trusted-root` and `--signing-config` for simplified config. v4 planned (removing legacy features). Never import as Go library. | HIGH |
| in-toto/attestation | v1.2.0 | SLSA provenance format | Go bindings (most mature language) for in-toto attestation framework. Protobuf-based Statement and Provenance v1 predicate types. Used by cosign, SLSA GitHub generator, Homebrew. SLSA v1.1/v1.2 RC2 provenance predicates. | HIGH |
### Transparency Log (Go)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| transparency-dev/trillian-tessera | v1.0.2 | Transparency log library | **Use Tessera, NOT Trillian v1.** Tessera is v1.0.2 GA (Feb 2025), production-ready. Tile-based architecture = higher throughput, lower cost, simpler deployment. Library-not-microservice. Supports POSIX filesystem (self-hosted), AWS, GCP backends. | HIGH |
| Criterion | Trillian v1 | Tessera v1.0.2 |
|-----------|-------------|-----------------|
| Status | Maintenance mode | GA, active development |
| Architecture | Microservice (gRPC server + MySQL/Postgres) | Library (embed in your Go binary) |
| Storage | Requires separate database | POSIX filesystem, GCP, AWS |
| Operational cost | High (server + DB) | Low (library + filesystem) |
| API | Proprietary gRPC | Tiled HTTP API (cacheable, CDN-friendly) |
| Self-hosting | Complex | Simple (POSIX = just a directory) |
| Budget fit | ~$200/mo for Trillian+DB | ~$50/mo (no separate process) |
### SBOM (Go)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| CycloneDX/cyclonedx-go | v0.10.0 | SBOM generation and parsing | Official Go library for CycloneDX format. Supports spec versions 1.0-1.6, read/write JSON and XML. 425+ importers, Apache 2.0. Requires Go 1.23+. | HIGH |
| CycloneDX/cyclonedx-gomod | latest | Go module SBOM generation | Generates CycloneDX SBOMs from Go modules. Useful for SkillLedger's own SBOM (GoReleaser integration) but NOT for skill artifact SBOMs (skills are multi-ecosystem). | MEDIUM |
### Policy Engine (Go)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| open-policy-agent/opa | v1.15.2 | Embedded policy evaluation | Use `github.com/open-policy-agent/opa/v1/rego` package to embed OPA directly in CLI binary. No OPA server needed. Built with Go 1.26.2. | HIGH |
### Hosted Service (Python)
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Python | 3.12+ | Runtime | FastAPI 0.130+ requires 3.10+. Use 3.12 for performance and f-string improvements. | HIGH |
| FastAPI | 0.128+ | HTTP API framework | Async-first, Pydantic v2 native, auto OpenAPI docs. Dependency injection via `Depends()` for DB sessions, auth, policy. Requires Python 3.10+. | HIGH |
| Pydantic | v2.x | Data validation | 50x faster than v1. Use `model_validator` and `from_attributes=True` for ORM mapping. | HIGH |
| pydantic-settings | latest | Configuration | Extracted from Pydantic v2 core. Type-safe config from env vars, .env files, secrets. Use for all service configuration. | HIGH |
| SQLAlchemy | 2.0+ | Database ORM | Async-first with asyncpg. Use `async_sessionmaker` and `AsyncSession` for non-blocking DB ops. | HIGH |
| asyncpg | latest | PostgreSQL async driver | Fastest async PostgreSQL driver for Python. Connection string: `postgresql+asyncpg://`. | HIGH |
| Alembic | latest | Database migrations | SQLAlchemy-native migration tool. Supports async engines. Essential for schema evolution. | HIGH |
| uvicorn | latest | ASGI server | Production server for FastAPI. Use `uvicorn[standard]` for uvloop and httptools. | HIGH |
### Build and Release
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| GoReleaser | v2.15.3 | Release automation | Cross-compilation, checksums, SBOM generation, Cosign signing, SLSA provenance via slsa-github-generator. Handles all reproducible build flags. | HIGH |
| GitHub Actions | - | CI/CD | SLSA provenance generation via slsa-github-generator. GoReleaser integration. Standard for open-source supply-chain security projects. | HIGH |
### Reproducible Build Configuration
# .goreleaser.yaml (key sections)
- `CGO_ENABLED=0`: Static linking, no C dependencies
- `-trimpath`: Removes local filesystem paths from binary
- `mod_timestamp: "{{.CommitTimestamp}}"`: Git commit time, not build time
- `ldflags -X main.date={{.CommitDate}}`: Commit date, not current date
### Spec and Schema
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| YAML | - | Artifact spec format | Human-readable, git-diffable, universal tooling. | HIGH |
| JSON Schema | draft-2020-12 | Schema validation | Validate artifact specs and capability manifests. | HIGH |
| santhosh-tekuri/jsonschema | v6.x | Go JSON Schema validation | Fast, spec-compliant, supports draft-2020-12. | MEDIUM |
### Supporting Libraries (Go)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| stretchr/testify | latest | Test assertions | Always. `assert` and `require` packages for unit tests. |
| rs/zerolog | latest | Structured logging | Always. Zero-allocation JSON logging. Use for `--verbose` / `--json` output modes. |
| charmbracelet/lipgloss | latest | Terminal styling | Always. Pretty CLI output -- progress bars, tables, colored text. Used by gh, charm tools. |
| spf13/afero | latest | Filesystem abstraction | Testing. Mock filesystem for audit/scan operations. |
| google/go-containerregistry | latest | OCI registry interaction | If storing signed artifacts in OCI registries. Cosign uses this internally. |
| grpc/grpc-go | v1.73.0 | gRPC | Only if Tessera personality needs gRPC frontend. May not be needed with HTTP tiled API. |
### Supporting Libraries (Python)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| httpx | latest | HTTP client | Async client for external APIs (IOC feeds, Tessera log). Also used as FastAPI test client. |
| structlog | latest | Structured logging | JSON logging for service. Pairs well with FastAPI middleware. |
| python-jose or PyJWT | latest | JWT handling | Auth tokens for hosted service. |
| pytest + pytest-asyncio | latest | Testing | Async test support for FastAPI endpoints. |
| ruff | latest | Linter/formatter | Replaces flake8 + black + isort. Single tool, 10-100x faster. |
### Development Tools
| Tool | Purpose | Notes |
|------|---------|-------|
| GoReleaser v2.15.3 | Release automation | `.goreleaser.yaml` in repo root. |
| golangci-lint | Go linting | Aggregates 50+ linters. `.golangci.yml` config. |
| Task (go-task) | Task runner | Modern Makefile replacement. `Taskfile.yml` for monorepo build/test/lint. |
| pre-commit | Git hooks | Runs linters on commit. Works across Go and Python in monorepo. |
| buf | Protobuf management | Only if custom protobuf messages needed for artifact spec. |
### Infrastructure
| Technology | Purpose | Why | Confidence |
|------------|---------|-----|------------|
| PostgreSQL 16+ | Service database | JSONB for attestation metadata, strong indexing. Self-hostable. | HIGH |
| Docker Compose | Self-hosted deployment | Single-command deployment: service + Postgres + Tessera log. | HIGH |
| protobuf 3.x | Serialization | Sigstore bundle format uses protobuf. sigstore-go depends on protobuf-specs. | HIGH |
## Alternatives Considered
| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Transparency log | Tessera v1.0.2 | Trillian v1 | Maintenance mode. Higher cost. Microservice model adds ops burden. Google/transparency.dev recommends Tessera for all new logs. |
| Signing library | sigstore-go v1.1.4 | cosign as library | No semver, no API stability, massive dep tree. Sigstore project explicitly warns against library use. |
| CLI framework | Cobra v1.10.2 | urfave/cli v2 | Cobra is the Sigstore ecosystem standard. Consistency with cosign, opa, kubectl. Better docs, Viper integration. |
| Policy engine | OPA embedded | OPA server/sidecar | Embedding avoids network dependency at verify-time. Single binary is a key constraint. No external process needed for CLI. |
| Python ORM | SQLAlchemy 2.0 | SQLModel | SQLModel is simpler but less mature for complex queries. SQLAlchemy 2.0 async is production-proven. |
| SBOM format | CycloneDX | SPDX | CycloneDX is security-focused (VEX, vulnerability tracking). SPDX is license/compliance-focused. CycloneDX has better Go library support. |
| Python linter | ruff | flake8 + black | ruff replaces all of them, 10-100x faster. |
| Tessera storage | POSIX (self-hosted) | GCP/AWS | Start with POSIX for self-hosted and early hosted service. Move to cloud backends when scaling beyond single server. |
| Python framework | FastAPI | Django | Django is synchronous-first, heavy. FastAPI's async + auto-docs + Pydantic is ideal for API service. |
| Postgres driver | asyncpg | psycopg3 | asyncpg is faster for pure async. psycopg3 only if you need sync fallback. |
| Go logging | zerolog | zap | Either works. zerolog has simpler API, zero-allocation. Not a critical choice. |
## What NOT to Use
| Avoid | Why | Use Instead |
|-------|-----|-------------|
| cosign as a Go library | No semver, no API stability, massive dependency tree. Sigstore project explicitly warns against this. Future cosign will be based on sigstore-go. | sigstore-go v1.1.4 |
| Trillian v1 for new projects | Maintenance mode. No new features. Higher operational cost. Google recommends Tessera. | Tessera v1.0.2 |
| SPDX for security SBOMs | License/compliance focused, weaker security features vs CycloneDX. | CycloneDX v1.6 via cyclonedx-go |
| Python for CLI | Slower startup, requires runtime, poor cross-compilation. | Go 1.26 (single static binary) |
| OPA server for CLI | Unnecessary process, adds latency, deployment complexity. | Embedded `rego` package |
| Pydantic v1 | 50x slower validation. FastAPI requires v2 for modern features. | Pydantic v2 |
| opa/sdk package | Deprecated. | opa/v1/rego |
| Manual Makefiles for release | Error-prone, no cross-compilation, no signing integration. | GoReleaser v2.15.3 |
## Tessera "Personality" Pattern
- **skillledger-log**: Go binary running Tessera personality (POSIX storage for self-hosted)
- **skillledger-service**: FastAPI (auth, publisher management, API gateway, metadata)
- **postgres**: Metadata store (publishers, policies, audit trail -- NOT the Merkle tree)
## Monorepo Structure
## Version Compatibility Matrix
| Package | Requires Go | Compatible With | Notes |
|---------|-------------|-----------------|-------|
| sigstore-go v1.1.4 | 1.23+ | protobuf-specs, cosign v3 bundles | Core signing/verification |
| cyclonedx-go v0.10.0 | 1.23+ | CycloneDX spec 1.0-1.6 | SBOM generation |
| OPA v1.15.2 | 1.26+ (built with) | Rego v1 syntax | Embedded policy engine |
| Cobra v1.10.2 | 1.16+ | Viper v1.21.0 | CLI framework |
| Tessera v1.0.2 | 1.22+ | POSIX, GCP, AWS storage | Transparency log |
| in-toto/attestation v1.2.0 | 1.20+ | SLSA v1.0/v1.1 provenance | Attestation format |
| grpc-go v1.73.0 | 1.23+ | protobuf 3.x | If needed for Tessera frontend |
| Python Package | Requires Python | Compatible With | Notes |
|----------------|-----------------|-----------------|-------|
| FastAPI 0.128+ | 3.10+ | Pydantic v2, SQLAlchemy 2.0 | Service framework |
| SQLAlchemy 2.0 | 3.7+ | asyncpg, Alembic | Async ORM |
| Pydantic v2 | 3.8+ | FastAPI 0.128+ | Validation |
## Version Pinning Strategy
- **Go:** `go.sum` provides content hashes. Run `go mod tidy` and commit `go.sum`. Pin major.minor in `go.mod`.
- **Python:** Use `pip-tools` to generate pinned `requirements.txt` from `pyproject.toml`. Pin exact versions in production.
- **Both:** Dependabot or Renovate for automated dependency updates.
## Installation
### CLI Development
# Go 1.26+
# Core
# Supporting
### Service Development
# Python 3.12+
# Supporting
# Dev
### Build and Release Tools
# GoReleaser
# Cosign CLI (NOT as Go library)
# golangci-lint
# Task runner
## Sources
- [sigstore/sigstore-go](https://github.com/sigstore/sigstore-go) -- v1.1.4 (Dec 10, 2025). Verified release, Go 1.23+ requirement, signing/verification API. **HIGH confidence.**
- [Sigstore Go client docs](https://docs.sigstore.dev/language_clients/go/) -- Official recommendation for Go integration. **HIGH confidence.**
- [Sigstore integration docs](https://docs.sigstore.dev/cosign/system_config/integration/) -- Explicit warning against cosign library use. **HIGH confidence.**
- [sigstore/cosign releases](https://github.com/sigstore/cosign/releases) -- v3.0.6 (Apr 6, 2026). **HIGH confidence.**
- [transparency-dev/tessera](https://github.com/transparency-dev/tessera) -- v1.0.2 GA (Feb 17, 2025). Verified POSIX/GCP/AWS backends. **HIGH confidence.**
- [Tessera announcement](https://blog.transparency.dev/introducing-trillian-tessera) -- Trillian v1 maintenance mode, Tessera rationale. **HIGH confidence.**
- [google/trillian](https://github.com/google/trillian) -- "Trillian is in maintenance mode." **HIGH confidence.**
- [CycloneDX/cyclonedx-go](https://github.com/CycloneDX/cyclonedx-go) -- v0.10.0 (Jan 31, 2026). Spec 1.0-1.6, Go 1.23+. **HIGH confidence.**
- [OPA releases](https://github.com/open-policy-agent/opa/releases) -- v1.15.2 (Apr 8, 2026). Built with Go 1.26.2. **HIGH confidence.**
- [OPA Go integration docs](https://www.openpolicyagent.org/docs/integration) -- Embedded rego package API. **HIGH confidence.**
- [spf13/cobra releases](https://github.com/spf13/cobra/releases) -- v1.10.2 (Dec 4, 2024). **HIGH confidence.**
- [spf13/viper releases](https://github.com/spf13/viper/releases) -- v1.21.0 (Sep 8, 2024). **HIGH confidence.**
- [in-toto/attestation](https://github.com/in-toto/attestation) -- v1.2.0 (Mar 18, 2026). Go most mature binding. **HIGH confidence.**
- [GoReleaser releases](https://github.com/goreleaser/goreleaser/releases) -- v2.15.3 (Apr 15, 2026). **HIGH confidence.**
- [GoReleaser reproducible builds](https://goreleaser.com/blog/reproducible-builds/) -- SLSA provenance, determinism flags. **HIGH confidence.**
- [Go 1.26 release](https://go.dev/blog/go1.26) -- Current stable, 1.26.2 (Apr 7, 2026). **HIGH confidence.**
- [FastAPI docs](https://fastapi.tiangolo.com/) -- Verified via Context7. Dependency injection, async patterns. **HIGH confidence.**
- [sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs) -- Bundle format specification. **HIGH confidence.**
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, or `.github/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
