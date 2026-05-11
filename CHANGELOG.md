# Changelog

All notable changes to SkillLedger are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public open-source release prep: LICENSE (MIT), Elastic License 2.0
  for the Enterprise Edition, SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md,
  comprehensive `.env.example` covering 24+ variables.
- Domain migration from `skillledger.dev` to `skillledger.in`.

### Changed
- Untracked `.planning/` directory from the public repository (kept locally
  for internal workflow state).
- Rewrote `.gitignore` to cover .env variants, IDE files, Go/Python/Node
  build outputs, Caddy runtime data, OS files, backups.

### Removed
- Tracked 58MB `cli/skillledger` Mach-O binary purged from working tree and
  from all 794 commits of git history via `git filter-repo`.
- Internal `*REVIEW*.md` post-mortem documents at the repository root,
  archived to `.planning/audits/`.

### Security
- Audited working tree and git history for secrets. No hardcoded API keys,
  tokens, certificates, database credentials, or customer data found in
  either current code or historical commits.

---

## [3.1.0] - 2026-05-11

Closed all deferred items from v2.0 and v3.0.

### Added
- HTTP SkillID resolution wired into provenance-aware policy for HTTP-proxied
  traffic.
- RuntimeAdapter interface connected to downstream callers in the proxy
  pipeline.
- Hot-reload for proxy policy set/preset commands (no longer advisory-only).
- 13 integration tests covering OTP email flow, SAML SSO, auth middleware,
  Stripe billing, Docker compose, dashboard layout, Monaco policy editor,
  file upload, and VPS install scenarios.

### Fixed
- Verification gaps resolved across Phases 09, 10, 13, 16, 28, 29, 30
  (`human_needed` items closed).

---

## [3.0.0] - 2026-05-07

Distribution, monetisation, and enterprise.

### Added
- npm distribution: `npx skillledger` via cross-compiled Go binaries packaged
  as platform-specific optional dependencies, built by GoReleaser CI.
- Email OTP login + JWT tokens + CLI login/logout flow.
- Hosted threat-library endpoints (`/v1/ioc`, `/v1/yara`) with ETag caching.
- CLI threat-library auto-sync with offline fallback.
- Community threat-library GitHub repository with PR validation.
- Free-tier usage metering and rate limiting (50 publishes/month).
- Stripe pay-as-you-go billing for the hosted transparency log.
- Enterprise org model: organisations, owner/admin/member/viewer roles,
  license-key gating in `service/src/skillledger_service/ee/`.
- Org-wide policy distribution and centralised violation event ingestion.
- Per-seat Stripe Subscriptions billing for enterprise.
- SP-initiated SAML SSO with JIT provisioning.
- Next.js 15 + React 19 enterprise dashboard with six feature pages:
  posture, violations, policy editor (Monaco), billing, org management, SSO.
- Production deployment templates: Docker Compose, Railway, Render, VPS
  install script.

### Security
- Post-milestone full codebase security review (22 parallel agents) closed
  41 issues, including 5 blockers (tlog Merkle proofs, Rego injection, IOC
  per-file hashing, GitHub Actions injection, path traversal) and 30+
  critical/important issues (JWT fail-closed, CORS, constant-time
  comparisons, schema hardening, FK cascades, session rollback, hook
  hardening, SHA-pinned GitHub Actions).

---

## [2.0.0] - 2026-04-29

Runtime skill protection — antivirus for AI agent skills.

### Added
- Runtime proxy with HTTP/HTTPS MITM and MCP stdio/WebSocket interception
  across all seven supported agent ecosystems.
- Multi-scanner detection pipeline: secret exfiltration, IOC network
  matching, DNS exfiltration, slow-drip entropy tracking.
- MCP tool pinning with rug-pull detection.
- Prompt-injection scanning (heuristic + DeBERTa ONNX with `--no-ml`
  fallback).
- OPA-based runtime capability enforcement with configurable presets and
  auto-profiling for unmanifested skills.
- Provenance-aware policy with three trust tiers gating runtime permissions
  based on SLSA verification status.
- SARIF + JSON violation reporting compatible with GitHub Code Scanning.
- YARA runtime scanning for custom detection rules.

### Fixed
- Data race in proxy MITM, OOM denial-of-service vector in archive
  collector, empty-checksum acceptance, WebSocket origin check bypass,
  `afero.Fs` abstraction violations (Phase 15.1 critical fixes).

---

## [1.0.0] - 2026-04-19

Supply-chain verification foundation.

### Added
- Universal artifact specification with JSON Schema validation across seven
  ecosystems: Claude Code, MCP, OpenClaw, Anthropic, OpenAI/Codex, OpenCode,
  generic.
- Deterministic content-addressed build with CycloneDX SBOM generation and
  reproducible-build support via `SOURCE_DATE_EPOCH`.
- Sigstore keyless signing with SLSA L3 provenance attestations.
- Tessera-based transparency log with inclusion-proof and consistency-proof
  verification.
- Capability policy DSL with OPA integration and three built-in presets
  (`strict`, `moderate`, `permissive`).
- Install-time verification pipeline: signature, provenance, transparency
  log, policy (fail-closed).
- Hosted FastAPI service with publisher authentication and reusable
  GitHub Actions workflow.
- Pre-install hooks for Claude Code, MCP, npm, OpenClaw ecosystems.

[Unreleased]: https://github.com/skillledger/skillledger/compare/v3.1.0...HEAD
[3.1.0]: https://github.com/skillledger/skillledger/releases/tag/v3.1.0
[3.0.0]: https://github.com/skillledger/skillledger/releases/tag/v3.0.0
[2.0.0]: https://github.com/skillledger/skillledger/releases/tag/v2.0.0
[1.0.0]: https://github.com/skillledger/skillledger/releases/tag/v1.0.0
