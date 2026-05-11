<div align="center">

# SkillLedger

**Supply-chain security for AI agent skills — build, sign, verify, and runtime-protect skills across every major agent ecosystem.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![EE License: ELv2](https://img.shields.io/badge/EE-Elastic%202.0-005571.svg)](service/src/skillledger_service/ee/LICENSE)
[![CI](https://github.com/skillledger/skillledger/actions/workflows/skillledger-ci.yml/badge.svg)](https://github.com/skillledger/skillledger/actions/workflows/skillledger-ci.yml)
[![npm](https://img.shields.io/npm/v/skillledger.svg)](https://www.npmjs.com/package/skillledger)
[![GitHub stars](https://img.shields.io/github/stars/skillledger/skillledger?style=social)](https://github.com/skillledger/skillledger/stargazers)

</div>

---

## What is SkillLedger?

SkillLedger is an open-source toolchain that lets developers build AI agent skills into **content-addressed, signed artifacts** with [SLSA L3](https://slsa.dev/) provenance, and lets anyone verify those artifacts at install time against a public transparency log and a capability policy. A runtime proxy then intercepts every skill's network and tool I/O to catch secret exfiltration, prompt injection, and capability escalation while the skill is actually running.

It works across **every major agent ecosystem** — Claude Code skills, MCP servers, OpenClaw plugins, Anthropic skills, OpenAI/Codex tools, OpenCode, and any future format via the universal artifact spec.

**Why it matters:** [CVE-2026-25253](https://nvd.nist.gov/) (CVSS 8.8, Feb 2026) showed that 341 of 2,857 skills on ClawHub had been silently swapped with stealer malware. The attack exploited three gaps — no registry-to-source verification, no install-time signatures, no runtime capability bounds. SkillLedger closes all three.

---

## Demo & Screenshots

_Coming soon — short demo video showing `skillledger audit`, `skillledger build → sign → verify`, and the runtime proxy catching a prompt-injection attempt._

---

## Features

- **Install-time verification** — Sigstore keyless signing, SLSA L3 provenance, Tessera transparency log, OPA-backed capability policy. Fail-closed by default.
- **Runtime proxy** — HTTP/HTTPS MITM + MCP stdio/WebSocket interception. Catches secret exfil, prompt injection (DeBERTa ONNX), DNS exfiltration, IOC network calls, capability escalation, MCP tool rug-pulls, and YARA-rule matches as they happen.
- **Universal artifact spec** — One JSON-Schema-validated format covers 7 agent ecosystems with per-ecosystem profiles.
- **Deterministic builds** — Byte-identical artifacts from the same source tree, with reproducible CycloneDX SBOMs.
- **Provenance-aware policy** — Three trust tiers gate runtime permissions based on SLSA verification status.
- **Auto-syncing threat library** — Community-curated IOC hashes, IOC domains, and YARA rules, refreshed every CLI run.
- **SARIF reporting** — Drop-in compatibility with GitHub Code Scanning, Defender for DevOps, and any SARIF consumer.
- **Three policy presets** — `strict`, `moderate`, `permissive`. Custom policies via a small DSL that compiles to Rego.
- **Pre-install hooks** — Verify automatically when installing skills via Claude Code, MCP, npm, or OpenClaw.
- **Self-hostable** — Single Docker Compose command spins up the full stack with automatic TLS via Caddy.
- **Enterprise edition** — Org model, per-seat billing, SSO/SAML, org-wide policy distribution, centralised violation dashboard. (ELv2-licensed.)

---

## Tech Stack

| Layer | Technology |
|---|---|
| CLI | Go 1.26, Cobra, sigstore-go, Tessera, OPA (embedded), CycloneDX, YARA, DeBERTa ONNX |
| Service | Python 3.12, FastAPI, SQLAlchemy 2.0 async, Pydantic v2, Alembic, asyncpg |
| Dashboard | Next.js 15, React 19, TypeScript, Tailwind v4, shadcn/ui, TanStack Query, Auth.js |
| Storage | PostgreSQL 16 |
| Transport | Caddy 2 (TLS), Docker Compose |
| CI | GitHub Actions (reusable workflows), GoReleaser, npm |
| Distribution | `npx skillledger` (cross-compiled platform-specific binaries) |

---

## Quick Start

The fastest path: no Go toolchain, no Docker, no setup.

```bash
# Run any command directly
npx skillledger@latest audit
npx skillledger@latest --help
```

Audit every AI skill installed on your machine across all seven supported ecosystems and get a CycloneDX SBOM plus IOC matches:

```bash
npx skillledger@latest audit --format sarif > audit.sarif
```

---

## Prerequisites

For end users:

- **Node.js 18+** to run `npx skillledger`
- A GitHub or Google account if you plan to **sign** artifacts (Sigstore keyless OIDC)

For contributors / self-hosters:

- **Go 1.26+** to build the CLI from source
- **Docker + Compose v2** to run the transparency log + service stack
- **Python 3.12+** to hack on the service outside Docker
- **Node 20+** for the dashboard

---

## Installation

### Option 1 — `npx` (recommended)

```bash
npx skillledger@latest <command>
```

### Option 2 — npm global install

```bash
npm install -g skillledger
skillledger --help
```

### Option 3 — Build from source

```bash
git clone https://github.com/skillledger/skillledger.git
cd skillledger/cli
go build -o skillledger ./cmd/skillledger
sudo mv skillledger /usr/local/bin/
skillledger --help
```

---

## Configuration

Every variable the project reads is documented in [`.env.example`](.env.example). For local dev, copy it and fill in the blanks:

```bash
cp .env.example .env
cp dashboard/.env.local.example dashboard/.env.local
```

The most important variables:

| Variable | Required for | Generate / get from |
|---|---|---|
| `POSTGRES_PASSWORD` | service stack | `openssl rand -base64 32` |
| `SKILLLEDGER_ADMIN_API_KEY` | publisher management | `openssl rand -base64 32` |
| `SKILLLEDGER_JWT_SECRET` | user auth | `openssl rand -base64 32` |
| `AUTH_SECRET` | dashboard sessions | `openssl rand -base64 32` |
| `LOG_PRIVATE_KEY` | transparency log | `openssl genpkey -algorithm Ed25519 -outform DER \| base64` |
| `SKILLLEDGER_RESEND_API_KEY` | OTP email delivery | [resend.com](https://resend.com) |
| `SKILLLEDGER_STRIPE_SECRET_KEY` | billing (optional) | [stripe.com dashboard](https://dashboard.stripe.com) |
| `SKILLLEDGER_EE_LICENSE_KEY` | Enterprise routers (optional) | me@rishikeshranjan.com |

See [`.env.example`](.env.example) for the full annotated list.

---

## Usage

### Audit installed skills

```bash
skillledger audit                    # human-readable table
skillledger audit --format sarif     # SARIF for GitHub Code Scanning
skillledger audit --yara-rules ./my-rules/
```

Scans `~/.claude/skills/`, MCP server configs, `~/.openclaw/`, Anthropic, OpenAI/Codex, and OpenCode directories. Generates a CycloneDX SBOM and matches each skill against the bundled and live threat library.

### Build → sign → publish → verify

```bash
# In your skill's source directory
skillledger init --kind claude-code-skill
skillledger validate

skillledger build
# -> dist/my-skill.skillledger.tar.gz   (content-addressed, deterministic)
# -> skill-lock.json

skillledger sign --artifact dist/my-skill.skillledger.tar.gz --lockfile skill-lock.json
# -> .sigstore.json bundle (keyless OIDC, SLSA L3 attestation)

skillledger publish \
  --artifact dist/my-skill.skillledger.tar.gz \
  --lockfile skill-lock.json \
  --service-url https://api.skillledger.in \
  --api-key $SKILLLEDGER_API_KEY

skillledger verify \
  --artifact my-skill.skillledger.tar.gz \
  --preset moderate \
  --service-url https://api.skillledger.in
```

### Runtime proxy

Start the proxy, then run any agent through it:

```bash
skillledger proxy start --preset moderate --report violations.sarif
# Proxy listens on localhost:8888 by default
```

The proxy intercepts every outbound HTTPS call, every MCP tool invocation, and every stdio message; checks them against the active policy + threat library + YARA rules; and writes violations to `violations.sarif`.

### Custom policy

```yaml
# my-policy.yaml
skillledger-policy: 1
deny:
  - capabilities.filesystem.read: contains("/.ssh/")
  - capabilities.filesystem.read: contains("/.aws/")
  - capabilities.network.outbound: any
    except: ["api.anthropic.com"]
  - capabilities.secrets: any
allowlist-publishers:
  - cert-identity: "https://github.com/anthropic/*"
warn:
  - capabilities.tools: contains("sh")
```

```bash
skillledger policy compile --file my-policy.yaml
skillledger policy check --file my-policy.yaml --artifact my-skill.tar.gz
skillledger policy list
```

### Pre-install hooks

```bash
hooks/install.sh --ecosystem all          # Claude Code, MCP, npm, OpenClaw
hooks/install.sh --ecosystem claude-code  # Just one
hooks/install.sh --ecosystem all --link   # Symlinks instead of copies
```

After installation, every new skill is verified automatically before it is allowed to load.

---

## Supported Ecosystems

| Ecosystem | Manifest Kind | Hook |
|---|---|---|
| Claude Code | `claude-code-skill` | `claude-code-hook.sh` |
| MCP Servers | `mcp-server` | `mcp-hook.sh` |
| OpenClaw | `openclaw-plugin` | `openclaw-hook.sh` |
| Anthropic Skills | `anthropic-skill` | generic |
| OpenAI Tools | `openai-tool` | generic |
| Codex Tools | `codex-tool` | generic |
| OpenCode | `opencode` | generic |
| npm packages | `generic` | `npm-hook.sh` |
| Anything else | `generic` | `generic-hook.sh` |

---

## Deployment

### Self-host on a single VPS (recommended, ~$5/mo)

The cheapest production setup is a single small VPS running everything in Docker Compose behind Caddy. Tested on Hetzner CX22, Contabo VPS S, DigitalOcean basic droplet, and Hostinger KVM 1.

```bash
git clone https://github.com/skillledger/skillledger.git
cd skillledger

# Point DNS:
#   api.skillledger.in  A  <your-server-ip>
#   app.skillledger.in  A  <your-server-ip>

cp .env.example .env
# Edit .env with real values; minimum: POSTGRES_PASSWORD,
# SKILLLEDGER_ADMIN_API_KEY, SKILLLEDGER_JWT_SECRET, AUTH_SECRET,
# LOG_PRIVATE_KEY, SKILLLEDGER_DOMAIN=api.skillledger.in,
# DASHBOARD_DOMAIN=app.skillledger.in

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Caddy provisions Let's Encrypt certificates on first HTTP request to each domain. There is nothing else to configure.

A one-shot installer is also available:

```bash
curl -fsSL https://raw.githubusercontent.com/skillledger/skillledger/main/deploy/install.sh | bash
```

### One-click deploy

| Platform | Button | Notes |
|---|---|---|
| Railway | [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/skillledger/skillledger) | Single click, $5+/mo |
| Render | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/skillledger/skillledger) | Uses `render.yaml`, $7+/mo |
| Docker Compose | (manual) | Cheapest, full control |

### CI/CD: reusable GitHub Actions workflow

```yaml
jobs:
  build-sign-verify:
    uses: skillledger/skillledger/.github/workflows/skillledger-ci.yml@main
    with:
      skill-dir: ./my-skill
      policy-preset: moderate
    secrets:
      SKILLLEDGER_API_KEY: ${{ secrets.SKILLLEDGER_API_KEY }}
    permissions:
      id-token: write     # Sigstore keyless signing
      contents: read
```

Individual composite actions are available at `skillledger/skillledger/.github/actions/{build,sign,verify}@main`.

---

## Contributing

We welcome contributions of every size — typo fixes, new ecosystem adapters, threat-library entries, performance work, and anything in between. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

If you are not sure where to start, open a [Discussion](https://github.com/skillledger/skillledger/discussions).

---

## Licensing

SkillLedger uses a dual licence:

- **MIT License** ([LICENSE](LICENSE)) for everything except the Enterprise Edition.
- **Elastic License 2.0** ([service/src/skillledger_service/ee/LICENSE](service/src/skillledger_service/ee/LICENSE)) for code under `service/src/skillledger_service/ee/`. This covers org management, per-seat billing, SSO/SAML, and org-wide policy distribution.

You can self-host and use everything for free, including the EE code, subject to the three ELv2 limitations (no managed-service resale, no license-key tampering, no notice removal). Contact `me@rishikeshranjan.com` for a commercial licence outside ELv2 terms.

---

## Support

- **Bug reports & feature requests:** [GitHub Issues](https://github.com/skillledger/skillledger/issues)
- **Questions & discussion:** [GitHub Discussions](https://github.com/skillledger/skillledger/discussions)
- **Security disclosures:** see [SECURITY.md](SECURITY.md) — `me@rishikeshranjan.com`
- **Enterprise enquiries:** `me@rishikeshranjan.com`

---

<div align="center">

Built by [Rishikesh Ranjan](https://github.com/ranjanrishikesh) and contributors.

</div>
