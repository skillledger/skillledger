# SkillLedger — How to Use

This is a practical guide to using SkillLedger. For the full backstory, threat model, and business context, see [project.md](project.md).

## Quick Start

### 1. Audit your installed skills

Scan all installed AI agent skills across every ecosystem and get an SBOM + IOC report:

```bash
skillledger audit
```

This discovers skills in:
- `~/.claude/skills/` (Claude Code)
- MCP server configs (`mcp_servers.json`)
- `~/.openclaw/` (OpenClaw)
- Anthropic, OpenAI, Codex, OpenCode directories

Output: CycloneDX SBOM + IOC matches (known-compromised skills). Supports `--format json` and `--format sarif` for GitHub Code Scanning integration.

Add custom YARA detection rules:
```bash
skillledger audit --yara-rules ./my-rules/
```

### 2. Initialize a skill manifest

Create a `skillledger.yaml` in your skill's source directory:

```bash
cd my-skill/
skillledger init --kind claude-code-skill
```

This generates a manifest describing your skill's identity, version, source, capabilities, and ecosystem profile. Edit it to declare what your skill actually needs:

```yaml
skillledger: 1
id: com.example.my-skill
version: 1.0.0
kind: claude-code-skill
source:
  vcs: git
  repo: https://github.com/example/my-skill
capabilities:
  filesystem:
    read: ["$CWD/**"]
    write: []
  network:
    outbound: []
  secrets: []
  tools: ["git"]
```

Validate it:
```bash
skillledger validate
```

### 3. Build a deterministic artifact

```bash
skillledger build
```

This produces:
- A content-addressed `.skillledger.tar.gz` archive (byte-identical on repeated builds)
- A `skill-lock.json` lockfile with the artifact hash and provenance reference

The build collects source files in sorted order, applies `.skillledgerignore` patterns, normalizes metadata (timestamps, permissions), and produces a canonical tar.gz. Same source = same artifact bytes, every time.

### 4. Sign the artifact

```bash
skillledger sign --artifact dist/my-skill.skillledger.tar.gz --lockfile skill-lock.json
```

This:
- Signs using Sigstore keyless signing (OIDC identity via your GitHub/Google account)
- Generates SLSA L3 provenance attestation linking artifact to source commit
- Records the signature in the Sigstore transparency log
- Produces a `.sigstore.json` bundle

No key management needed — your identity IS the key.

### 5. Publish to the transparency log

```bash
skillledger publish \
  --artifact dist/my-skill.skillledger.tar.gz \
  --lockfile skill-lock.json \
  --service-url https://log.skillledger.dev \
  --api-key $SKILLLEDGER_API_KEY
```

This writes an entry to the append-only Merkle tree. Once published, the entry cannot be modified or deleted — anyone can verify your artifact was published.

### 6. Verify at install time

```bash
skillledger verify \
  --artifact my-skill.skillledger.tar.gz \
  --preset moderate \
  --service-url https://log.skillledger.dev
```

This runs the full verification pipeline:
1. **Signature check** — Is the Sigstore signature valid?
2. **Provenance check** — Does the SLSA attestation link to the claimed source?
3. **Transparency log check** — Is the artifact hash in the log with a valid inclusion proof?
4. **Policy check** — Does the capability manifest comply with the configured policy?

Fail-closed: any failure blocks the install.

### 7. Install pre-install hooks

Automatically verify skills before they're installed in each ecosystem:

```bash
# Install hooks for all ecosystems
hooks/install.sh --ecosystem all

# Or specific ecosystems
hooks/install.sh --ecosystem claude-code
hooks/install.sh --ecosystem mcp
hooks/install.sh --ecosystem openclaw

# Use symlinks instead of copies
hooks/install.sh --ecosystem all --link
```

### 8. Use policy presets

Three built-in presets, no DSL knowledge needed:

```bash
# Strict: no network, no secrets, no shell tools
skillledger verify --preset strict --artifact my-skill.tar.gz

# Moderate: limited network, no secrets (default)
skillledger verify --preset moderate --artifact my-skill.tar.gz

# Permissive: warns but doesn't block
skillledger verify --preset permissive --artifact my-skill.tar.gz
```

### 9. Write custom policies

For enterprises that need fine-grained control:

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
# Compile policy to Rego (for inspection)
skillledger policy compile --file my-policy.yaml

# Check a skill against your policy
skillledger policy check --file my-policy.yaml --artifact my-skill.tar.gz

# List available presets
skillledger policy list
```

## CI/CD Integration

### GitHub Actions (reusable workflow)

```yaml
# .github/workflows/skill-ci.yml
name: Skill CI
on: [push]

jobs:
  build-sign-verify:
    uses: skillledger/skillledger/.github/workflows/skillledger-ci.yml@main
    with:
      skill-dir: ./my-skill
      policy-preset: moderate
    secrets:
      SKILLLEDGER_API_KEY: ${{ secrets.SKILLLEDGER_API_KEY }}
    permissions:
      id-token: write  # Required for Sigstore keyless signing
      contents: read
```

### Individual composite actions

```yaml
# Build only
- uses: skillledger/skillledger/.github/actions/build@main
  with:
    skill-dir: ./my-skill

# Sign only (requires cosign-installer)
- uses: sigstore/cosign-installer@v3
- uses: skillledger/skillledger/.github/actions/sign@main
  with:
    artifact-path: ${{ steps.build.outputs.artifact-path }}

# Verify only
- uses: skillledger/skillledger/.github/actions/verify@main
  with:
    artifact-path: ${{ steps.build.outputs.artifact-path }}
    policy-preset: strict
```

## Self-Hosted Deployment

### Development

```bash
docker compose up -d
# Service at http://localhost:8000
# Log at http://localhost:2025
# Postgres at localhost:5432
```

### Production

```bash
# Set required environment variables
export SKILLLEDGER_DOMAIN=log.skillledger.dev
export SKILLLEDGER_ADMIN_API_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 32)

# Deploy with Caddy TLS
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

This deploys:
- **Caddy** reverse proxy with automatic HTTPS (ports 80/443)
- **skillledger-service** (FastAPI, bound to 127.0.0.1:8000 — only Caddy can reach it)
- **skillledger-log** (Tessera personality, bound to 127.0.0.1:2025)
- **PostgreSQL** (metadata store)

### Publisher Management

```bash
# Create a publisher (requires admin API key)
curl -X POST https://log.skillledger.dev/publishers \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-org", "contact_email": "security@example.com"}'

# Generate an API key for the publisher
curl -X POST https://log.skillledger.dev/publishers/1/keys \
  -H "Authorization: Bearer $ADMIN_API_KEY"
# Returns: {"raw_key": "...", "key_prefix": "...", "publisher_name": "my-org"}
# Save the raw_key — it's shown only once.

# List publishers
curl https://log.skillledger.dev/publishers \
  -H "Authorization: Bearer $ADMIN_API_KEY"
```

## Supported Ecosystems

| Ecosystem | Manifest Kind | Hook |
|-----------|--------------|------|
| Claude Code | `claude-code-skill` | `claude-code-hook.sh` |
| MCP Servers | `mcp-server` | `mcp-hook.sh` |
| OpenClaw | `openclaw-plugin` | `openclaw-hook.sh` |
| Anthropic Skills | `anthropic-skill` | (use generic) |
| OpenAI Tools | `openai-tool` | (use generic) |
| Codex Tools | `codex-tool` | (use generic) |
| OpenCode | `opencode` | (use generic) |
| npm packages | `generic` | `npm-hook.sh` |
| Any other | `generic` | `generic-hook.sh` |

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SKILLLEDGER_API_KEY` | Publisher API key for authenticated publish | (none) |
| `SKILLLEDGER_SERVICE_URL` | Transparency log service URL | `http://localhost:8000` |
| `SKILLLEDGER_POLICY` | Policy preset for verification | `moderate` |
| `SKILLLEDGER_SKIP_TLOG` | Skip transparency log check (offline mode) | `false` |
| `SKILLLEDGER_DATABASE_URL` | Service database connection string | `sqlite+aiosqlite:///./skillledger.db` |
| `SKILLLEDGER_LOG_URL` | Log personality URL (internal) | `http://localhost:2025` |
| `SKILLLEDGER_ADMIN_API_KEY` | Admin bootstrap key for publisher management | (none) |
| `SKILLLEDGER_DOMAIN` | Production domain for Caddy TLS | `log.skillledger.dev` |
