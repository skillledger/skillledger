# SkillLedger Artifact Spec v0.1

A deterministic build-and-attestation format for AI agent skill artifacts. This spec defines the universal `skillledger.yaml` manifest that canonically represents skills across all supported ecosystems.

## Core Fields

Every `skillledger.yaml` manifest must include these core fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `skillledger` | integer | Yes | Spec version marker. Must be `1` for v0.1. |
| `id` | string | Yes | Reverse-domain-style identifier (e.g., `com.example.my-skill`). Pattern: `^[a-z0-9]+(\.[a-z0-9-]+)*$` |
| `version` | string | Yes | SemVer version string (e.g., `"1.0.0"`). Must be quoted in YAML to avoid type coercion. |
| `kind` | string | Yes | Ecosystem type. One of the 8 supported kinds (see below). |
| `source` | object | Yes | Git repository reference (`repository`, `ref`, `directory`). |
| `build` | object | No | Build configuration (`command`, `env`, `reproducible`). |
| `capabilities` | object | Yes | Permission declarations. Undeclared capabilities are denied. |
| `attestation` | object | No | Signing and provenance metadata (`signed_by`, `transparency_log`, `provenance`). |
| `profile` | object | No | Ecosystem-specific fields. Schema varies by `kind`. |

## Capability Categories

Capabilities use a category + scope granularity model. Each category accepts an array of scoped permission strings. **Undeclared capabilities default to denied (fail-closed).**

| Category | Scope Pattern | Examples |
|----------|--------------|----------|
| `filesystem` | `read` / `write[:path]` | `read`, `write:./data`, `write:/tmp` |
| `network` | `outbound[:host]` / `inbound[:port]` | `outbound:*.openai.com`, `inbound:8080` |
| `secrets` | `env[:name]` / `file[:path]` / `vault[:key]` | `env:API_KEY`, `file:/etc/secret`, `vault:db-password` |
| `tools` | `execute[:command]` | `execute:bash`, `execute:python`, `execute:node` |

Unknown capability categories are rejected (`additionalProperties: false`).

## Ecosystem Kinds

SkillLedger v0.1 ships with profile schemas for 8 ecosystem kinds:

| Kind | Ecosystem | Key Profile Fields |
|------|-----------|--------------------|
| `claude-code-skill` | Claude Code | `skill_name`, `triggers`, `load_behavior` |
| `mcp-server` | Model Context Protocol | `transport`, `command`, `args`, `env_vars` |
| `openclaw-plugin` | OpenClaw | `config_schema`, `provider_auth_env_vars`, `channel_env_vars` |
| `anthropic-skill` | Anthropic Platform | `skill_name`, `description`, `triggers` |
| `openai-tool` | OpenAI | `function_name`, `api_spec` |
| `codex-tool` | OpenAI Codex | `display_name`, `category`, `mcp_servers` |
| `opencode` | OpenCode | `plugin_type`, `tools`, `agents` |
| `generic` | Any / Future | `runtime`, `entrypoint` |

## Core-Plus-Profiles Architecture

The manifest uses a **core-plus-profiles** design:

- **Core fields** are strict: unknown top-level fields are rejected via `unevaluatedProperties: false` in JSON Schema draft-2020-12.
- **Profile fields** are forward-compatible: unknown fields within the `profile` object are allowed (`additionalProperties: true`), enabling ecosystem evolution without spec changes.
- The `kind` field acts as a discriminator: an `allOf` with `if/then` blocks dispatches validation to the appropriate profile schema based on the `kind` value.

## Canonical Serialization

For content-addressed operations (signing, verification, transparency log entries), manifests are serialized using **Normalized JSON per RFC 8785 (JSON Canonicalization Scheme)**:

- Sorted keys (lexicographic Unicode code point order)
- No insignificant whitespace
- UTF-8 NFC normalization
- Deterministic number formatting

This produces a single canonical byte sequence for any given manifest, regardless of the original YAML formatting.

## Schema URIs

All schemas are published under `https://skillledger.dev/schemas/v0.1/`:

- `core.schema.json` -- Main manifest schema
- `capabilities.schema.json` -- Capability declarations
- `profiles/{kind}.schema.json` -- Per-ecosystem profile schemas

Schemas use JSON Schema draft-2020-12.

## Design Principles

1. **Fail-closed**: Undeclared capabilities are denied. If a skill doesn't declare `network` access, it gets none.
2. **Content-addressed**: Canonical serialization enables deterministic hashing for signing and verification.
3. **Ecosystem-agnostic core**: The same core fields work across all agent ecosystems. Ecosystem differences live in `profile`.
4. **Forward-compatible profiles**: New profile fields can be added without breaking existing validators.
5. **Human-readable**: YAML manifests are git-diffable and easy to author by hand.
