# SkillLedger Community Threat Library

Community-contributed threat intelligence for the SkillLedger supply-chain security toolchain.

## Directory Structure

```
threat-library/
  ioc/
    hashes.json       # SHA-256 hashes of known-malicious artifacts
    domains.json      # Known-malicious domains (C2, exfil, phishing)
  yara/
    rules/            # YARA detection rules (.yar files)
  schema/
    ioc-hash.schema.json    # JSON Schema for hash entries
    ioc-domain.schema.json  # JSON Schema for domain entries
```

## Contributing

All contributions are submitted via GitHub Pull Request. CI validates every submission automatically.

### Adding IOC Hashes

Add an entry to `ioc/hashes.json`. Each entry requires:

| Field | Type | Description |
|-------|------|-------------|
| `sha256` | string | SHA-256 hash (64 lowercase hex characters) |
| `description` | string | Human-readable threat description (1-512 chars) |
| `severity` | enum | One of: `critical`, `high`, `medium`, `low`, `info` |
| `source` | string | Attribution source (1-255 chars) |
| `reported_at` | string | Date reported in `YYYY-MM-DD` format |

Example:

```json
{
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "description": "Known malicious skill package",
  "severity": "critical",
  "source": "your-org-name",
  "reported_at": "2026-05-01"
}
```

### Adding IOC Domains

Add an entry to `ioc/domains.json` with the same fields, replacing `sha256` with:

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Malicious domain name (max 255 chars) |

### Adding YARA Rules

Create a `.yar` file in `yara/rules/`. Each rule file must:

- Contain a valid `rule <name>` declaration
- Include a `condition:` section
- Follow standard YARA syntax

Example:

```yara
rule MaliciousSkillLoader {
    meta:
        description = "Detects malicious skill loader pattern"
        severity = "high"
        author = "your-name"
    strings:
        $suspicious = "eval(atob("
    condition:
        $suspicious
}
```

### Severity Levels

| Level | Use When |
|-------|----------|
| `critical` | Active exploitation, high-impact supply-chain attack |
| `high` | Known malicious, significant risk |
| `medium` | Suspicious activity, moderate risk |
| `low` | Low confidence indicator, minor risk |
| `info` | Informational, no direct threat |

## Validation

CI runs `scripts/validate-threat-library.py` on every PR touching `threat-library/**`. The script checks:

- JSON Schema conformance for all IOC entries
- No duplicate hashes or domains
- Valid severity levels
- YARA rule syntax (structural validation)

Run locally before submitting:

```bash
pip install jsonschema
python3 scripts/validate-threat-library.py
```

## Schema Reference

- [IOC Hash Schema](schema/ioc-hash.schema.json)
- [IOC Domain Schema](schema/ioc-domain.schema.json)
