# Security Policy

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

SkillLedger is a supply-chain security tool — vulnerabilities here can compromise other organisations' trust pipelines. We take every report seriously and ask that you give us a fair chance to fix issues before they become public knowledge.

### Private disclosure channels

Choose whichever is convenient:

| Channel | Use for |
|---|---|
| **GitHub Private Vulnerability Reporting** ([open a report](https://github.com/skillledger/skillledger/security/advisories/new)) | Preferred. Tracked, encrypted, and integrated with our patch workflow. |
| **Email** — `me@rishikeshranjan.com` | If GHSA is not an option, or for issues affecting hosted infrastructure (`*.skillledger.in`). |

For email reports, please include:

- A description of the vulnerability
- Steps to reproduce (or a proof-of-concept)
- The affected component (`cli/`, `service/`, `dashboard/`, `hooks/`, `log/`, `service/src/skillledger_service/ee/`)
- The affected version(s) (commit SHA or release tag)
- Your assessment of severity / impact
- Whether you have published the issue anywhere or coordinated with another party

If you need an encrypted channel, request a PGP key in your first message and we will provide one.

## What We Consider In-Scope

- Bypassing the verification pipeline (signature, provenance, transparency-log inclusion, policy)
- Forging or substituting artifacts that pass verification
- Tampering with the transparency log (entries, proofs, checkpoint signatures)
- Authentication or authorisation failures in the hosted service (`api.skillledger.in`)
- Privilege escalation in the runtime proxy (capability bypass, secret exfiltration not detected, prompt-injection detection bypass)
- License-key bypass in the Enterprise Edition (`service/src/skillledger_service/ee/`)
- Sensitive data exposure (API keys, JWTs, license keys, SAML assertions)
- Remote code execution, SQL injection, command injection, SSRF, path traversal
- Cryptographic weaknesses (signature scheme misuse, IV reuse, hash truncation)
- Supply-chain attacks against our own builds (dependency tampering, CI compromise)

## Out of Scope

- Vulnerabilities in third-party dependencies that have a published CVE but no SkillLedger-side workaround beyond upgrading (please report upstream)
- Social-engineering, physical-access, or denial-of-service via legitimate API usage
- Self-XSS, missing security headers on non-authenticated endpoints, or theoretical attacks without a working proof-of-concept
- Issues affecting unsupported versions (see below)
- Issues only reachable by running SkillLedger with `--allow-http`, `SKILLLEDGER_ALLOW_HTTP=1`, or other documented insecure development flags

## Supported Versions

We currently support security fixes for the latest minor release line only. Earlier releases will not receive backported patches; please upgrade.

| Version | Supported |
|---|---|
| `v3.1.x` (latest) | Yes |
| `v3.0.x` | Critical fixes only |
| `v2.x` | No |
| `v1.x` | No |

## Response Targets

| Stage | Target |
|---|---|
| Acknowledge receipt | 2 business days |
| Initial triage and severity assessment | 5 business days |
| Patch and coordinated disclosure plan | 30 days (Critical/High), 90 days (Medium/Low) |
| Public advisory + CVE request (if applicable) | After patch ships |

These are targets, not guarantees. We will keep you updated if we miss them.

## Coordinated Disclosure

We follow a 90-day coordinated disclosure window by default. We will:

1. Confirm the issue and agree on a severity rating with you
2. Develop a fix in a private branch
3. Notify enterprise customers in advance where appropriate
4. Release the patch
5. Publish a public advisory (CVE if eligible) crediting you, unless you prefer to remain anonymous

If a vulnerability is already being actively exploited in the wild, we may shorten the window and release an emergency patch.

## Safe Harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy
- Avoid privacy violations, data destruction, and service disruption
- Do not exfiltrate any data beyond what is necessary to demonstrate the vulnerability
- Give us a reasonable chance to fix the issue before public disclosure

## Hall of Fame

We credit reporters in release notes and (with your permission) in a future `THANKS.md`. If you would like to remain anonymous, tell us at first contact.

## Bug Bounty

We do not currently run a paid bug-bounty programme. This may change as the project matures.
