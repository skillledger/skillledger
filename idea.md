# SkillLedger — Reproducible-build and attestation infra for Claude Code skills, MCP servers, and OpenClaw plugins

**Category:** AI dev tools / software deep tech / supply chain security

**Lens used:** 11 (wedge into moat) + 1 (inversion)

**Source signal:** CVE-2026-25253 (CVSS 8.8, disclosed Feb 3 2026); 341 malicious skills / 2,857 total in ClawHub registry (12% compromise); Moltbook breach leaked 1.5M agent API tokens Jan 31 2026; Microsoft Agent Governance Toolkit released April 2 2026 under MIT — covers runtime governance but not the artifact build/provenance layer.

**Problem:** A 6-person SaaS team in Bangalore runs ~40 Claude Code skills and 12 MCP servers across their dev loop. On Feb 4 2026 their security team asked "which of these did we verify?" Answer: none. The team installed `solana-wallet-tracker` from ClawHub in January — one of the 341 compromised skills that dropped Atomic Stealer on two laptops. The team's security engineer now has to manually audit every skill dir every time any developer `npm i`s a new MCP server. They can't block skill installation because developers will route around it, and they can't use Microsoft's AGT because AGT governs runtime behavior, not "was this artifact actually built from the source it claims?"

**Solution:** A deterministic build-and-attestation toolchain purpose-built for agent skill artifacts. Developers `skillledger build` their skill from source → output is a content-addressed artifact with an SLSA-3 provenance attestation, SBOM, tool-boundary manifest (declared filesystem/network/secret access), and Ed25519 signature rooted in a Sigstore-style transparency log. Enterprise installs `skillledger verify` as a pre-install hook — installs fail if the artifact isn't in the transparency log or declares capabilities beyond what the installer's policy permits. Core IP: the **skill artifact spec** (canonical serialization of Claude Code skill, MCP server config, OpenClaw plugin manifest into a single reproducibly-buildable format) and the **capability manifest language** that lets enterprises write policies like "no skill from this vendor may read `~/.ssh`."

**Why now:** Three things converged in 60 days. (1) OpenClaw/ClawHub's supply-chain attack is the first at-scale agent-skill compromise — the playbook is public. (2) Microsoft's AGT legitimized runtime governance but explicitly doesn't define a skill-artifact build format. (3) Sigstore, SLSA, and npm provenance have all matured to the point where the hard crypto pieces are commodities — a small team doesn't build them, they compose them. 5 years ago Sigstore didn't exist, SLSA was a Google whitepaper, and there was no agent skill ecosystem to protect.

**Wedge:** 3-month plan. Month 1: ship `skillledger audit` — a free CLI that scans a developer's `~/.claude-code/skills/`, `~/.openclaw/`, and `mcp_servers.json`, flags anything not signed, matches against a self-hosted mirror of ClawHub's known-compromised list, and outputs an SBOM. Ship it to the Claude Code and MCP Discord/Slack communities — distribution via the OpenClaw/MCP security subreddits which have been on high alert since Feb 3. Month 2: publish the artifact spec v0.1 and a reproducible build mode for any skill defined as a TypeScript/Python/Bash source tree. Month 3: onboard 10 paying design partners — Indian SaaS companies with security-conscious CTOs (Rishi's existing ngram network + Bangalore CISO community). Price: $500/developer/month for the hosted transparency log + policy engine.

**Why this is non-obvious:** Everyone reading the OpenClaw disclosure is building runtime agent sandboxes (the MS AGT approach). The inversion is that *runtime sandboxing cannot detect a supply-chain substitution attack* — by the time the skill runs, the swap has already happened. The real problem is build provenance, and nobody in the AI tooling stack has ported the Sigstore/SLSA pattern into the skill-artifact format. The dominant assumption is "runtime is where you catch it"; the truth is "runtime is too late."

**Existing players:**
- **Microsoft Agent Governance Toolkit** (Apr 2 2026, MIT) — runtime policy engine, not a build/provenance layer. Complementary, not competitive. Can sit upstream of AGT.
- **Chalk** (open-source attestation engine, GA announced late 2025) — general-purpose SLSA attestation, not tailored to agent skills, no capability manifest language, no transparency log product.
- **SlowMist MCP-Security-Checklist** (GitHub) — a static checklist PDF, not a tool.
- **AI Skills Store** (aiskillstore.com) — community marketplace with "security checks" that are opaque repo-quality scans, not cryptographic signing.
- **Sigstore / SLSA** — upstream infra. SkillLedger composes them; doesn't reinvent.
- **OpenClaw itself** will eventually fix its own registry — but that only covers OpenClaw, not Claude Code skills or MCP servers. Enterprises want one tool across all three ecosystems.

The space is **emerging, not crowded**. The OpenClaw crisis is 10 weeks old; MS AGT is 13 days old. First-mover on the artifact-spec position is real because once a spec has momentum it calcifies.

**Economics:**
- *Rough TAM:* ~300K developers actively using Claude Code + MCP + OpenClaw in enterprises today per YC W26 data and Claude Code adoption curves. At $500/dev/month = $1.8B TAM ceiling, realistic SAM ~$200M (security-conscious enterprises only).
- *Revenue model:* Seat-based SaaS ($500/dev/mo) for the policy engine + transparency log; free CLI for audit; paid artifact repo tier for organizations mirroring internal skills ($2K/month per team).
- *Initial investment to wedge:* <$30K. Sigstore/SLSA are free; a transparency log is a Merkle-tree server on ~$200/month Hetzner; the CLI is a weekend of Go. Biggest cost is 3 months of Rishi's time.
- *Success probability:* Medium-High — the pain is fresh, Rishi is already in the Claude Code skills ecosystem (his context.md mentions OpenClaw, Tool Integrations), and distribution channels (Discords, HN, security Twitter) respond to a working CLI. The downside: Anthropic or OpenClaw could make their own signing mandatory, absorbing the opportunity — but even then, the cross-ecosystem policy engine layer survives.

**Getting started (this week):**
1. Fork and study the OpenClaw CVE-2026-25253 patch commit + the ClawHub malicious-skills IOC list to understand the attack surface precisely. Also read Anthropic's Claude Code skill spec and the MCP server spec line-by-line.
2. Spend two nights writing `skillledger audit` as a Go CLI that scans the three directory layouts and produces an SBOM in CycloneDX. Post a demo GIF to HN ("Show HN: Audit your Claude Code skills for the OpenClaw-style supply-chain attack") — this is the distribution wedge.
3. DM five of the 24 DLI-selected chip design startups in Bangalore (found via PIB / ISM site) + five Bangalore SaaS CTOs Rishi knows through ngram's growth community. Ask: "after OpenClaw, how are you auditing your agent skills?" — this is customer discovery, not a pitch.
4. Draft the artifact spec v0.1 as a public GitHub repo with explicit comparison to npm provenance and Python PEP 740. Invite feedback from the Sigstore maintainers (Luke Hinds, Dan Lorenc).
5. Prototype the transparency log in a weekend using Trillian (Google's Merkle-tree lib) — reuse, don't rebuild.

### Deep dive on Idea 1

**Expanded threat model.** The OpenClaw attack chain (Jan 27-29 2026) was instructive because it had three sequential weaknesses, not one:

1. *Registry trust.* ClawHub accepted skill submissions without requiring a verifiable link between the published tarball and its source repository. An attacker could publish `solana-wallet-tracker` without any proof that the code on GitHub matched the tarball on ClawHub.
2. *Install-time trust.* The OpenClaw client happily installed skills by name without checking signatures because none existed in the spec.
3. *Runtime trust.* Once installed, skills ran with the full capability of the user's shell — no sandbox declared which filesystem paths, env vars, or network endpoints the skill was allowed to touch.

Microsoft's AGT (Apr 2 2026) attacks weakness #3 — runtime isolation, policy enforcement, goal-hijacking detection. SkillLedger attacks #1 and #2, which are structurally upstream: if you can catch a supply-chain substitution at install time, you never need runtime policy to adjudicate it. Both are needed. The defensibility argument is that AGT does not own the artifact-format layer and Microsoft's incentive is to push AGT as a runtime-agnostic toolkit, not to define a cross-vendor skill spec (which would cannibalize Azure's agent platform ambitions).

**Proposed artifact format (v0.1 sketch).** A `skillledger.yaml` at the root of any skill source tree:

```yaml
skillledger: 1
id: com.rishiclaw.git-smart-commit
version: 0.4.2
kind: claude-code-skill   # or mcp-server, openclaw-plugin, anthropic-skill
source:
  vcs: git
  repo: https://github.com/rishiclaw/git-smart-commit
  commit: 4f9a2b1...  # exact commit hash
  path: /skills/git-smart-commit
build:
  reproducible: true
  toolchain: node@20.15.0, typescript@5.4.3
  entrypoint: dist/index.js
  sbom: sbom.cyclonedx.json
capabilities:
  filesystem:
    read: ["$CWD/**", "$HOME/.config/git/**"]
    write: ["$CWD/.git/**"]
  network:
    outbound: []   # none
  secrets: []
  tools: ["git"]
attestation:
  builder: sigstore-cosign
  provenance: slsa-3
  transparency_log: https://log.skillledger.dev
```

The install-time CLI verifies: (1) the Sigstore signature against the bundled cert chain, (2) the SHA256 of the artifact matches the transparency-log entry, (3) the capability manifest does not exceed the installer's local policy. Violations fail closed.

**Capability manifest language.** Inspired by WebAssembly Component Model's capability approach and Android's permission declarations, but designed for LLM agents. Example local policy for a cautious enterprise:

```yaml
skillledger-policy: 1
deny:
  - capabilities.filesystem.read: contains("/.ssh/")
  - capabilities.filesystem.read: contains("/.aws/")
  - capabilities.filesystem.write: contains("$HOME")
  - capabilities.network.outbound: any
    except: ["api.anthropic.com", "api.openai.com"]
  - capabilities.secrets: any
allowlist-publishers:
  - cert-identity: "https://github.com/anthropic/*"
  - cert-identity: "https://github.com/modelcontextprotocol/*"
  - cert-identity: "https://github.com/<org>/*"
warn:
  - capabilities.tools: contains("sh")
  - capabilities.tools: contains("exec")
```

This is the IP. Nobody has articulated a capability surface specifically tuned to what agent skills actually do: file-scope reads, shell tool invocations, outbound HTTP, env var access, secret reads. Sigstore/SLSA handle the cryptography; what they don't do is give you a domain-specific vocabulary for "this skill reads git metadata only."

**Architecture (composed, not invented).**
- Signing and build provenance: Cosign (Sigstore). Open-source.
- Transparency log: Trillian (Google). Open-source.
- SBOM format: CycloneDX. Open-source standard.
- Reproducible build layer: Nix-lite or Buildpacks for common skill toolchains (Node, Python, Go). The skill spec locks the toolchain.
- Capability manifest: SkillLedger's own spec (the IP).
- Policy engine: OPA (Open Policy Agent) with SkillLedger's capability-DSL compiler to Rego.
- Install-time CLI: Go binary distributed via Homebrew, scoop, and `curl | sh`.
- Hosted service: Python FastAPI (familiar to Rishi) + Postgres. Trillian runs as a sidecar.

Rishi writes roughly three things: the artifact spec, the capability-DSL-to-Rego compiler, and the verification CLI. Everything else is off-the-shelf.

**Detailed 90-day roadmap.**

*Days 1-10:*
- Write `skillledger audit` CLI (Go). Scans `~/.claude/skills/`, `~/.openclaw/`, and any MCP config. Outputs CycloneDX SBOM + a list of skills matching known-bad IOCs from ClawHub's post-breach disclosure.
- Land a Show HN post: "Audit your Claude Code skills for supply-chain compromise — a free CLI, post-OpenClaw."
- Target: 500 GitHub stars, 50 installs in week one.

*Days 11-30:*
- Publish artifact spec v0.1 in a public `skillledger/spec` repo. Open RFCs for 30 days.
- Write reference implementation of `skillledger build` that consumes a skill source tree and produces a signed, reproducible artifact.
- Schedule 10 customer-discovery calls: 5 Bangalore SaaS CTOs (ngram network), 3 Anthropic employees (via public forums), 2 OpenClaw maintainers.
- Write a comparative blog: "Why npm provenance and PEP 740 don't fit AI agent skills."

*Days 31-60:*
- Ship hosted transparency log at `log.skillledger.dev` on Hetzner (€20/month).
- Implement capability-DSL compiler (DSL → Rego).
- Onboard first 3 design partners under a pilot: free for 3 months in exchange for case studies.
- Submit a talk proposal to KubeCon + CloudNativeCon Europe 2026 ("Supply Chain for Agent Skills — Lessons from the OpenClaw Breach").

*Days 61-90:*
- Launch paid tier: $500/developer/month, billed annually in INR or USD.
- Target: 5 paying teams, $2.5K-$15K MRR.
- Begin conversations with Sigstore steering committee about upstreaming the capability manifest format as a Sigstore attestation predicate.

**Distribution channels, ranked by fit.**
1. Hacker News — a working CLI that scans for the OpenClaw IOCs has news value for 48h. Frontpage = 10K installs.
2. Claude Code official Discord (~50K users), OpenClaw Discord, MCP community Slack — these audiences are already anxious about skill trust.
3. Security Twitter / Mastodon — tag @DanLorenc, @lukehinds, @mattifestation. If Sigstore's maintainers cite it, credibility cascades.
4. India CISO WhatsApp groups (ngram's network) — $500/dev/month is sellable to Indian security-conscious enterprises where headcount is cheap but liability is catching up (DPDP Act enforcement).
5. Anthropic's developer relations — if SkillLedger becomes the reference tool for Claude Code skill supply-chain audit, Anthropic may link to it from docs (which would be terminal velocity).
6. ISO 27001 / SOC 2 auditors — once one auditor includes "agent skill supply-chain controls" in their checklist, every enterprise needs a tool.

**Business model options, ranked.**
- *Seat-based SaaS ($500/dev/mo)* — default. Predictable, compounds.
- *Usage-based (per verification)* — harder to price, lower LTV.
- *Open core* — CLI free, hosted transparency log + policy engine paid.
- *Acquisition fit* — 24-36 months out, a natural acqui-sell to Sigstore's commercial sponsor (Chainguard), GitHub Advanced Security, or Anthropic directly. The company's core IP — the capability manifest language — is exactly what Anthropic would want to OWN for Claude Code long-term.

**Why Rishi specifically wins this.**
- Already ships Claude Code skills, OpenClaw, and MCP servers (per `context.md`). Is user-zero.
- FastAPI + Python + TypeScript map to every component.
- ngram's growth network gives warm intros to Bangalore CTOs — the highest-ACV early customers.
- India is underweight in supply-chain security mindshare but DPDP Act + RBI MFA mandates are waking up enterprises fast; timing aligns with Indian buyer urgency.
- Small-team wedge fits the <$100K constraint — this is a solo-founder product for 6-9 months before needing a hire.

**Risk table.**

| Risk | Probability | Mitigation |
|------|-------------|------------|
| Anthropic ships native signing in Claude Code skills | Medium | Position as the cross-vendor tool (Claude + OpenAI + OpenClaw + MCP). Anthropic signing covers one ecosystem. |
| Microsoft AGT expands to include build-provenance | Medium-High | Ship faster, open-spec position, be the reference impl before MS adds it. Or be acquired by MS if they'd rather buy. |
| Sigstore adds a "skill-attestation" predicate directly | Low-Medium | Contribute it and own the spec editorship. Makes SkillLedger the canonical implementation. |
| Enterprises decide "we'll just audit manually" | High near-term | Land the first 3 paying customers with regulatory-driven demand (DPDP, SOC 2 Type II audits). Once one auditor cites it, others follow. |
| OpenClaw fixes its own registry and the crisis feeling fades | Medium | The NEXT supply-chain attack will happen within 12 months — this is an evergreen category once the spec exists. Also the Claude Code skill ecosystem is larger than OpenClaw. |
| Developers resist install-time friction | Medium | Default-warn instead of default-fail. Use a "paved road" approach — if you install signed skills, everything is faster. |

**Unit economics (rough).**
- CAC: low. Distribution is content + Discord presence. Assume $200/customer through month 6, $500/customer later.
- ACV: $18K/year for a 3-developer team, $180K for 30 developers.
- Gross margin: ~85% (SaaS, low infra cost until scale).
- Payback: <3 months at $500/dev/mo.
- LTV/CAC: 20x+ at current assumptions.

**Expansion ladder (years 2-3).**
1. Add runtime hooks that integrate with Microsoft AGT, LangChain callbacks, and Claude Code's own hook system — now you cover install AND runtime.
2. Add "publisher reputation" — track which publishers have published skills that later got flagged, build a trust graph.
3. Expand from skills to full agent bundles (skills + prompts + tools + model configs) — the whole agent-config supply chain.
4. License the capability manifest format to enterprises that want to impose their own internal policies across any tool (VSCode extensions, Slack apps, Zapier integrations) — the real moat is the policy language.

**Partnership angles.**
- Sigstore (Chainguard) — upstream the attestation predicate, become the canonical implementer.
- Anthropic — if Claude Code docs link to SkillLedger as the recommended audit tool, pre-launch acquisition conversation possible.
- DPIIT / CERT-In — India CERT could recommend it for government agent-skill deployments. Status-based moat.
- OpenClaw — direct integration into ClawHub; offer as the default verification.
- Cloud Native Computing Foundation (CNCF) — donate the spec, get it adopted as a cross-cloud standard.

---
