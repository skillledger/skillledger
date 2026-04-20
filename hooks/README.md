# SkillLedger Pre-Install Hooks

Pre-install verification hooks that invoke `skillledger verify` before skill installation. Each hook checks the artifact's signature, transparency log inclusion, and capability policy compliance -- blocking installation if verification fails.

## Prerequisites

- `skillledger` CLI must be installed and available in your `PATH`
- Install from: https://github.com/skillledger/skillledger

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SKILLLEDGER_POLICY` | `moderate` | Policy preset to evaluate against. Options: `strict`, `moderate`, `permissive`, or path to a custom `.rego` file |
| `SKILLLEDGER_SERVICE_URL` | `http://localhost:8000` | URL of the SkillLedger transparency log service |
| `SKILLLEDGER_SKIP_TLOG` | `false` | Set to `true` to skip transparency log verification (offline mode) |

## Installation

### Claude Code

Copy the hook script to your Claude Code hooks directory:

```bash
cp hooks/claude-code-hook.sh .claude/hooks/pre-install
chmod +x .claude/hooks/pre-install
```

Or configure in your Claude Code settings to run the hook before installing any skill:

```json
{
  "hooks": {
    "pre_install": "./hooks/claude-code-hook.sh ${artifact_path}"
  }
}
```

### MCP (Model Context Protocol) Servers

Configure in your MCP client settings as a pre-install command. The exact configuration depends on your MCP client:

```json
{
  "pre_install": "hooks/mcp-hook.sh ${artifact_path}"
}
```

For Claude Desktop, add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pre_install_hook": "hooks/mcp-hook.sh"
  }
}
```

### npm

Add the hook to your `package.json` scripts:

```json
{
  "scripts": {
    "preinstall": "./hooks/npm-hook.sh ${npm_package_name}"
  }
}
```

Or invoke directly before installing a skill package:

```bash
./hooks/npm-hook.sh path/to/package.tgz && npm install path/to/package.tgz
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Verification passed | Allow installation to proceed |
| `1` | Verification failed | Block installation -- artifact failed signature, transparency log, or policy check |

All hooks propagate the exact exit code from `skillledger verify`. A non-zero exit code means the artifact should NOT be installed.

## Offline Mode

For air-gapped or disconnected environments, set `SKILLLEDGER_SKIP_TLOG=true`:

```bash
export SKILLLEDGER_SKIP_TLOG=true
./hooks/claude-code-hook.sh path/to/artifact
```

In offline mode:
- Signature verification is still enforced
- Policy evaluation is still enforced
- Transparency log inclusion check is skipped

This is useful for environments where the SkillLedger service is not reachable, but you still want signature and policy verification.

## Customization

### Using a Custom Policy

```bash
export SKILLLEDGER_POLICY=strict
./hooks/claude-code-hook.sh path/to/artifact
```

### Pointing to a Hosted Service

```bash
export SKILLLEDGER_SERVICE_URL=https://log.skillledger.dev
./hooks/mcp-hook.sh path/to/artifact
```
