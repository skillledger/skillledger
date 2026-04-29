# skillledger

Supply-chain security toolchain for AI agent skills.

SkillLedger lets developers build skills from source into content-addressed,
signed artifacts with SLSA-3 provenance, and lets enterprises verify those
artifacts at install time against a transparency log and capability policy.

## Installation

```bash
npm install -g skillledger
```

## Usage

```bash
# Audit installed skills
skillledger audit

# Build a skill artifact
skillledger build

# Sign with Sigstore
skillledger sign

# Publish to transparency log
skillledger publish

# Verify at install time
skillledger verify
```

## Troubleshooting

If the binary was not installed (common when optionalDependencies are disabled):

```bash
npx skillledger --force-install
```

Or reinstall with optional dependencies enabled:

```bash
npm install -g skillledger --include=optional
```

## Supported Platforms

- macOS arm64 (Apple Silicon)
- macOS x64 (Intel)
- Linux x64
- Linux arm64
- Windows x64

## Links

- [GitHub](https://github.com/skillledger/skillledger)
- [Documentation](https://github.com/skillledger/skillledger#readme)
