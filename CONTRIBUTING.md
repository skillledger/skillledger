# Contributing to SkillLedger

Thanks for taking the time to contribute. SkillLedger is a supply-chain
security tool used by other organisations; we hold every change to a
high bar for safety and reproducibility. This document explains how to
set up your environment, the workflow we expect, and how to file a
useful issue or pull request.

If something is unclear, open a [Discussion](https://github.com/skillledger/skillledger/discussions)
before sinking time into code.

---

## Code of Conduct

This project adopts the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating, you agree to abide by its terms. Report unacceptable
behaviour to **me@rishikeshranjan.com**.

---

## Reporting Security Issues

**Do not file public issues for security vulnerabilities.** Follow the
private disclosure process in [SECURITY.md](SECURITY.md).

---

## What You Can Contribute

Good first contributions:

- Documentation fixes, clarifications, typos
- Threat-library additions: IOC hashes, IOC domains, YARA rules
  (`threat-library/`)
- New ecosystem adapters (Bedrock skills, AutoGen tools, etc.)
- Test coverage for existing behaviour
- Bug fixes referenced in an open issue

Larger work (architecture changes, new commands, new endpoints) should
start with a Discussion or an Issue tagged `proposal` so we can align
on scope before you write code.

---

## Repository Layout

```
cli/                   Go CLI binary (skillledger)
log/                   Tessera transparency-log personality (Go)
service/               FastAPI hosted service (Python)
service/src/skillledger_service/ee/
                       Enterprise Edition - Elastic License 2.0 (NOT MIT)
dashboard/             Next.js 15 + React 19 enterprise dashboard
hooks/                 Pre-install verification hooks (shell)
spec/                  JSON Schema definitions + example manifests
threat-library/        Community IOC and YARA data
deploy/                Production deployment templates
.github/               Workflows, issue templates, CODEOWNERS
```

The `service/src/skillledger_service/ee/` directory is licensed under
the Elastic License 2.0, not MIT. Read its [LICENSE](service/src/skillledger_service/ee/LICENSE)
before contributing to that path.

---

## Development Setup

### Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Go | 1.26+ | `cli/`, `log/` |
| Python | 3.12+ | `service/` |
| Node.js | 20+ (LTS) | `dashboard/` |
| Docker + Compose v2 | latest | full-stack local testing |
| `git` | 2.40+ | history filtering, signed commits |

### One-time setup

```bash
git clone git@github.com:skillledger/skillledger.git
cd skillledger

# Pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install

# Go dependencies
cd cli && go mod download && cd ..

# Python dependencies
cd service
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd ..

# Dashboard dependencies
cd dashboard && npm install && cd ..

# Copy env template
cp .env.example .env
cp dashboard/.env.local.example dashboard/.env.local
# Edit both files with real values
```

### Running the stack locally

```bash
docker compose up -d
# Service:   http://localhost:8000
# Log:       http://localhost:2025
# Postgres:  localhost:5432

# Dashboard (separate terminal)
cd dashboard && npm run dev
# http://localhost:3000
```

---

## Branch and Commit Conventions

### Branch names

Use a short, hyphenated, prefixed name:

| Prefix | Use for |
|---|---|
| `feat/` | New features or capabilities |
| `fix/` | Bug fixes |
| `docs/` | Documentation only |
| `refactor/` | Internal restructuring with no behaviour change |
| `test/` | Test-only changes |
| `chore/` | Tooling, CI, dependencies |
| `perf/` | Performance improvements |
| `security/` | Security fixes (often coordinated privately first) |

Examples: `feat/codex-tool-adapter`, `fix/tlog-proof-edge-case`,
`docs/install-on-windows`.

### Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short imperative subject, <=72 chars>

<optional body explaining WHY, not WHAT. Wrap at ~72 cols.>

<optional footers: Refs #123, Closes #456, BREAKING CHANGE: ...>
```

`<type>` matches the branch prefixes above. Scopes are optional but
useful, e.g. `feat(cli): add --json output to audit`.

Keep commits focused. A pull request should be reviewable as a sequence
of small, individually-defensible commits.

---

## Pull Request Process

1. **Fork** the repository, or branch directly if you have write access.
2. **Open an issue first** for non-trivial changes. Link the PR to it.
3. **Write tests.** Every behaviour change needs a test. Bug fixes need
   a regression test that fails before the fix.
4. **Update docs.** README, CHANGELOG (`[Unreleased]`), and any inline
   docs that drift.
5. **Run the full local check** (see "Running tests" below). Don't
   submit a PR that doesn't pass locally.
6. **Push** and open a PR against `main`. Fill in the PR template.
7. **CI must pass.** PRs with red CI will not be reviewed.
8. **Address review comments** by pushing follow-up commits; do not
   force-push during review. The reviewer will squash on merge.
9. **Merge** is done by a maintainer once at least one approving review
   is recorded and all required checks pass.

We aim to triage new PRs within 5 business days.

---

## Running Tests

```bash
# Go CLI tests (run from cli/)
cd cli && go test ./...

# Python service tests (run from service/)
cd service && python3 -m pytest tests/ -v

# Dashboard type-check and lint
cd dashboard && npm run lint && npm run typecheck

# GitHub Actions YAML validity
python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ['.github/actions/build/action.yml','.github/actions/sign/action.yml','.github/actions/verify/action.yml','.github/workflows/skillledger-ci.yml']]"
```

If a Go test fails complaining about `libtokenizers`, run only the
non-CGO packages:

```bash
CGO_ENABLED=0 go test ./...
```

---

## Code Style

### Go (`cli/`, `log/`)

- `gofmt` and `goimports` (the pre-commit hook runs both)
- `golangci-lint run` (config: `.golangci.yml`)
- All filesystem access must go through `afero.Fs` for testability
- Use `afero.Lstater.LstatIfPossible()` for symlink detection (Walk
  resolves symlinks silently)
- Content hashes are formatted as `sha256-<lowercase-hex>`

### Python (`service/`)

- `ruff format` and `ruff check` (configured in `pyproject.toml`)
- Type hints everywhere; `mypy` clean
- Async-first: all DB access via `AsyncSession`
- Configuration via `pydantic-settings` with `SKILLLEDGER_` env prefix
- Authentication via the `get_current_publisher` or
  `get_admin_or_publisher` dependencies; never roll your own

### TypeScript (`dashboard/`)

- `eslint` + `prettier` (run by `npm run lint`)
- Strict TypeScript - no `any`, no implicit `any`
- API access via the generated TypeScript client (never raw `fetch` for
  authenticated endpoints)
- The `design` skill (`.claude/skills/design/SKILL.md`) is mandatory
  when creating or modifying any UI file. See [CLAUDE.md](CLAUDE.md).

### Shell (`hooks/`, `deploy/`)

- `set -euo pipefail` at the top of every script
- ShellCheck clean (`shellcheck hooks/*.sh deploy/*.sh`)

---

## Adding a New Ecosystem Adapter

1. Define a JSON Schema profile under `spec/schemas/profiles/<name>.schema.json`
2. Mirror it under `cli/internal/schema/schemas/profiles/<name>.schema.json`
   (embedded for offline validation)
3. Implement the `Adapter` interface in `cli/internal/ecosystem/<name>/`
4. Register the adapter in `cli/internal/ecosystem/registry.go`
5. Write golden-file tests in `cli/internal/ecosystem/<name>/testdata/`
6. Add an install hook under `hooks/<name>-hook.sh` if applicable
7. Update the "Supported Ecosystems" table in `README.md`

---

## Filing a Bug Report

Use the **Bug report** issue template. The minimum we need to act:

- SkillLedger version (`skillledger --version`) and commit SHA
- Operating system and architecture
- The exact command that triggered the bug
- Expected behaviour vs. actual behaviour
- Any relevant log output (use `SKILLLEDGER_DEBUG=1` for verbose logs)
- A minimal reproduction repository or manifest if possible

Reports without a reproduction may be closed pending more information.

---

## Filing a Feature Request

Use the **Feature request** issue template. We need:

- The problem you are trying to solve (not the solution you want)
- A description of how SkillLedger falls short today
- Any alternatives you have considered
- Whether you would be willing to implement the change yourself

We are deliberately conservative about adding scope. Features that
duplicate existing tools (skill marketplaces, OS-level sandboxing,
full container isolation) are out of scope per `.planning/PROJECT.md`.

---

## Releasing (Maintainer Only)

1. Update `CHANGELOG.md` - move `[Unreleased]` items into a new
   versioned section.
2. Bump `cli/VERSION` and any package manifests.
3. Tag the release: `git tag -s vX.Y.Z -m "vX.Y.Z"` (signed tags).
4. Push the tag: `git push origin vX.Y.Z`. GoReleaser publishes the
   npm package and GitHub release.
5. Publish a security advisory if the release includes a CVE.

---

## License

By contributing, you agree that your contributions will be licensed
under:

- **MIT License** for everything except `service/src/skillledger_service/ee/`
- **Elastic License 2.0** for code in `service/src/skillledger_service/ee/`

If you contribute to the EE directory, you also grant us the right to
relicense your contribution under any future ELv2-compatible terms.
