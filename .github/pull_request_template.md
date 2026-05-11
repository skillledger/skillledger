## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Related issue

<!-- "Closes #123" or "Refs #123". Required for non-trivial changes. -->

Closes #

## Type of change

<!-- Tick all that apply. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would change existing behaviour)
- [ ] Refactor (no behaviour change)
- [ ] Documentation only
- [ ] Test only
- [ ] CI / build / tooling

## Component

<!-- Which part of SkillLedger does this touch? -->

- [ ] cli
- [ ] service (FastAPI / transparency log)
- [ ] service ee (org / SSO / billing - Elastic-2.0 licensed)
- [ ] dashboard
- [ ] hooks
- [ ] log (Tessera personality)
- [ ] deployment / docker / Caddy
- [ ] schemas / spec
- [ ] threat library
- [ ] docs

## Testing

<!-- Describe what you ran. New behaviour requires new tests. -->

- [ ] `cd cli && go test ./...` passes
- [ ] `cd service && python3 -m pytest tests/ -v` passes
- [ ] `cd dashboard && npm run lint && npm run typecheck` passes
- [ ] I added or updated tests for the change
- [ ] I tested the change manually (describe how below)

### Manual test notes

<!-- e.g. "Built a Claude Code skill with the new flag, verified locally, then re-verified after publishing to a local tlog." -->

## Screenshots / output

<!-- Optional. Required for UI changes. -->

## Checklist

- [ ] My branch is up to date with `main`
- [ ] My code follows the style described in [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md)
- [ ] I have updated `CHANGELOG.md` under `[Unreleased]`
- [ ] I have updated relevant docs (README, inline comments where the WHY is non-obvious)
- [ ] I have not added any new secrets, internal URLs, or personal data
- [ ] I have not introduced new dependencies without justification
- [ ] If this touches `service/src/skillledger_service/ee/`, I understand it is Elastic License 2.0 and have read the [EE LICENSE](../blob/main/service/src/skillledger_service/ee/LICENSE)
- [ ] If this touches security-sensitive paths (signing, verification, policy, proxy), I have flagged this in the PR title

## Breaking changes

<!-- Required if you ticked "Breaking change" above. Describe what breaks and migration steps. -->
