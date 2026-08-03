# Changelog

All notable changes are documented here. The project has no supported release yet.

## Unreleased

### Added

- Independent Phase 0 architecture, ADRs, threat model, methodology draft, and implementation plan.
- Milestone 0 reproducible toolchain pins for Node.js 24.18.1, pnpm 10.34.5, Python 3.13, and uv 0.12.1.
- Frozen JavaScript and Python dependency locks.
- Cross-platform bootstrap and 14-gate repository verification commands.
- Repository invariant, toolchain, secret-scanner, Windows command-shim, runtime, and CI pinning tests.
- Commit-pinned CI foundation workflow with least-privilege permissions.

### Security

- Safe environment template with the model disabled by default.
- Tracked secret/key/generated-file rejection and assignment-shaped secret scanning.
- No Tyche configuration, credentials, dependencies, source, or ticket functionality imported.

### Verification

- On 2026-08-03, fast-forwarded `main` from `0647393` to the unchanged Milestone 0 commit `40d639f` from `implementation/milestone-0`.
- Verified the merged `main` state with `python scripts/bootstrap.py` (exit 0), `python scripts/verify_repo.py` (14/14 gates), `python -m uv run --frozen pytest -q` (13 passed), and `git show --check --oneline --stat HEAD` (exit 0).

### Known limitations

- No application services, database schema, migrations, user journeys, containers, or deployment exist yet.
- The upstream Tyche credential exposure remains a production launch blocker outside this repository's authority.
