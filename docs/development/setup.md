# Local Development Setup

Milestone 0 establishes the reproducible toolchain only. Application services and containers are introduced in later milestones.

## Prerequisites

- Git
- Node.js exactly `24.18.1` (the bootstrap fails closed on a mismatch)
- a Python 3.12+ launcher; uv installs/manages the pinned Python 3.13 environment
- Corepack, included with the pinned Node distribution
- GNU Make is optional on Windows

Required versions are pinned in `.nvmrc`, `.python-version`, `package.json`, and `pyproject.toml`. The bootstrap command will validate/install project dependencies without reading credentials from Tyche or contacting assessment targets.

```sh
make bootstrap
make check
```

On Windows without GNU Make, use the equivalent commands:

```powershell
python scripts/bootstrap.py
python scripts/verify_repo.py
```

Bootstrap installs uv `0.12.1` through pip, synchronizes `uv.lock` into `.venv`, activates pnpm `10.34.5` through Corepack, and installs only `pnpm-lock.yaml`. It does not start services, read `.env`, or make assessment-target connections.

`verify_repo.py` runs 14 named gates: Phase 0 structure, repository invariants, lock drift, formatting, lint, types, unit tests, contracts, migrations, secrets, images, SBOM inputs, documentation, and Git whitespace. Future-surface gates fail if their components are introduced before their planned milestone.

Copy `.env.example` to `.env` only for local development and replace every `CHANGEME_LOCAL_ONLY` value. `.env` is ignored. Never use production credentials in the local fixture environment. The model provider remains disabled until the agent milestone.

## Runtime troubleshooting

If bootstrap reports a Node mismatch, install the exact `.nvmrc` version using your normal version manager or the official Node distribution, open a fresh terminal, and rerun. Do not bypass the engine check or edit the pin locally.
