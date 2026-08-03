# SIEMBIOT Cyber Health Portal

SIEMBIOT is a planned free/community platform for Romanian public institutions and private organizations to measure external security posture, assess organizational maturity, and receive private, evidence-backed remediation guidance.

The repository has completed Phase 0 and is implementing **Milestone 0: reproducible foundation**. It does not yet contain a runnable product and must not be represented as production-ready, NIS2-compliant, certified, or capable of performing authorized scans.

## Development

Toolchains and dependencies are exact or lockfile-pinned. See [local setup](docs/development/setup.md), then run:

```sh
make bootstrap
make check
```

On Windows without GNU Make, run `python scripts/bootstrap.py` followed by `python scripts/verify_repo.py`.

## Phase 0 documents

- [Repository audit](docs/product/repository-audit.md)
- [Product specification](docs/product/product-specification.md)
- [Target architecture](docs/architecture/target-architecture.md)
- [Threat model](docs/security/threat-model.md)
- [Tyche adaptation boundary](docs/architecture/tyche-adaptation.md)
- [Architecture decisions](docs/adr/README.md)
- [Implementation plan](docs/plans/2026-08-03-production-implementation-plan.md)
- [Authoritative source register](docs/knowledge-base/source-register.md)
- [Changelog](CHANGELOG.md)

## Upstream relationship

Microsoft Tyche is a read-only architectural reference pinned in the audit. Its Git history, configuration, credentials, generated files, dependencies, and ticket-management functionality are not part of this repository. No Microsoft endorsement is implied.

## License

MIT. See [LICENSE](LICENSE).
