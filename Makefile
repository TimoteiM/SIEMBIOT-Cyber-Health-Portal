.PHONY: bootstrap check contracts-check api-test web-test e2e-auth fixture-stack test-adapters test-collectors policy-validate db-up db-down migrate

bootstrap:
	python scripts/bootstrap.py

check:
	python scripts/verify_repo.py

contracts-check:
	python -m uv run --frozen python scripts/check_contracts.py

api-test:
	python -m uv run --frozen pytest tests/api tests/contracts -q

web-test:
	corepack pnpm --filter @siembiot/web test
	corepack pnpm --filter @siembiot/web typecheck

e2e-auth:
	python -m uv run --frozen pytest tests/security/test_auth_tenant_authorization.py -q

fixture-stack:
	python -m uv run --frozen python scripts/validate_fixture_pack.py

test-adapters:
	python -m uv run --frozen pytest tests/adapters -q

test-collectors:
	python -m uv run --frozen pytest tests/collectors tests/fixtures/test_fake_internet.py tests/security/test_collector_network_architecture.py tests/security/test_no_external_fixture_network.py -q

policy-validate:
	python -m uv run --frozen python scripts/validate_policy.py

db-up:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml up -d --wait

db-down:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml down

migrate:
	python -m uv run --frozen alembic -c services/api/alembic.ini upgrade head
