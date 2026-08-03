.PHONY: bootstrap check contracts-check api-test web-test e2e-auth db-up db-down migrate

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

db-up:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml up -d --wait

db-down:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml down

migrate:
	python -m uv run --frozen alembic -c services/api/alembic.ini upgrade head
