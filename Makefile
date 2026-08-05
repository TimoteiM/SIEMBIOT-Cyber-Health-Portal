.PHONY: bootstrap check contracts-check api-test web-test e2e-auth db-up db-down migrate \
	test-domain test-network-safety test-collectors test-adapters providers-check fixture-stack \
	policy-validate test-normalization test-scoring methodology-reproduce

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

test-domain:
	python -m uv run --frozen pytest tests/domain -q

test-network-safety:
	python -m uv run --frozen pytest tests/network tests/security/test_network_architecture.py -q

test-collectors:
	python -m uv run --frozen pytest tests/collectors -q

test-adapters:
	python -m uv run --frozen pytest tests/adapters -q

policy-validate:
	python -m uv run --frozen pytest tests/policy/test_evaluation.py -q

test-normalization:
	python -m uv run --frozen pytest tests/policy/test_pipeline.py -q

test-scoring:
	python -m uv run --frozen pytest tests/policy/test_scoring.py tests/policy/test_findings.py -q

methodology-reproduce:
	python -m uv run --frozen python scripts/reproduce_methodology.py --check

providers-check:
	python -m uv run --frozen python scripts/generate_provider_matrix.py --check

# Collection fixtures are in-process, so there is no container stack to start.
# This target verifies the fixture corpus is loadable and self-consistent.
fixture-stack:
	python -m uv run --frozen pytest tests/collectors tests/network -q

db-up:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml up -d --wait

db-down:
	docker compose --env-file .env -f infra/compose/postgres.compose.yml down

# Local infrastructure only: PostgreSQL plus an OIDC provider. The API and web run on
# the host, because production images are Milestone 10 work.
stack-up:
	docker compose --env-file .env -f infra/compose/local-stack.compose.yml up -d --wait

stack-down:
	docker compose --env-file .env -f infra/compose/local-stack.compose.yml down

api-serve:
	python -m uv run --frozen uvicorn --app-dir services/api/src \
		--factory siembiot.main:create_app --host 127.0.0.1 --port 8000

web-serve:
	corepack pnpm --filter @siembiot/web dev

migrate:
	python -m uv run --frozen alembic -c services/api/alembic.ini upgrade head
