.PHONY: bootstrap check contracts-check api-test web-test e2e-auth db-up db-down migrate \
	test-domain test-network-safety test-collectors test-adapters providers-check fixture-stack \
	policy-validate test-normalization test-scoring methodology-reproduce observe \
	worker-serve beat-serve prod-up prod-down prod-migrate smoke

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

# Assess a public domain using passive observation only. No enrollment, no ownership
# proof: DOMAIN=example.com make observe
observe:
	python -m uv run --frozen python scripts/observe_domain.py $(DOMAIN)

# The queue worker. Run `make beat-serve` alongside it -- the scheduler is a separate
# process because Celery refuses --beat on Windows, and separating them is what you
# want in production anyway: workers scale out, the scheduler must not. Exactly one
# scheduler should run. A second would enqueue every due run twice; harmless, since the
# engine deduplicates, but twice the load for nothing.
#
# A thread pool, not prefork: collection is waiting on DNS, TLS and HTTP, so threads fit
# the work, each task opens its own database connection, and it is the one pool that
# behaves identically on Windows and Linux.
worker-serve:
	python -m uv run --frozen --env-file .env celery -A siembiot_worker.celery_app worker \
		--queues assessments --pool threads --concurrency 4 --loglevel info

beat-serve:
	python -m uv run --frozen --env-file .env celery -A siembiot_worker.celery_app beat \
		--loglevel info

# The production-like stack: the real images, hardened the way they are meant to run.
# Distinct project name from the development stack, which shares this directory.
PROD_COMPOSE = docker compose -f infra/compose/production-like.compose.yml --env-file .env

prod-migrate:
	$(PROD_COMPOSE) --profile migrate run --rm migrate

prod-up:
	$(PROD_COMPOSE) up -d --build

prod-down:
	$(PROD_COMPOSE) down

# Proves the stack serves, rather than merely started: a container that reached
# "running" has only proved that its entrypoint resolved.
smoke:
	python scripts/smoke_test.py

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

# Local infrastructure only. Authentication terminates upstream and is owned by another
# team, so no identity provider runs here. The API and web run on the host, because
# production images are Milestone 10 work.
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
	python -m uv run --frozen --env-file .env alembic -c services/api/alembic.ini upgrade head
