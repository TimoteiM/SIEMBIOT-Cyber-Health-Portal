# The worker image.
#
# Shares the API's construction and differs in one way that matters: this is the
# process that makes outbound connections to other people's infrastructure. Egress from
# this image is what an operator needs to be able to constrain, so it runs as its own
# user and carries nothing that would let it be repurposed quietly.

FROM python@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY --from=ghcr.io/astral-sh/uv@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853 /uv /usr/local/bin/uv

WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY services ./services
COPY packages/policy ./packages/policy
RUN uv sync --frozen --no-dev


FROM python@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/services/worker/src:/app/services/agent-gateway/src

RUN groupadd --gid 10002 siembiot \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin siembiot

# pg_dump, for the nightly backup task.
#
# Major version 17 specifically, matching the server: pg_dump refuses to dump from a
# server newer than itself, so a 16 client against a 17 database is a backup that stops
# working on the day the database is upgraded and not before.
#
# From Debian's own archive rather than the PostgreSQL project's apt repository, which
# would mean trusting an additional signing key for a package the base distribution
# already carries. `postgresql-client-17` is ~10 MB against an image measured in
# hundreds; the alternative -- a task that reports `pg_dump_not_available` every night --
# costs more.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes postgresql-client-17 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --chown=root:root services/worker /app/services/worker
# The analysis gateway. Carried whether or not a model is configured: an image that
# lacked it would report `skipped_gateway_unavailable` for a deployment that had set
# a key and reasonably expected a narrative, and the two are indistinguishable from
# the outside.
COPY --chown=root:root services/agent-gateway /app/services/agent-gateway
# The policy catalog is what the worker evaluates against, and its digest is recorded
# on every score, so it ships with the image rather than being fetched at runtime.
COPY --chown=root:root packages/policy /app/packages/policy

USER 10002:10002

# No healthcheck. A Celery worker has no socket to probe, and `celery inspect ping`
# would have this container declare itself unhealthy whenever the broker is briefly
# unreachable -- restarting a worker mid-run to no purpose. The engine already treats
# an interrupted run as resumable; liveness here is the orchestrator's business.

# Neither --beat nor a scheduler: exactly one scheduler runs, from beat.Dockerfile, and
# baking it in here would start one per replica the moment anybody scaled the workers.
ENTRYPOINT ["celery", "-A", "siembiot_worker.celery_app", "worker", \
            "--queues", "assessments", "--pool", "threads", "--concurrency", "4", \
            "--loglevel", "info"]
