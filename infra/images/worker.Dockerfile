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
    PYTHONPATH=/app/services/worker/src

RUN groupadd --gid 10002 siembiot \
    && useradd --uid 10002 --gid 10002 --no-create-home --shell /usr/sbin/nologin siembiot

WORKDIR /app
COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --chown=root:root services/worker /app/services/worker
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
