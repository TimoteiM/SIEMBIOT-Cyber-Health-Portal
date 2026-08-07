# The scheduler image.
#
# Identical to the worker apart from the entrypoint, and separate on purpose: exactly
# one scheduler must run. Two would enqueue every due assessment twice -- harmless,
# because the engine deduplicates, but twice the load against other people's
# infrastructure for no benefit. Keeping it a distinct image and a distinct deployment
# makes "scale this to one" something an operator states rather than remembers.
#
# It also makes no outbound connections to targets. It reads schedules and writes rows;
# the collection all happens in the worker.

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

RUN groupadd --gid 10003 siembiot \
    && useradd --uid 10003 --gid 10003 --no-create-home --shell /usr/sbin/nologin siembiot

WORKDIR /app
COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --chown=root:root services/worker /app/services/worker
# The policy catalog is what the worker evaluates against, and its digest is recorded
# on every score, so it ships with the image rather than being fetched at runtime.
COPY --chown=root:root packages/policy /app/packages/policy

USER 10003:10003

# No healthcheck. There is no socket to probe, and a scheduler that declares itself
# unhealthy during a brief broker outage would be restarted for nothing. Whether beat is
# actually dispatching is answered by `siembiot_schedules_due`, which is the signal that
# matters: a scheduler that is running but not dispatching looks healthy to any probe.

# `beat`, not `worker`. This image consumes no queue and runs no task; it only wakes on
# the intervals in `beat_schedule` and enqueues `siembiot.sweep` and
# `siembiot.start_scheduled` for the workers to pick up.
#
# The schedule file goes in /tmp because the root filesystem is read-only. Losing it on
# restart is harmless -- both entries are fixed intervals rather than crontabs, so beat
# reschedules them immediately from the configuration.
ENTRYPOINT ["celery", "-A", "siembiot_worker.celery_app", "beat", \
            "--schedule", "/tmp/celerybeat-schedule", \
            "--loglevel", "info"]
