# The API image.
#
# Built to run with a read-only root filesystem, as an unprivileged user, with no
# package manager and no shell utilities beyond what Python needs. The reasoning is the
# same one that shapes the rest of this system: an image is a boundary, and everything
# left inside it is available to whoever gets in.
#
# Base pinned by digest rather than by tag. `python:3.13-slim` is a moving target, so a
# tag makes the build reproducible only until somebody republishes it -- which is also
# how an unnoticed base change reaches production.

FROM python@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

# uv is pinned by digest for the same reason as the base image; a build tool that
# changes under you produces a different artefact from the same source. The verify
# gate checks this, and caught it being pinned by tag on the first attempt.
COPY --from=ghcr.io/astral-sh/uv@sha256:4de5495181a281bc744845b9579acf7b221d6791f99bcc211b9ec13f417c2853 /uv /usr/local/bin/uv

WORKDIR /src

# The lockfile alone first, so dependency installation is cached independently of the
# source. Editing a handler should not reinstall the world.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY services ./services
COPY packages/policy ./packages/policy
RUN uv sync --frozen --no-dev --extra pdf


FROM python@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251

# No uv, no compiler, no lockfiles in the runtime image: none of it is needed to serve
# a request, and each is a tool for whoever should not be here.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/services/api/src:/app/services/worker/src

# Font and text-shaping libraries for PDF rendering. Named individually rather than by a
# meta-package: a report renders Romanian diacritics, and a missing font produces a
# document full of boxes that still looks like a successful render.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# A fixed uid rather than a name, so file ownership is the same whatever the host
# resolves. 10001 is outside the range distributions assign to their own accounts.
RUN groupadd --gid 10001 siembiot \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin siembiot

WORKDIR /app
COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --chown=root:root services/api /app/services/api
# The worker package too: HTTPS domain verification goes through the shared network
# safety boundary, so the API reaches into siembiot_worker.network_safety. That is a
# real dependency and shipping only the API source produced an image that imported
# cleanly in the build and failed at start.
COPY --chown=root:root services/worker /app/services/worker
# The policy package is data the API reads at runtime to render findings and guidance.
COPY --chown=root:root packages/policy /app/packages/policy

# Owned by root and readable by the runtime user, which is what makes a read-only root
# filesystem workable: the process has nothing it is allowed to modify.
USER 10001:10001

EXPOSE 8000

# Liveness only. Readiness is /api/v1/ready and belongs to the orchestrator, which can
# take a replica out of rotation; a container healthcheck can only restart it, and
# restarting for a database outage makes recovery slower rather than faster.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"]

ENTRYPOINT ["uvicorn", "--factory", "siembiot.main:create_app", "--host", "0.0.0.0", "--port", "8000"]
