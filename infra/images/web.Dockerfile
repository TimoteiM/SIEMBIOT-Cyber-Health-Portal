# The web image.
#
# A standalone Next build: the server and only the dependencies it actually reaches,
# rather than the whole node_modules tree. Smaller is the lesser reason; the real one
# is that a development toolchain shipped to production is a toolchain available to
# whoever gets in.

FROM node@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS build

ENV NEXT_TELEMETRY_DISABLED=1 \
    CI=true

# Where the browser's /api requests are forwarded.
#
# A build argument rather than a runtime variable because Next evaluates rewrites()
# during `next build` and serialises the result into routes-manifest.json. Setting it
# in the container's environment looks right and does nothing -- worth naming, because
# the first build of this image baked the development default and every proxied request
# failed with ECONNREFUSED to 127.0.0.1.
#
# The cost is that the image carries one assumption about its network. A deployment
# that fronts both services with a shared ingress -- routing /api to the API and the
# rest here -- needs no rewrite at all, and no rebuild to move either service.
ARG SIEMBIOT_API_BASE_URL=http://api:8000
ENV SIEMBIOT_API_BASE_URL=${SIEMBIOT_API_BASE_URL}

WORKDIR /src

# Corepack pins pnpm from package.json, so the build uses the same package manager the
# lockfile was written by rather than whatever is newest.
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/contracts/package.json packages/contracts/
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm --filter @siembiot/web build


FROM node@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN groupadd --gid 10004 siembiot \
    && useradd --uid 10004 --gid 10004 --no-create-home --shell /usr/sbin/nologin siembiot

WORKDIR /app

# The standalone output already contains the server and its resolved dependencies.
# Static assets and the public tree are separate because Next expects to find them
# beside the server rather than inside it.
COPY --from=build --chown=root:root /src/apps/web/.next/standalone ./
COPY --from=build --chown=root:root /src/apps/web/.next/static ./apps/web/.next/static

USER 10004:10004

EXPOSE 3000

# The application's own page, not a static file: a 200 from the framework means it can
# render, whereas a file served from disk would pass while rendering was broken.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:3000/', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

# The development identity middleware is inert here: it is gated on NODE_ENV being
# exactly "development", which this image sets to production before anything runs.
ENTRYPOINT ["node", "apps/web/server.js"]
