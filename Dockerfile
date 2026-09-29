FROM oven/bun:1.4.0 AS base

WORKDIR /app

# Persistent queue mountpoint, owned by the runtime user. Docker seeds the empty
# named volume from this directory, so uid 1000 can write relay.db.
RUN mkdir -p /data && chown 1000:1000 /data

# Dependency layer first: editing index.ts must not invalidate `bun install`.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Application code.
COPY --chown=1000:1000 . .

ENV NODE_ENV=production
USER bun

EXPOSE 8655
CMD ["bun", "run", "start"]
