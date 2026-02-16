FROM node:24-bookworm-slim AS base
RUN corepack enable pnpm
WORKDIR /workspace

FROM base AS deps
COPY package.json pnpm-lock.yaml* ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    CI=true pnpm install --frozen-lockfile 2>/dev/null || CI=true pnpm install

FROM base AS build
COPY --from=deps /workspace/node_modules ./node_modules
COPY . .

FROM base AS production
COPY --from=deps /workspace/node_modules ./node_modules
COPY . .

ENV NODE_ENV=production
EXPOSE 8090

CMD ["pnpm", "start"]
