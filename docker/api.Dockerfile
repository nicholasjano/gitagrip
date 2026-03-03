FROM node:24.14.0-alpine AS base
RUN corepack enable

FROM base AS builder
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm turbo build --filter=@gitagrip/api
RUN pnpm deploy --legacy --filter=@gitagrip/api --prod /prod/api

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 appuser

COPY --from=builder --chown=appuser:nodejs /prod/api ./
COPY --from=builder --chown=appuser:nodejs /app/apps/api/dist ./dist

USER appuser

EXPOSE 4000

CMD ["node", "dist/index.js"]
