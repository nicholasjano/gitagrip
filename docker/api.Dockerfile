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

RUN apk add --no-cache git curl wget ca-certificates coreutils

# match scanner binaries to image arch (Mac arm64 vs prod amd64)
ARG TARGETARCH
RUN case "$TARGETARCH" in \
    arm64) \
      OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_musllinux_aarch64; \
      OPENGREP_SHA=d12806eb2e8f67b3b2221bac57d57af763a7bb39cb9149806c0e42cdefe58bdd; \
      GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_arm64.tar.gz; \
      GITLEAKS_SHA=b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f; \
      TRIVY_URL=https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-ARM64.tar.gz; \
      TRIVY_SHA=7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd; \
      ;; \
    *) \
      OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_musllinux_x86; \
      OPENGREP_SHA=4991ea777c0a853db45876a2c324fb4fed65873e725dd1677bcb9e707f959f99; \
      GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz; \
      GITLEAKS_SHA=79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e; \
      TRIVY_URL=https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz; \
      TRIVY_SHA=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75; \
      ;; \
    esac \
    && wget -O /tmp/opengrep "$OPENGREP_URL" \
    && echo "${OPENGREP_SHA}  /tmp/opengrep" | sha256sum -c - \
    && mv /tmp/opengrep /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && curl -sSfL "$GITLEAKS_URL" -o /tmp/gitleaks.tar.gz \
    && echo "${GITLEAKS_SHA}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xz -C /usr/local/bin/ gitleaks -f /tmp/gitleaks.tar.gz \
    && rm /tmp/gitleaks.tar.gz \
    && curl -sSfL "$TRIVY_URL" -o /tmp/trivy.tar.gz \
    && echo "${TRIVY_SHA}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xz -C /usr/local/bin/ trivy -f /tmp/trivy.tar.gz \
    && rm /tmp/trivy.tar.gz

RUN git clone --depth=1 https://github.com/opengrep/opengrep-rules.git /opt/opengrep-rules-src || \
    (rm -rf /opt/opengrep-rules-src && git clone --depth=1 https://github.com/semgrep/semgrep-rules.git /opt/opengrep-rules-src) \
    && mkdir -p /opt/opengrep-rules \
    && for dir in security owasp cwe; do \
      if [ -d "/opt/opengrep-rules-src/$dir" ]; then \
        cp -r "/opt/opengrep-rules-src/$dir" "/opt/opengrep-rules/$dir"; \
      fi; \
    done \
    && rm -rf /opt/opengrep-rules-src

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 appuser
RUN mkdir -p /home/appuser/.cache/trivy /home/appuser/.cache/opengrep \
    && chown -R appuser:nodejs /home/appuser/.cache
RUN chown -R appuser:nodejs /opt/opengrep-rules

COPY --from=builder --chown=appuser:nodejs /prod/api ./
COPY --from=builder --chown=appuser:nodejs /app/apps/api/dist ./dist
COPY --from=builder --chown=appuser:nodejs /app/THIRD-PARTY-NOTICES.md ./THIRD-PARTY-NOTICES.md

USER appuser

EXPOSE 4000

CMD ["node", "dist/index.js"]
