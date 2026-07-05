FROM node:24.16.0-alpine AS base
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
ARG TRIVY_VERSION=0.69.3
ARG SCORECARD_VERSION=5.4.0
RUN case "$TARGETARCH" in \
    arm64) \
      OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_musllinux_aarch64; \
      OPENGREP_SHA=d12806eb2e8f67b3b2221bac57d57af763a7bb39cb9149806c0e42cdefe58bdd; \
      GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_arm64.tar.gz; \
      GITLEAKS_SHA=b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f; \
      TRIVY_ARCH=ARM64; \
      SCORECARD_ARCH=arm64; \
      ;; \
    *) \
      OPENGREP_URL=https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_musllinux_x86; \
      OPENGREP_SHA=4991ea777c0a853db45876a2c324fb4fed65873e725dd1677bcb9e707f959f99; \
      GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz; \
      GITLEAKS_SHA=79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e; \
      TRIVY_ARCH=64bit; \
      SCORECARD_ARCH=amd64; \
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
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" -o /tmp/trivy.tar.gz \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" -o /tmp/trivy.sums \
    && grep "trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" /tmp/trivy.sums \
       | sed "s|trivy_.*|/tmp/trivy.tar.gz|" | sha256sum -c - \
    && tar -xz -C /usr/local/bin/ trivy -f /tmp/trivy.tar.gz \
    && rm /tmp/trivy.tar.gz /tmp/trivy.sums \
    && curl -sSfL "https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/scorecard_${SCORECARD_VERSION}_linux_${SCORECARD_ARCH}.tar.gz" -o /tmp/scorecard.tar.gz \
    && curl -sSfL "https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/scorecard_checksums.txt" -o /tmp/scorecard.sums \
    && grep "scorecard_${SCORECARD_VERSION}_linux_${SCORECARD_ARCH}.tar.gz" /tmp/scorecard.sums \
       | sed "s|scorecard_.*|/tmp/scorecard.tar.gz|" | sha256sum -c - \
    && tar -xz -C /usr/local/bin/ scorecard -f /tmp/scorecard.tar.gz \
    && rm /tmp/scorecard.tar.gz /tmp/scorecard.sums

# opengrep does not publish checksums.txt; SHA256s verified locally with:
#   curl -sSfL "$OPENGREP_URL" -o /tmp/opengrep && sha256sum /tmp/opengrep
# recompute on version bump and update OPENGREP_SHA above

# archived opengrep-rules snapshot (LGPL fork of semgrep-rules); verify SHA at:
#   https://github.com/opengrep/opengrep-rules/commit/f1d2b562b414783763fd02a6ed2736eaed622efa
ARG OPENGREP_RULES_SHA=f1d2b562b414783763fd02a6ed2736eaed622efa
RUN mkdir -p /opt/opengrep-rules \
    && git -C /opt/opengrep-rules init \
    && git -C /opt/opengrep-rules remote add origin https://github.com/opengrep/opengrep-rules.git \
    && git -C /opt/opengrep-rules fetch --depth 1 origin "${OPENGREP_RULES_SHA}" \
    && git -C /opt/opengrep-rules checkout FETCH_HEAD \
    && test "$(git -C /opt/opengrep-rules rev-parse HEAD)" = "${OPENGREP_RULES_SHA}" \
    && rm -rf /opt/opengrep-rules/.git

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 appuser
RUN mkdir -p /var/lib/trivy /home/appuser/.cache/opengrep \
    && trivy --cache-dir /var/lib/trivy image --download-db-only \
    && chown -R appuser:nodejs /var/lib/trivy /home/appuser/.cache
RUN chown -R appuser:nodejs /opt/opengrep-rules

ARG LIZARD_VERSION=1.9.25
ARG JSCPD_VERSION=4.2.5
RUN apk add --no-cache python3 py3-pip \
    && pip install --break-system-packages "lizard==${LIZARD_VERSION}" \
    && npm install -g "jscpd@${JSCPD_VERSION}"

COPY --from=builder --chown=appuser:nodejs /prod/api ./
COPY --from=builder --chown=appuser:nodejs /app/apps/api/dist ./dist
COPY --from=builder --chown=appuser:nodejs /app/THIRD-PARTY-NOTICES.md ./THIRD-PARTY-NOTICES.md

USER appuser

EXPOSE 4000

CMD ["node", "dist/index.js"]
