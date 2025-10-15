# Copyright 2024 Nitro Agility S.r.l.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1
FROM alpine:3.22.2

# Build-time args
ARG TARGETARCH
ARG BINARY_NAME=server-all-in-one
ARG DB_FILE=permguard.db
ARG GRPC_HP_VER=v0.4.18

# Minimal runtime deps:
# - ca-certificates: validate TLS for wget
# - tini: minimal init for PID 1 (signals/zombie reaping)
RUN apk add --no-cache ca-certificates tini

# Non-root user
RUN addgroup -S app && adduser -S -G app -h /opt/permguard app

# App layout
WORKDIR /opt/permguard
RUN mkdir -p /opt/permguard/volume && chown -R app:app /opt/permguard

# App binary + seed DB (owned by non-root)
COPY --chown=app:app linux/${TARGETARCH}/${BINARY_NAME} /opt/permguard/server-all-in-one
COPY --chown=app:app ${DB_FILE} /opt/permguard/permguard.db
RUN chmod +x /opt/permguard/server-all-in-one

# Startup script (idempotent seed copy, then exec)
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -euo pipefail' \
  'if [ ! -f /opt/permguard/volume/permguard.db ]; then' \
  '  cp /opt/permguard/permguard.db /opt/permguard/volume/;' \
  'fi' \
  'exec /opt/permguard/server-all-in-one' \
  > /opt/permguard/startup.sh && \
  chown app:app /opt/permguard/startup.sh && \
  chmod +x /opt/permguard/startup.sh

# Runtime configuration
ENV PERMGUARD_DEBUG="FALSE" \
    PERMGUARD_LOG_LEVEL="INFO" \
    PERMGUARD_SERVER_APPDATA="/opt/permguard/volume"

# Download gRPC health probe (ADD) then verify checksum over HTTPS
ADD https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HP_VER}/grpc_health_probe-linux-${TARGETARCH} /bin/grpc_health_probe
RUN set -eu; \
    CHECKSUMS_URL="https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HP_VER}/checksums.txt"; \
    EXPECTED_SHA="$(wget -qO- "${CHECKSUMS_URL}" | grep -E "grpc_health_probe-linux-${TARGETARCH}\$" | awk '{print $1}')" ; \
    echo "${EXPECTED_SHA}  /bin/grpc_health_probe" | sha256sum -c - ; \
    chmod 0755 /bin/grpc_health_probe

# Network metadata
EXPOSE 9091 9092 9094

# Container health (gRPC health check on 9091)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /bin/grpc_health_probe -addr=localhost:9091 || exit 1

# Persistent application data
VOLUME ["/opt/permguard/volume"]

# Drop privileges
USER app

# Proper init as PID 1
ENTRYPOINT ["/sbin/tini", "--", "/opt/permguard/startup.sh"]
