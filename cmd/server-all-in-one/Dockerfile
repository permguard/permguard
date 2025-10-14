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
FROM alpine:latest

ARG BINARY=server-all-in-one
ARG DB_FILE=permguard.db
ARG TARGETARCH

RUN mkdir -p /opt/permguard
RUN rm -rf /opt/permguard/volume && mkdir -p /opt/permguard/volume

WORKDIR /opt/permguard
COPY ${BINARY} /opt/permguard/server-all-in-one
COPY ${DB_FILE} /opt/permguard/permguard.db

RUN echo '#!/bin/sh' > /opt/permguard/startup.sh \
    && echo 'cp /opt/permguard/permguard.db /opt/permguard/volume/' >> /opt/permguard/startup.sh \
    && echo '/opt/permguard/server-all-in-one' >> /opt/permguard/startup.sh \
    && chmod +x /opt/permguard/startup.sh

ENV PERMGUARD_DEBUG="FALSE"
ENV PERMGUARD_LOG_LEVEL="INFO"
ENV PERMGUARD_SERVER_APPDATA="/opt/permguard/volume"

ADD https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.18/grpc_health_probe-linux-${TARGETARCH} /bin/grpc_health_probe
RUN chmod +x /bin/grpc_health_probe

EXPOSE 9091
EXPOSE 9092
EXPOSE 9094

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /bin/grpc_health_probe -addr=localhost:9091 || exit 1

VOLUME ["/opt/permguard/volume"]

ENTRYPOINT ["/opt/permguard/startup.sh"]
