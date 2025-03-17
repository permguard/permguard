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
# Build Stage
FROM golang:1.23.5-alpine AS builder

RUN apk add --no-cache make gcc musl-dev
ARG VERSION
ARG BUILD_TIME
ARG GIT_COMMIT

WORKDIR /opt/build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN make build-all-in-one

# Final Stage
FROM alpine:latest

RUN mkdir -p /opt/permguard
RUN rm -rf /opt/permguard/volume && mkdir -p /opt/permguard/volume

WORKDIR /opt/permguard
COPY --from=builder /opt/build/dist/server-all-in-one .
COPY --from=builder /opt/build/dist/permguard.db /opt/permguard/permguard.db

RUN echo '#!/bin/sh' > /opt/permguard/startup.sh \
    && echo 'cp /opt/permguard/permguard.db /opt/permguard/volume/' >> /opt/permguard/startup.sh \
    && echo '/opt/permguard/server-all-in-one' >> /opt/permguard/startup.sh \
    && chmod +x /opt/permguard/startup.sh

ENV PERMGUARD_DEBUG="FALSE"
ENV PERMGUARD_LOG_LEVEL="INFO"
ENV PERMGUARD_SERVER_APPDATA="/opt/permguard/volume"

EXPOSE 9091
EXPOSE 9092
EXPOSE 9094

VOLUME ["/opt/permguard/volume"]

ENTRYPOINT ["/opt/permguard/startup.sh"]
