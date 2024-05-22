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
FROM golang:1.21.3 AS BuildStage
LABEL maintainer="Nitro Agility S.r.l. Team <opensource@nitroagility.com>"

COPY ./cmd /app/cmd
COPY ./pkg /app/pkg
COPY ./scripts /app/scripts
COPY ./go.mod /app/go.mod
COPY ./go.sum /app/go.sum
COPY ./LICENSE /app/LICENSE
COPY ./Makefile /app/Makefile
WORKDIR /app
RUN /bin/bash ./scripts/build.sh

# Build Official Image
FROM alpine:3.19
LABEL maintainer="Nitro Agility S.r.l. Team <opensource@nitroagility.com>"

ARG USER=nonroot
ENV HOME /home/$USER

RUN adduser -D "$USER" \
        && echo "$USER ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$USER" \
        && chmod 0440 "/etc/sudoers.d/$USER"
USER $USER

WORKDIR /home/$USER
COPY --from=BuildStage /app/permguard ./

ENTRYPOINT ["/home/$USER/permguard"]
