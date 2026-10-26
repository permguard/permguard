# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The Compose lab's one image (TD-3): the four binaries — the CLI, the Control Plane, the Data Plane
# and the all-in-one — built from this checkout in one cargo invocation, on a small Debian with the
# shell, curl, jq and openssl the lab's bootstrap and assertions run on. Every lab service runs it,
# as the same non-root user the release images use.
#
# It is a lab image, not a release one: the release images are built by the repository's
# `Dockerfile`, static and on `scratch`, and verified at deploy (TD-4). The lab's script and the
# examples it applies are mounted at run time, so changing them never rebuilds the binaries.
#
#   docker build -f lab/compose/Dockerfile -t permguard/lab:local .

FROM rust:1.97-slim-trixie AS builder

# `libprotobuf-dev` beside the compiler: the Data Plane's protocol imports the well-known types,
# which Debian ships in the -dev package (see the repository's `Dockerfile`).
RUN apt-get update \
 && apt-get install --no-install-recommends --yes protobuf-compiler libprotobuf-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=permguard-lab-target \
    cargo build --release --locked \
        -p permguard-cli --bin permguard \
        -p permguard-control-plane --bin permguard-control-plane \
        -p permguard-data-plane --bin permguard-data-plane \
        -p permguard-all-in-one --bin permguard-all-in-one \
 && mkdir -p /out \
 && cp target/release/permguard target/release/permguard-control-plane \
       target/release/permguard-data-plane target/release/permguard-all-in-one /out/

FROM debian:trixie-slim AS lab

RUN apt-get update \
 && apt-get install --no-install-recommends --yes bash ca-certificates curl jq openssl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nonroot \
 && mkdir -p /var/lib/permguard /lab \
 && chown 65532:65532 /var/lib/permguard /lab

COPY --from=builder /out/ /usr/local/bin/
COPY LICENSE /usr/share/doc/permguard/

USER 65532:65532
WORKDIR /lab
