# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The image verifier a deployment runs before a Permguard container starts (TD-4): the GitHub CLI,
# whose `gh attestation verify` checks an image digest's Sigstore-signed SLSA provenance against
# the repository, the builder workflow and the tag it must come from. The chart's `verify-image`
# init container runs it; build it, push it, and name it by digest in
# `imageVerification.verifier.image`.
#
#   docker build -f docker/verifier/Dockerfile -t <registry>/permguard-verifier:2.98.0 docker/verifier
#
# The CLI is the release tarball of `cli/cli`, pinned by version and by the checksums that release
# published; a different tarball fails the build.

FROM debian:trixie-slim

ARG GH_VERSION=2.98.0
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sum=3b8ac6b30336802fc1a858d7c084e11cdf24ac1a761ca90b68022d7d729208de ;; \
      arm64) sum=cf689084f3a3618f7eae4a2420d335d74626d65f5e594b9828d125d69f800d86 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install --no-install-recommends --yes ca-certificates curl; \
    tarball="gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSLo "/tmp/${tarball}" "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${tarball}"; \
    echo "${sum}  /tmp/${tarball}" | sha256sum --check; \
    tar -xzf "/tmp/${tarball}" -C /tmp; \
    install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /usr/local/bin/gh; \
    rm -rf /tmp/gh_* ; \
    apt-get purge --yes curl; \
    apt-get autoremove --yes; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 65532 nonroot; \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin nonroot

USER 65532:65532
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/gh"]
