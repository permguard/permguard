# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# The CLI image: one static binary on a distroless static base.
#
# The CLI is the one Permguard image that dials *out* — the planes only accept connections — so the
# certificate authorities a public TLS endpoint is checked against have to be in it. They come from
# the base rather than being copied out of a distribution image here: the bundle is then whoever
# maintains it upstream, and it is the same bundle every other image in this repository trusts.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
ARG BINARY_NAME=permguard

LABEL org.opencontainers.image.title="permguard-cli" \
      org.opencontainers.image.description="The Permguard command-line interface." \
      org.opencontainers.image.source="https://github.com/permguard/permguard" \
      org.opencontainers.image.licenses="Apache-2.0"

# `HOME` is where the CLI keeps its configuration, and a container that cannot write one is a
# container where `config set` fails. Created here and owned by the user the container runs as;
# mount a volume over it to keep a configuration between runs.
COPY --chown=65532:65532 docker/rootfs/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/LICENSE
COPY ${TARGETPLATFORM}/${BINARY_NAME} /usr/local/bin/permguard

USER 65532:65532

ENV HOME=/var/lib/permguard

ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["--help"]
