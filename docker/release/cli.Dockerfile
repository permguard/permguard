# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# The certificate authorities a public TLS endpoint is checked against.
#
# The CLI is the one Permguard image that dials *out*, so it is the one that needs a trust store: the
# planes only ever accept connections. Copied out of a distribution image rather than vendored, so the
# bundle is whoever maintains it upstream and not us.
FROM alpine:3 AS certificates

RUN apk add --no-cache ca-certificates

FROM scratch

ARG TARGETPLATFORM
ARG BINARY_NAME=permguard

LABEL org.opencontainers.image.title="permguard-cli" \
      org.opencontainers.image.description="The Permguard command-line interface." \
      org.opencontainers.image.source="https://github.com/permguard/permguard" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY docker/rootfs/etc/passwd docker/rootfs/etc/group /etc/
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chown=65532:65532 docker/rootfs/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/LICENSE
COPY ${TARGETPLATFORM}/${BINARY_NAME} /usr/local/bin/permguard

USER 65532:65532

# HOME is where the CLI keeps its configuration, and a container that cannot write one is a container
# where `config set` fails. Mount a volume over it to keep a configuration between runs.
ENV HOME=/var/lib/permguard

ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["--help"]
