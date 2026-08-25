# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

FROM scratch

ARG TARGETPLATFORM
ARG BINARY_NAME=permguard_control_plane

LABEL org.opencontainers.image.title="permguard-control-plane" \
      org.opencontainers.image.description="Permguard control plane runtime." \
      org.opencontainers.image.source="https://github.com/permguard/permguard" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY docker/rootfs/etc/passwd docker/rootfs/etc/group /etc/
COPY --chown=65532:65532 docker/rootfs/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/LICENSE
COPY ${TARGETPLATFORM}/${BINARY_NAME} /usr/local/bin/permguard

USER 65532:65532

EXPOSE 7556 7558

ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["/etc/permguard/config.yml"]
