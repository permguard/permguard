# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# The release image: one static binary — already built, tested and checksummed by the release
# pipeline — on a distroless static base.
#
# Distroless rather than `scratch`, and the difference is three things this image would otherwise
# have to carry itself: the certificate authorities a public TLS endpoint is checked against, the
# `/etc/passwd` entry that makes uid 65532 a *name* rather than a bare number, and the timezone
# database. There is still no shell, no package manager and no libc: what runs is the binary.
#
# GoReleaser hands the prebuilt binary to the build under `${TARGETPLATFORM}/${BINARY_NAME}`, which
# is why the COPY names both.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETPLATFORM
ARG BINARY_NAME=permguard-data-plane

LABEL org.opencontainers.image.title="permguard-data-plane" \
      org.opencontainers.image.description="Permguard data plane runtime." \
      org.opencontainers.image.source="https://github.com/permguard/permguard" \
      org.opencontainers.image.licenses="Apache-2.0"

# The state directory, created here and owned by the user the container runs as. A `VOLUME` over a
# path that does not exist in the image gets one created by the daemon, owned by root — and a
# process running as 65532 cannot then write its own working directory.
COPY --chown=65532:65532 docker/rootfs/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/LICENSE
COPY ${TARGETPLATFORM}/${BINARY_NAME} /usr/local/bin/permguard

USER 65532:65532

VOLUME ["/var/lib/permguard"]
ENV PERMGUARD_WORKING_DIR=/var/lib/permguard

EXPOSE 5443 7443

# The configuration file is an argument, not a flag, and it is required. Naming a default here says
# where to mount one — `-v ./config.yml:/etc/permguard/config.yml` — instead of answering a bare
# `docker run` with a usage error.
ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["/etc/permguard/config.yml"]
