# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# The release image: one static musl binary — already built, tested and
# checksummed by the release pipeline — on a distroless static base. There is
# no shell, no package manager and no libc in the final filesystem: what runs
# is the binary, and only the binary.
#
# GoReleaser builds this per platform, passing the prebuilt binary in the
# build context and its name as BINARY_NAME.

FROM gcr.io/distroless/static-debian12:nonroot

ARG BINARY_NAME
COPY ${BINARY_NAME} /usr/bin/permguard-server

# The state volume, owned by the nonroot user of the base image.
VOLUME ["/var/lib/permguard"]
ENV PERMGUARD_WORKING_DIR=/var/lib/permguard

ENTRYPOINT ["/usr/bin/permguard-server"]
