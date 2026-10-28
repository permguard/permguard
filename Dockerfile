# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Where the binary comes from: `builder` compiles it here, from this checkout; `prebuilt` takes it
# from `prebuilt/linux_<arch>/<BIN>` in the context, the layout `scripts/build-cross.sh` stages.
# CI builds the four binaries once, natively and cached, and makes every image from them; a build
# with no argument still compiles, so `docker build .` keeps working on any machine.
ARG BINARY_SOURCE=builder

FROM rust:1.97-slim-trixie AS builder

WORKDIR /src

# `libprotobuf-dev` beside the compiler: `contracts/proto/permguard/data/v1/pdp.proto` imports the
# well-known types (`google/protobuf/struct.proto`, `wrappers.proto`), and Debian ships those
# `.proto` files in the -dev package, not with `protoc`. Without it a build from a clean clone —
# or a clean BuildKit cache — fails in `permguard-control-client`'s `build.rs` before any Rust
# source is compiled.
RUN apt-get update \
 && apt-get install --no-install-recommends --yes protobuf-compiler libprotobuf-dev musl-tools \
 && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac > /target-triple \
 && rustup target add "$(cat /target-triple)"

ARG PACKAGE=permguard-control-plane
ARG BIN=permguard-control-plane
ARG PERMGUARD_COPYRIGHT_YEAR=2022
ARG PERMGUARD_COPYRIGHT_HOLDER="Nitro Agility S.r.l."
ARG PERMGUARD_BUILD_COMMIT=""
# Empty means "whatever the workspace says", which is what an unstamped build honestly is: the
# binary reads an empty stamp as no stamp (`permguard_core::build`), so a lab image reports the
# workspace version and `unknown`, not two blank fields. A release passes the tag here, the same
# string GoReleaser stamps into the published binaries.
ARG PERMGUARD_BUILD_VERSION=""
ENV PERMGUARD_COPYRIGHT_YEAR=${PERMGUARD_COPYRIGHT_YEAR} \
    PERMGUARD_COPYRIGHT_HOLDER=${PERMGUARD_COPYRIGHT_HOLDER} \
    PERMGUARD_BUILD_COMMIT=${PERMGUARD_BUILD_COMMIT} \
    PERMGUARD_BUILD_VERSION=${PERMGUARD_BUILD_VERSION}

COPY . .

# Joined with `&&`, not `;`: a `;`-chain runs every command whatever the previous one returned,
# and the step's status is the last command's. A failed `cargo build` was followed by a `cp` of a
# binary that was never produced, and *that* was the error BuildKit reported, with cargo's own
# diagnostic scrolled away above it. Now `cp` never runs after a failed build, and the step fails
# with cargo's status.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    TRIPLE="$(cat /target-triple)" \
 && UNDERSCORED="$(echo "${TRIPLE}" | tr '-' '_')" \
 && export "CC_${UNDERSCORED}=musl-gcc" \
 && export "CARGO_TARGET_$(echo "${UNDERSCORED}" | tr 'a-z' 'A-Z')_LINKER=musl-gcc" \
 && cargo build --release --locked --target "${TRIPLE}" -p "${PACKAGE}" --bin "${BIN}" \
 && cp "target/${TRIPLE}/release/${BIN}" /usr/local/bin/permguard

RUN ldd /usr/local/bin/permguard 2>&1 | grep -qE "statically linked|not a dynamic executable" \
 || (echo "the binary is dynamically linked and the runtime image has no libc" >&2 && exit 1)

# The prebuilt binary, static already: `scripts/build-cross.sh` links it against musl, and the CI
# job that stages it checks that before building any image.
FROM scratch AS prebuilt
ARG TARGETARCH
ARG BIN=permguard-control-plane
COPY prebuilt/linux_${TARGETARCH}/${BIN} /usr/local/bin/permguard

FROM ${BINARY_SOURCE} AS binary

# The user and the state directory, staged on a small Debian so that an image from a prebuilt
# binary never pulls the Rust toolchain.
FROM debian:trixie-slim AS staged
RUN mkdir -p /staged/var/lib/permguard \
 && chown -R 65532:65532 /staged/var/lib/permguard \
 && printf 'nonroot:x:65532:65532:nonroot:/:/sbin/nologin\n' > /staged/passwd \
 && printf 'nonroot:x:65532:\n' > /staged/group

FROM scratch AS runtime

LABEL org.opencontainers.image.title="Permguard" \
      org.opencontainers.image.description="Permguard plane runtime." \
      org.opencontainers.image.source="https://github.com/permguard/permguard" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=staged /staged/passwd /staged/group /etc/
COPY --from=binary /usr/local/bin/permguard /usr/local/bin/permguard
COPY --from=staged --chown=65532:65532 /staged/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/

USER 65532:65532

EXPOSE 5443 5444 6443 7443

ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["/etc/permguard/config.yml"]
