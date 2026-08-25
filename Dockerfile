# syntax=docker/dockerfile:1
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.97-slim-trixie AS builder

WORKDIR /src

RUN apt-get update \
 && apt-get install --no-install-recommends --yes protobuf-compiler musl-tools \
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
ENV PERMGUARD_COPYRIGHT_YEAR=${PERMGUARD_COPYRIGHT_YEAR} \
    PERMGUARD_COPYRIGHT_HOLDER=${PERMGUARD_COPYRIGHT_HOLDER} \
    PERMGUARD_BUILD_COMMIT=${PERMGUARD_BUILD_COMMIT}

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    TRIPLE="$(cat /target-triple)"; \
    UNDERSCORED="$(echo "${TRIPLE}" | tr '-' '_')"; \
    export "CC_${UNDERSCORED}=musl-gcc"; \
    export "CARGO_TARGET_$(echo "${UNDERSCORED}" | tr 'a-z' 'A-Z')_LINKER=musl-gcc"; \
    cargo build --release --locked --target "${TRIPLE}" -p "${PACKAGE}" --bin "${BIN}"; \
    cp "target/${TRIPLE}/release/${BIN}" /usr/local/bin/permguard

RUN mkdir -p /staged/var/lib/permguard \
 && chown -R 65532:65532 /staged/var/lib/permguard \
 && printf 'nonroot:x:65532:65532:nonroot:/:/sbin/nologin\n' > /staged/passwd \
 && printf 'nonroot:x:65532:\n' > /staged/group

RUN ldd /usr/local/bin/permguard 2>&1 | grep -qE "statically linked|not a dynamic executable" \
 || (echo "the binary is dynamically linked and the runtime image has no libc" >&2 && exit 1)

FROM scratch AS runtime

LABEL org.opencontainers.image.title="Permguard" \
      org.opencontainers.image.description="Permguard plane runtime." \
      org.opencontainers.image.source="https://github.com/permguard/permguard-rust" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /staged/passwd /staged/group /etc/
COPY --from=builder /usr/local/bin/permguard /usr/local/bin/permguard
COPY --from=builder --chown=65532:65532 /staged/var/lib/permguard /var/lib/permguard
COPY LICENSE /usr/share/doc/permguard/

USER 65532:65532

EXPOSE 7556 7558 7656 7658

ENTRYPOINT ["/usr/local/bin/permguard"]
CMD ["/etc/permguard/config.yml"]
