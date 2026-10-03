#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the Linux and Windows release binaries and stages them for GoReleaser.
#
#   scripts/build-cross.sh <output-directory>
#
# Four binaries for four targets, cross-compiled with `cargo zigbuild` from one Linux runner, staged
# as <output>/<os>_<arch>/<binary> — the layout `.goreleaser.yaml` imports as prebuilt. A Windows
# binary is staged without `.exe`; GoReleaser adds it in the archive.
#
# The release workflow runs this twice on separate runners: once in `cross-binaries`, whose output
# is what ships, and once in `reproducible-rebuild`, whose output is only compared against it. The
# same script is what makes the comparison mean anything. The version comes from the tag
# (`GITHUB_REF_NAME`) and the commit from `GITHUB_SHA`, the only inputs that differ per release.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

output="${1:?usage: scripts/build-cross.sh <output-directory>}"
export PERMGUARD_BUILD_VERSION="${GITHUB_REF_NAME#v}"
export PERMGUARD_BUILD_COMMIT="${GITHUB_SHA}"

binaries=(permguard permguard-all-in-one permguard-control-plane permguard-data-plane)
packages=(--package permguard-cli --package permguard-all-in-one --package permguard-control-plane --package permguard-data-plane)

# target  os_arch  extension
while read -r target staged extension; do
    cargo zigbuild --release --locked --target "${target}" "${packages[@]}"
    mkdir -p "${output}/${staged}"
    for binary in "${binaries[@]}"; do
        cp "target/${target}/release/${binary}${extension}" "${output}/${staged}/${binary}"
    done
done <<'TARGETS'
x86_64-unknown-linux-musl linux_amd64
aarch64-unknown-linux-musl linux_arm64
x86_64-pc-windows-gnu windows_amd64 .exe
aarch64-pc-windows-gnullvm windows_arm64 .exe
TARGETS

chmod +x "${output}"/*/*
printf 'ok: %s binaries staged under %s\n' "$(find "${output}" -type f | wc -l | tr -d ' ')" "${output}"
