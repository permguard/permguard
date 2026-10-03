#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Extracts the Linux and Windows binaries of a published release into the layout
# `scripts/build-cross.sh` stages, so `scripts/compare-rebuild.sh` compares a rebuild with what a
# user downloads rather than with an intermediate artifact.
#
#   scripts/extract-shipped.sh <archives-directory> <out-directory>
#
# An archive is named `<archive id>_<Os>_<arch>.tar.gz` (or `.zip` for Windows). Its binary is
# written to `<out>/<os>_<arch>/<binary>`, without the `.exe` a Windows binary carries, as the build
# stages it. An archive whose name or content does not match is an error, never skipped.
set -euo pipefail

archives="${1:?usage: scripts/extract-shipped.sh <archives> <out>}"
out="${2:?usage: scripts/extract-shipped.sh <archives> <out>}"

binary_of() {
    case "$1" in
        permguard_cli) echo permguard ;;
        permguard_all_in_one) echo permguard-all-in-one ;;
        permguard_control_plane) echo permguard-control-plane ;;
        permguard_data_plane) echo permguard-data-plane ;;
        *) return 1 ;;
    esac
}

count=0
for archive in "${archives}"/*; do
    name="$(basename "${archive}")"
    if ! [[ "${name}" =~ ^(permguard_[a-z_]+)_(Linux|Windows)_(x86_64|arm64)\.(tar\.gz|zip)$ ]]; then
        printf 'error: not a release archive this script knows: %s\n' "${name}" >&2
        exit 1
    fi
    id="${BASH_REMATCH[1]}"
    os="$(tr '[:upper:]' '[:lower:]' <<<"${BASH_REMATCH[2]}")"
    arch="${BASH_REMATCH[3]}"
    [ "${arch}" = x86_64 ] && arch=amd64
    if ! binary="$(binary_of "${id}")"; then
        printf 'error: no binary is known for the archive id %s\n' "${id}" >&2
        exit 1
    fi
    member="${binary}"
    [ "${os}" = windows ] && member="${binary}.exe"

    unpacked="$(mktemp -d)"
    case "${name}" in
        *.tar.gz) tar -xzf "${archive}" -C "${unpacked}" ;;
        *.zip) unzip -q "${archive}" -d "${unpacked}" ;;
    esac
    found="$(find "${unpacked}" -type f -name "${member}")"
    if [ -z "${found}" ] || [ "$(wc -l <<<"${found}")" -ne 1 ]; then
        printf 'error: %s does not hold exactly one %s\n' "${name}" "${member}" >&2
        exit 1
    fi
    mkdir -p "${out}/${os}_${arch}"
    cp "${found}" "${out}/${os}_${arch}/${binary}"
    rm -rf "${unpacked}"
    count=$((count + 1))
done

if [ "${count}" -ne 16 ]; then
    printf 'error: extracted %s binaries; the release publishes 16 for Linux and Windows\n' "${count}" >&2
    exit 1
fi
printf 'ok: 16 published binaries extracted into %s\n' "${out}"
