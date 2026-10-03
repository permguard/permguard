#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Compares an independent rebuild with the binaries that shipped and writes the verdict.
#
#   scripts/compare-rebuild.sh <shipped-directory> <rebuilt-directory> <verdict-file>
#
# Both directories hold the `<os>_<arch>/<binary>` layout `scripts/build-cross.sh` stages. The
# verdict lists every binary with both SHA-256 digests and ends with one line: `reproducible: yes`
# only when every binary matched and both sides hold the same set, `reproducible: no` otherwise —
# in which case the release does not claim to be reproducible. The macOS binaries are built on
# Apple hardware by another job and are not part of this comparison; the verdict says so.
#
# Exits 0 on a match and 3 on a mismatch, so a caller can publish the verdict either way and still
# report the mismatch.
set -euo pipefail

shipped="${1:?usage: scripts/compare-rebuild.sh <shipped> <rebuilt> <verdict>}"
rebuilt="${2:?usage: scripts/compare-rebuild.sh <shipped> <rebuilt> <verdict>}"
verdict="${3:?usage: scripts/compare-rebuild.sh <shipped> <rebuilt> <verdict>}"

digest() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

list() { (cd "$1" && find . -type f | sed 's|^\./||' | sort); }

matched=1
{
    printf 'independent rebuild of the Linux and Windows binaries, compared with what shipped\n'
    printf 'commit %s, tag %s\n\n' "${GITHUB_SHA:-unknown}" "${GITHUB_REF_NAME:-unknown}"
    if [ "$(list "${shipped}")" != "$(list "${rebuilt}")" ]; then
        printf 'the two builds do not hold the same set of binaries\n'
        matched=0
    fi
    while IFS= read -r binary; do
        expected="$(digest "${shipped}/${binary}")"
        actual="$( [ -f "${rebuilt}/${binary}" ] && digest "${rebuilt}/${binary}" || echo missing)"
        if [ "${expected}" = "${actual}" ]; then
            printf 'match     %s  %s\n' "${expected}" "${binary}"
        else
            printf 'MISMATCH  %s  %s  (rebuilt %s)\n' "${expected}" "${binary}" "${actual}"
            matched=0
        fi
    done < <(list "${shipped}")
    printf '\nnot compared: the macOS binaries, built on Apple hardware by another job\n'
    if [ "${matched}" -eq 1 ]; then
        printf 'reproducible: yes\n'
    else
        printf 'reproducible: no — this release does not claim to be reproducible\n'
    fi
} > "${verdict}"

cat "${verdict}"
[ "${matched}" -eq 1 ] || exit 3
