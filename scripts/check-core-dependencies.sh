#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Fails when `permguard-core` grows a dependency outside its allowlist.
#
# Every crate in the workspace — and every crate a downstream build writes to implement one of these
# contracts — depends on `permguard-core`. Whatever lands in its dependency list lands in all of them, and
# a contracts crate that drags a database driver stops being a contracts crate.
#
# The allowlist is what it takes to describe configuration, plus what a contract itself promises.
# Widening it is a deliberate act: change this line, and say why in the commit.
#
#   anyhow, serde, serde_norway  describing and reading configuration
#   zeroize                      erasing key material on drop is part of what `Secret` *is*, so it
#                                cannot live in whichever crate happens to construct one

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT}/crates/permguard-core/Cargo.toml"
ALLOWED=("anyhow" "serde" "serde_norway" "zeroize")

declared="$(
    awk '
        /^\[/ { in_deps = ($0 == "[dependencies]" || $0 == "[build-dependencies]"); next }
        !in_deps { next }
        /^[A-Za-z0-9_-]+/ { name = $0; sub(/[^A-Za-z0-9_-].*$/, "", name); print name }
    ' "${MANIFEST}"
)"

violations=""

for name in ${declared}; do
    allowed="no"

    for candidate in "${ALLOWED[@]}"; do
        if [ "${name}" = "${candidate}" ]; then
            allowed="yes"
            break
        fi
    done

    if [ "${allowed}" = "no" ]; then
        violations="${violations}  ${name}"$'\n'
    fi
done

if [ -n "${violations}" ]; then
    printf 'permguard-core declares dependencies outside its allowlist:\n%s' "${violations}" >&2
    printf 'error: allowed are %s\n' "${ALLOWED[*]}" >&2
    exit 1
fi

printf 'ok: permguard-core depends only on %s\n' "${ALLOWED[*]}"
