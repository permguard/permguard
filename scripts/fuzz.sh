#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Runs every coverage-guided fuzz target for a fixed budget.
#
#   scripts/fuzz.sh <seconds-per-target> [target ...]
#
# The targets are the `[[bin]]`s of fuzz/Cargo.toml, or the ones named. Each runs with `-max_len`
# set to the largest input crates/permguard-conformance/boundaries.json lets any decoder it covers
# accept, so a target never spends its budget on inputs no deployment would read; a target the
# registry does not name runs at 64 KiB. Pull requests run a short budget, the nightly job a long
# one. Needs a nightly toolchain and cargo-fuzz; a crash fails the run and leaves its input under
# fuzz/artifacts/<target>/.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

budget="${1:?usage: scripts/fuzz.sh <seconds-per-target> [target ...]}"
shift

registry="crates/permguard-conformance/boundaries.json"
if [ "$#" -gt 0 ]; then
    targets=("$@")
else
    targets=()
    while IFS= read -r target; do
        targets+=("${target}")
    done < <(sed -n 's/^name = "\(.*\)"$/\1/p' fuzz/Cargo.toml | grep -v '^permguard-fuzz$')
fi

failed=()
for target in "${targets[@]}"; do
    max_len="$(jq --arg target "${target}" \
        '[.boundaries[] | select(.fuzz == $target) | .max_input_bytes] | max // 65536' \
        "${registry}")"
    printf 'fuzz: %s for %ss, max_len %s\n' "${target}" "${budget}" "${max_len}"
    # Every target runs even after one fails: a crash in one decoder says nothing about the others.
    if ! cargo +nightly fuzz run "${target}" -- \
        -max_total_time="${budget}" \
        -max_len="${max_len}" \
        -rss_limit_mb=2048; then
        failed+=("${target}")
    fi
done

if [ "${#failed[@]}" -gt 0 ]; then
    printf 'error: these fuzz targets failed: %s\n' "${failed[*]}" >&2
    exit 1
fi
printf 'ok: %s fuzz targets ran for %ss each\n' "${#targets[@]}" "${budget}"
