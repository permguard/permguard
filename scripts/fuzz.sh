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

# AddressSanitizer's bookkeeping, bounded. By default it keeps a 30-frame stack trace of every
# allocation and a large quarantine of freed memory, and neither shrinks: a decoder that allocates
# per input grows the fuzzer's resident set by about 100 MB a second while its live heap stays
# under 40 MB, until libFuzzer reports an out-of-memory that is no bug at all. A 16 MB quarantine
# still catches a use after free, and four frames still say where it was allocated. A single
# oversized allocation is still caught: libFuzzer's malloc limit follows `-rss_limit_mb`.
export ASAN_OPTIONS="${ASAN_OPTIONS:-quarantine_size_mb=16:malloc_context_size=4}"

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
