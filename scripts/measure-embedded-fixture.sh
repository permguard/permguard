#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Measures the reference embedding application, `fixtures/embedded-application`, once per named
# profile: the resources the refactoring asks each embedded profile to record.
#
#   packages        what the profile links, the application counted
#   build_s         the release build of the reference application, from the profile's own
#                   target directory; clean when CLEAN=1 empties it first
#   size_bytes      the release binary, stripped
#   rss, threads,   what the running application reports of itself, started as an application
#   shutdown_ms     would and under the one-worker profile
#
# One tab-separated line per measure: profile, mode, measure, value. Trend signals, not gates:
# they depend on the machine and on what else it is doing. What is a gate, what a profile links
# and how many packages, is `check-embedded-fixture.sh`'s.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/fixtures/embedded-application"
MANIFEST="${FIXTURE}/Cargo.toml"
TARGETS="${CARGO_TARGET_DIR:-${ROOT}/target/embedded-fixture-release}"

measure() {
    local selection="$1"
    local name="${selection:-none}"
    # A target directory per profile: a build of one never answers for another.
    export CARGO_TARGET_DIR="${TARGETS}/${name//,/-}"
    if [ "${CLEAN:-0}" = "1" ]; then
        rm -rf "${CARGO_TARGET_DIR}"
    fi
    cp "${ROOT}/Cargo.lock" "${FIXTURE}/Cargo.lock"

    local packages
    packages="$(cargo tree --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" --edges normal,build --prefix none --format '{lib}' |
        sed 's/ (\*)$//' | sort -u | grep -c .)"
    printf '%s\t-\tpackages\t%s\n' "${name}" "${packages}"

    local began ended
    began="$(date +%s)"
    cargo build --quiet --release --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" --example reference 2>/dev/null
    ended="$(date +%s)"
    printf '%s\t-\tbuild_s\t%s\n' "${name}" "$((ended - began))"

    local binary="${CARGO_TARGET_DIR}/release/examples/reference"
    local stripped="${binary}.stripped"
    cp "${binary}" "${stripped}"
    strip "${stripped}" 2>/dev/null || true
    printf '%s\t-\tsize_bytes\t%s\n' "${name}" "$(wc -c <"${stripped}" | tr -d ' ')"

    local mode line
    for mode in default one-worker; do
        if [ "${mode}" = "one-worker" ]; then
            "${stripped}" --one-worker
        else
            "${stripped}"
        fi | while IFS= read -r line; do
            printf '%s\t%s\t%s\n' "${name}" "${mode}" "${line}"
        done
    done
}

for selection in "" cedar rego dogwood "cedar,rego,dogwood"; do
    measure "${selection}"
done
