#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Builds and tests the reference embedding application, `fixtures/embedded-application`, once per
# named profile, outside the repository's workspace.
#
# The application names one Permguard package, `permguard-data-plane`, with no default feature and
# a feature per language. It is a workspace of its own, so Cargo resolves each profile for it
# alone: nothing another member selects can be unified into what it links, which is the one thing
# a profile resolved inside the workspace cannot rule out.
#
# For every profile:
#
#   what it links     no server, listener, transport, telemetry exporter, network client, generated
#                     contract, TLS stack or default implementation, and no engine it did not
#                     select: read from `cargo tree`, so a package that is linked is found whether
#                     or not anything calls it
#   how much          no more packages than the profile's budget: the count measured when the
#                     profile was last settled, with a margin of about five in a hundred, so a
#                     dependency that grows a profile is seen when it arrives
#   what it does      the fixture's tests of that profile pass, and at least one ran
#   one worker        for a profile that decides a ledger alone, the reference application under the
#                     one-worker profile decides it and holds no more threads than the bound below
#
# The fixture's lockfile is the workspace's, copied before each run: a profile is proven with the
# versions the repository ships, and there is no second lockfile to keep.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/fixtures/embedded-application"
MANIFEST="${FIXTURE}/Cargo.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target/embedded-fixture}"

# What no embedded profile links, by library name as `cargo tree` prints it.
NEVER="permguard_server permguard_runtime permguard_offline permguard_transport permguard_telemetry
permguard_std permguard_client permguard_contracts axum tonic hyper tower_http opentelemetry rustls
clap"

# The engine each language brings. Dogwood lowers to Cedar, so it brings Cedar's too.
engines_of() {
    case "$1" in
        (cedar) printf 'cedar_policy\n' ;;
        (rego) printf 'regorus\n' ;;
        (dogwood) printf 'dogwood_language\ncedar_policy\n' ;;
    esac
}

# The most packages a profile may link, the application counted: measured on 2026-11-16 at 80,
# 153, 183, 181 and 260, where the Data Plane of the release before the refactoring linked 418.
budget_of() {
    case "$1" in
        ("") printf '85\n' ;;
        (cedar) printf '160\n' ;;
        (rego) printf '192\n' ;;
        (dogwood) printf '190\n' ;;
        (cedar,rego,dogwood) printf '273\n' ;;
    esac
}

check() {
    local selection="$1"
    local name="${selection:-no language}"
    printf '==> the embedding application built with `%s`\n' "${name}"

    cp "${ROOT}/Cargo.lock" "${FIXTURE}/Cargo.lock"

    local linked
    linked="$(cargo tree --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" --edges normal,build --prefix none --format '{lib}' |
        sed 's/ (\*)$//' | sort -u)"

    local allowed=""
    local language
    for language in ${selection//,/ }; do
        allowed="${allowed} $(engines_of "${language}")"
    done
    local forbidden="${NEVER}"
    local engine
    for engine in cedar_policy regorus dogwood_language; do
        case " ${allowed//$'\n'/ } " in
            (*" ${engine} "*) ;;
            (*) forbidden="${forbidden} ${engine}" ;;
        esac
    done

    local failed=0
    local package
    for package in ${forbidden}; do
        if printf '%s\n' "${linked}" | grep -qx "${package}"; then
            printf 'error: built with `%s`, the application links %s\n' "${name}" "${package}" >&2
            failed=1
        fi
    done
    for package in ${allowed}; do
        if ! printf '%s\n' "${linked}" | grep -qx "${package}"; then
            printf 'error: built with `%s`, the application does not link %s\n' "${name}" "${package}" >&2
            failed=1
        fi
    done
    local count budget
    count="$(printf '%s\n' "${linked}" | grep -c .)"
    budget="$(budget_of "${selection}")"
    printf '    %s packages, of a budget of %s\n' "${count}" "${budget}"
    if [ "${count}" -gt "${budget}" ]; then
        printf 'error: built with `%s`, the application links %s packages, past its budget of %s\n' \
            "${name}" "${count}" "${budget}" >&2
        failed=1
    fi
    if [ "${failed}" -ne 0 ]; then
        exit 1
    fi

    local output
    if ! output="$(cargo test --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" 2>&1)"; then
        printf '%s\n' "${output}" >&2
        printf 'error: the profile `%s` failed\n' "${name}" >&2
        exit 1
    fi
    # A profile that ran nothing proved nothing.
    if ! printf '%s\n' "${output}" | grep -Eq '^test result: ok\. [1-9][0-9]* passed'; then
        printf '%s\n' "${output}" >&2
        printf 'error: the profile `%s` ran no test\n' "${name}" >&2
        exit 1
    fi
}

# The most threads the reference application may hold under the one-worker profile: its own,
# one evaluating, one for storage and one for evidence, and two to spare. Measured at 2.
ONE_WORKER_THREADS=6

one_worker() {
    local selection="$1"
    printf '==> the reference application with `%s`, one worker\n' "${selection}"
    local report
    if ! report="$(cargo run --quiet --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" --example reference -- --one-worker 2>/dev/null)"; then
        printf '%s\n' "${report}" >&2
        printf 'error: with `%s`, the reference application failed under one worker\n' "${selection}" >&2
        exit 1
    fi
    local decisions threads
    decisions="$(printf '%s\n' "${report}" | awk -F '\t' '$1 == "decisions" { print $2 }')"
    threads="$(printf '%s\n' "${report}" | awk -F '\t' '$1 == "threads" { print $2 }')"
    printf '    %s decisions on %s threads, of a bound of %s\n' "${decisions:-0}" "${threads:-?}" "${ONE_WORKER_THREADS}"
    if [ "${decisions:-0}" -lt 1 ]; then
        printf 'error: with `%s`, the reference application decided nothing under one worker\n' "${selection}" >&2
        exit 1
    fi
    if [ -z "${threads}" ] || [ "${threads}" -lt 1 ] || [ "${threads}" -gt "${ONE_WORKER_THREADS}" ]; then
        printf 'error: with `%s`, one worker holds %s threads, past the bound of %s\n' \
            "${selection}" "${threads:-none counted}" "${ONE_WORKER_THREADS}" >&2
        exit 1
    fi
}

for selection in "" cedar rego dogwood "cedar,rego,dogwood"; do
    check "${selection}"
done
for selection in cedar rego; do
    one_worker "${selection}"
done

printf 'ok: the embedding application links and decides what each profile selects\n'
