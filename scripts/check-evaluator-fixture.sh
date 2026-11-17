#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Builds and tests the reference application that embeds the evaluator alone,
# `fixtures/evaluator-application`, once per named profile, outside the repository's workspace.
#
# The application names `permguard-evaluator` with no default feature, a feature per language, and
# the evidence model of each kind of record it keeps. It is a workspace of its own, so Cargo
# resolves each profile for it alone: nothing another member selects can be unified into what it
# links.
#
# For every profile, read from `cargo tree` with no colour, since a coloured repeat marker is not
# the marker this strips and a package would be counted twice:
#
#   what it links     no Host, runtime, default implementation, ledger, mirror, synchronization,
#                     stream engine, Plane, server, listener, client, contract, TLS stack, argument
#                     parser or asynchronous runtime; no engine and no evidence model it did not
#                     select
#   how much          no more packages than the profile's budget: the count measured when the
#                     profile was last settled, with a margin of about five in a hundred
#   what it does      the fixture's tests of that profile pass, and at least one ran
#
# The fixture's lockfile is the workspace's, copied before each run: a profile is proven with the
# versions the repository ships, and there is no second lockfile to keep.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/fixtures/evaluator-application"
MANIFEST="${FIXTURE}/Cargo.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target/evaluator-fixture}"

# What no profile of the evaluator links, by library name as `cargo tree` prints it.
NEVER="permguard_host permguard_runtime permguard_std permguard_offline permguard_embedded
permguard_data_plane permguard_data_plane_server permguard_control_plane
permguard_control_plane_server permguard_authority_plane permguard_authority_plane_server
permguard_server permguard_transport permguard_telemetry permguard_client permguard_contracts
permguard_tls permguard_mirror permguard_sync permguard_notp permguard_stream permguard_languages
permguard_evaluation_worker axum tonic hyper tower_http opentelemetry rustls clap tokio"

# What each selection brings. Dogwood is its own package, validating, and no feature of the
# evaluator; it lowers to Cedar, so it links Cedar's upstream
# package; Permguard's own Cedar package it does not.
brings() {
    case "$1" in
        (cedar) printf 'permguard_language_cedar cedar_policy\n' ;;
        (rego) printf 'permguard_language_rego regorus\n' ;;
        (dogwood) printf 'permguard_language_dogwood dogwood_language cedar_policy\n' ;;
        (decisions) printf 'permguard_decisions\n' ;;
        (events) printf 'permguard_events\n' ;;
    esac
}

# Everything a selection can bring: what a profile that did not select it may not link.
SELECTABLE="permguard_language_cedar permguard_language_rego permguard_language_dogwood cedar_policy
regorus dogwood_language permguard_decisions permguard_events"

# The most packages a profile may link, the application counted: measured on 2026-11-17 at 60,
# 137, 167, 166, 138, 138 and 139.
budget_of() {
    case "$1" in
        ("") printf '63\n' ;;
        (cedar) printf '144\n' ;;
        (rego) printf '175\n' ;;
        (dogwood) printf '174\n' ;;
        (cedar,decisions | cedar,events) printf '145\n' ;;
        (cedar,decisions,events) printf '146\n' ;;
    esac
}

check() {
    local selection="$1"
    local name="${selection:-no language}"
    printf '==> the evaluator application built with `%s`\n' "${name}"

    cp "${ROOT}/Cargo.lock" "${FIXTURE}/Cargo.lock"

    local linked
    linked="$(cargo tree --color never --manifest-path "${MANIFEST}" --no-default-features \
        --features "${selection}" --edges normal,build --prefix none --format '{lib}' |
        sed 's/ (\*)$//' | sort -u)"

    local allowed=""
    local selected
    for selected in ${selection//,/ }; do
        allowed="${allowed} $(brings "${selected}")"
    done
    local forbidden="${NEVER}"
    local package
    for package in ${SELECTABLE}; do
        case " ${allowed} " in
            (*" ${package} "*) ;;
            (*) forbidden="${forbidden} ${package}" ;;
        esac
    done

    local failed=0
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

for selection in "" cedar rego dogwood "cedar,decisions" "cedar,events" "cedar,decisions,events"; do
    check "${selection}"
done

printf 'ok: the evaluator application links and decides what each profile selects\n'
