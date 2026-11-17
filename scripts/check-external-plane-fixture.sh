#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Builds and tests the server assembled outside the repository's workspace,
# `fixtures/external-plane`: a Plane the workspace does not know, registered beside the
# open-source Data Plane in a server built from the kit, `permguard-server` with no feature.
#
# The fixture is a workspace of its own, so Cargo resolves it alone: nothing a member of the
# repository's workspace selects can be unified into what it links, and it reaches nothing but
# the packages' public interfaces.
#
#   what it links     the server kit, the runtime and the open-source Plane it reuses; no command
#                     line, no argument parser, no OTLP exporter, and no other Plane's adapter
#   how much          no more packages than its budget: the count measured when it was last
#                     settled, with a margin of about five in a hundred
#   what it does      its Plane is served beside the open-source one and both stop in order
#
# The fixture's lockfile is the workspace's, copied before the run.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ROOT}/fixtures/external-plane"
MANIFEST="${FIXTURE}/Cargo.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target/external-fixture}"

# What the kit and a Plane's module do not bring, by library name as `cargo tree` prints it.
NEVER="clap opentelemetry opentelemetry_otlp opentelemetry_sdk tracing_opentelemetry permguard_cli
permguard_all_in_one permguard_control_plane permguard_control_plane_server
permguard_authority_plane_server permguard_embedded"

# What the composition is made of.
ALWAYS="permguard_server permguard_runtime permguard_transport permguard_host
permguard_data_plane_server permguard_data_plane"

# Measured on 2026-11-17 at 355.
BUDGET=373

printf '==> the server assembled outside the workspace\n'
cp "${ROOT}/Cargo.lock" "${FIXTURE}/Cargo.lock"

linked="$(cargo tree --color never --manifest-path "${MANIFEST}" --edges normal,build \
    --prefix none --format '{lib}' | sed 's/ (\*)$//' | sort -u)"

failed=0
for package in ${NEVER}; do
    if printf '%s\n' "${linked}" | grep -qx "${package}"; then
        printf 'error: the external server links %s\n' "${package}" >&2
        failed=1
    fi
done
for package in ${ALWAYS}; do
    if ! printf '%s\n' "${linked}" | grep -qx "${package}"; then
        printf 'error: the external server does not link %s\n' "${package}" >&2
        failed=1
    fi
done
count="$(printf '%s\n' "${linked}" | grep -c .)"
printf '    %s packages, of a budget of %s\n' "${count}" "${BUDGET}"
if [ "${count}" -gt "${BUDGET}" ]; then
    printf 'error: the external server links %s packages, past its budget of %s\n' \
        "${count}" "${BUDGET}" >&2
    failed=1
fi
if [ "${failed}" -ne 0 ]; then
    exit 1
fi

if ! output="$(cargo test --manifest-path "${MANIFEST}" 2>&1)"; then
    printf '%s\n' "${output}" >&2
    printf 'error: the external server failed\n' >&2
    exit 1
fi
# A run that tested nothing proved nothing.
if ! printf '%s\n' "${output}" | grep -Eq '^test result: ok\. [1-9][0-9]* passed'; then
    printf '%s\n' "${output}" >&2
    printf 'error: the external server ran no test\n' >&2
    exit 1
fi

printf 'ok: a Plane of another repository is served by the kit beside an open-source one\n'
