#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Runs the packages whose features select what a build carries, in every profile, each resolved
# on its own: the policy languages, and the client library's surfaces and transports.
#
# The workspace's tests run with every feature, which is one profile: all three languages,
# evaluating. A language is a feature of the catalogue and evaluating is another, so a build may
# carry one language, and may validate without evaluating, as the Control Plane's does. Cargo
# unifies features across whatever is built together, so those profiles are proven only by building
# them apart, which is what this does:
#
#   the catalogue, validating        every language, no `evaluate`: the Control Plane's profile
#   the catalogue, one language      validating, then evaluating: its golden vectors and corpora
#                                    pass with neither of the other engines in the build
#   each engine package              by itself, validating, then evaluating
#   the embedded Data Plane          built with no language, and with each one alone
#
# A profile fails when it does not compile, when a test of it fails, or when it runs no test.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

run() {
    local name="$1"
    shift
    printf '==> %s\n' "${name}"
    local output
    if ! output="$(cargo test --locked "$@" 2>&1)"; then
        printf '%s\n' "${output}" >&2
        printf 'error: the profile `%s` failed\n' "${name}" >&2
        exit 1
    fi
    # A profile that ran nothing proved nothing: every one of these has tests of its own.
    if ! printf '%s\n' "${output}" | grep -Eq '^test result: ok\. [1-9][0-9]* passed'; then
        printf '%s\n' "${output}" >&2
        printf 'error: the profile `%s` ran no test\n' "${name}" >&2
        exit 1
    fi
}

run "the catalogue, validating" -p permguard-languages
for language in cedar rego dogwood; do
    run "the catalogue, ${language} alone, validating" \
        -p permguard-languages --no-default-features --features "${language}"
    run "the catalogue, ${language} alone, evaluating" \
        -p permguard-languages --no-default-features --features "${language},evaluate"
    run "permguard-language-${language}, validating" -p "permguard-language-${language}"
    run "permguard-language-${language}, evaluating" \
        -p "permguard-language-${language}" --features evaluate
done

# The embedded Data Plane selects its languages too, none by default. Its tests always decide in
# every language, so what is proven here is that each selection compiles by itself; what it links
# is `dependency_direction.rs`'s to prove.
for selection in "" cedar rego dogwood; do
    printf '==> permguard-data-plane built with `%s`\n' "${selection}"
    cargo check --locked -p permguard-data-plane --no-default-features --features "${selection}"
done

# The client library: nothing by default, a feature per surface and per transport. Every surface
# over one transport alone, then each surface by itself over both; its tests run with them all.
surfaces="catalog,notp,decisions,events,pdp,temporal,host,authority,documents"
for selection in "" "http,${surfaces}" "grpc,${surfaces}"; do
    printf '==> permguard-client built with `%s`\n' "${selection}"
    cargo check --locked -p permguard-client --no-default-features --features "${selection}"
done
for surface in catalog notp decisions events pdp temporal host authority documents; do
    printf '==> permguard-client, `%s` alone\n' "${surface}"
    cargo check --locked -p permguard-client --no-default-features --features "http,grpc,${surface}"
done
run "permguard-client, every surface over both transports" -p permguard-client

printf 'ok: every profile compiles and passes its tests on its own\n'
