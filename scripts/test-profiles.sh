#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Runs the packages whose features select what a build carries, in every profile, each resolved
# on its own: the policy languages, the client library's surfaces and transports, the two
# evidence models, the headless runtime with the offline package it links, and the reference
# applications, the embedded Data Plane's, the evaluator's and the native composition's, which are
# built outside the workspace.
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
# So are its capabilities: the evaluator alone with no feature, then the local ledger, the round,
# each evidence, and every combination of them.
for selection in "" cedar rego dogwood local-ledger sync decision-evidence event-evidence \
    "sync,decision-evidence" "sync,event-evidence" "decision-evidence,event-evidence" \
    "sync,decision-evidence,event-evidence" "cedar,rego,dogwood,sync,decision-evidence,event-evidence"; do
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

# The evidence models: the normative record, chain and envelope with no feature, then each runtime
# half alone. Their tests run with both halves.
for package in permguard-decisions permguard-events; do
    for selection in "" storage stream; do
        printf '==> %s built with `%s`\n' "${package}" "${selection}"
        cargo check --locked -p "${package}" --no-default-features --features "${selection}"
    done
    run "${package}, the model with its storage and its registration" -p "${package}"
done
# A decision record's answer from an evaluator's, with the model and no Host.
printf '==> permguard-decisions built with `evaluator`\n'
cargo check --locked -p permguard-decisions --no-default-features --features evaluator

# Offline volume administration: a remote custody is an adapter a build selects. Without one, the
# package builds with no network client and refuses that custody by name, which its test proves;
# the headless runtime links it that way, and its own tests start a Host with no server.
run "permguard-offline, no remote custody" -p permguard-offline
printf '==> permguard-offline built with `kms`\n'
cargo check --locked -p permguard-offline --features kms
run "permguard-runtime, headless" -p permguard-runtime

# The Data Plane embedded over a Host composed for it: by itself, with each language and with the
# adapter that fetches the Authority Plane's keys; its tests start a Host from a configuration file.
for selection in "" cedar rego dogwood sync decision-evidence event-evidence \
    "sync,decision-evidence,event-evidence" authority-refresh membership; do
    printf '==> permguard-embedded built with `%s`\n' "${selection}"
    cargo check --locked -p permguard-embedded --no-default-features --features "${selection}"
done
run "permguard-embedded, a Host composed for the application" -p permguard-embedded
run "permguard-evaluation-worker, the dedicated worker" -p permguard-evaluation-worker

# The embedded Data Plane as an application outside this workspace links it: every named profile
# resolved, built and tested for that application alone.
./scripts/check-embedded-fixture.sh

# The evaluator alone as an application outside this workspace links it: no language, each
# language, and each evidence model beside it, with no Host anywhere in the build.
./scripts/check-evaluator-fixture.sh

# The whole native composition as an application outside this workspace links it: a Host with no
# listener, a language, and the Data Plane's capabilities named or refused by name.
./scripts/check-native-fixture.sh

# The server kit: by itself, then with each thing a program owns beside it, and each Plane's
# adapter as a library over the kit alone.
for selection in "" cli signals authority-refresh otel kms "cli,signals,authority-refresh,otel,kms"; do
    printf '==> permguard-server built with `%s`\n' "${selection}"
    cargo check --locked -p permguard-server --no-default-features --features "${selection}"
done
for plane in authority control data; do
    printf '==> permguard-%s-plane-server, its module over the kit alone\n' "${plane}"
    cargo check --locked -p "permguard-${plane}-plane-server" --no-default-features --lib
done

# A server assembled outside this workspace from the kit: a Plane the workspace does not know
# beside an open-source one.
./scripts/check-external-plane-fixture.sh

printf 'ok: every profile compiles and passes its tests on its own\n'
