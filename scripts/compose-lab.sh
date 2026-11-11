#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The Compose lab's gate (TD-3): start a profile, let the lab's authority enroll it, run what the
# profile must prove, tear it down. The same script, the same assertions, on Linux and on macOS.
#
#   scripts/compose-lab.sh [profile ...]
#
# With no profile, every one of them, in turn: all-in-one, split-plane, multi-data-plane,
# multi-group, temporal-replicas. Each runs as its own Compose project, `permguard-lab-<profile>`,
# with fresh volumes, so two profiles share nothing.
#
# It needs docker with Compose v2.24 or later. The lab image is built first (cached; NO_BUILD=1
# skips it, PERMGUARD_LAB_IMAGE names another). KEEP=1 leaves the last profile running; the logs
# of a failed profile are written under ARTIFACTS (default `target/compose-lab`). ROTATION=1 runs
# the all-in-one with keys replaced every two minutes (`docker-compose.lab.rotation.yml`) and proves
# its decisions keep reaching its Control Plane across the rotations (BUG-0195). Every all-in-one
# run also proves the Authority Plane: a service account, its key and scopes over HTTPS and gRPC, a
# token revoked and the token keys rotated.
set -euo pipefail

# Written for the bash macOS ships, 3.2: no negative indexes, no empty array expanded under `-u`.
all=(all-in-one split-plane multi-data-plane multi-group temporal-replicas)
if [ "$#" -gt 0 ]; then profiles=("$@"); else profiles=("${all[@]}"); fi
last="${profiles[$((${#profiles[@]} - 1))]}"
for profile in "${profiles[@]}"; do
    case " ${all[*]} " in
    *" ${profile} "*) ;;
    *)
        echo "compose-lab: no profile ${profile}; one of: ${all[*]}" >&2
        exit 64
        ;;
    esac
done

command -v docker >/dev/null || {
    echo "compose-lab: docker is required" >&2
    exit 2
}
cd "$(git rev-parse --show-toplevel)"
export PERMGUARD_LAB_IMAGE="${PERMGUARD_LAB_IMAGE:-permguard/lab:local}"
artifacts="${ARTIFACTS:-target/compose-lab}"
mkdir -p "${artifacts}"

step() { printf '\n== %s\n' "$*"; }

if [ "${NO_BUILD:-0}" != 1 ]; then
    step "the lab image, ${PERMGUARD_LAB_IMAGE}"
    docker build -f lab/compose/Dockerfile -t "${PERMGUARD_LAB_IMAGE}" .
fi

run_profile() {
    local profile="$1" project="permguard-lab-$1"
    local files=(-f docker-compose.lab.yml)
    if [ "${ROTATION:-0}" = 1 ] && [ "${profile}" = all-in-one ]; then
        files+=(-f docker-compose.lab.rotation.yml)
    fi
    dc() { COMPOSE_PROFILES="${profile}" docker compose "${files[@]}" -p "${project}" "$@"; }
    failed() {
        dc ps -a >"${artifacts}/${profile}.ps" 2>&1 || true
        dc logs --no-color --timestamps >"${artifacts}/${profile}.log" 2>&1 || true
        echo "FAIL: ${profile}: $* (logs in ${artifacts}/${profile}.log)" >&2
        # The lab's authority first, then whatever a Host refused: the lines that say why.
        dc logs --no-color lab-pki lab-catalog lab-enroll 2>/dev/null | tail -n 20 >&2 || true
        grep -v -e '"level":"INFO"' -e '^lab-' "${artifacts}/${profile}.log" | tail -n 20 >&2 || true
        [ "${KEEP:-0}" = 1 ] || dc down -v --remove-orphans >/dev/null 2>&1 || true
        exit 1
    }

    # Whether one-shot `job` exited 0, waiting for it to exit: read from the engine rather than
    # `docker compose wait`, whose answer for a container that already exited differs by version.
    finished() {
        local container state code deadline=$((SECONDS + 900))
        container="$(dc ps -a -q "$1")"
        [ -n "${container}" ] || return 1
        while :; do
            state="$(docker inspect -f '{{.State.Status}}' "${container}")"
            [ "${state}" = exited ] && break
            [ "${SECONDS}" -lt "${deadline}" ] || return 1
            sleep 2
        done
        code="$(docker inspect -f '{{.State.ExitCode}}' "${container}")"
        [ "${code}" = 0 ]
    }

    step "${profile}: a fresh project, ${project}"
    dc down -v --remove-orphans >/dev/null 2>&1 || true
    dc up -d 2>/dev/null || failed "the profile did not start"
    # The one-shot services are the lab's authority: each must have finished, and cleanly.
    local jobs=(lab-pki lab-catalog)
    [ "${profile}" = all-in-one ] || jobs+=(lab-enroll)
    for job in "${jobs[@]}"; do
        finished "${job}" || failed "${job} did not finish cleanly"
    done
    dc logs --no-color lab-catalog lab-enroll 2>/dev/null | sed -n 's/^[^|]*| //p' || true

    step "${profile}: what it must prove"
    dc run --rm lab assert "${profile}" || failed "an assertion failed"
    if [ "${ROTATION:-0}" = 1 ] && [ "${profile}" = all-in-one ]; then
        step "${profile}: decisions across key rotations"
        dc run --rm lab assert "${profile}" rotation || failed "an assertion failed across rotations"
    fi
    if [ "${profile}" = all-in-one ]; then
        step "${profile}: service accounts, keys and tokens of the Authority Plane"
        dc run --rm lab assert "${profile}" authority || failed "an Authority Plane assertion failed"
    fi
    if [ "${profile}" = multi-data-plane ]; then
        step "${profile}: decisions by the Authority Plane's tokens"
        dc run --rm lab assert "${profile}" tokens || failed "a token assertion failed"
        step "${profile}: evaluation latency with token verification on (WP-14.1)"
        dc run --rm -e "LAB_P99_OBJECTIVE_MS=$(jq -r '.p99_ms.required' bench/slo.json)" lab assert "${profile}" latency ||
            failed "the evaluation latency passed its objective"
        step "${profile}: the Authority Plane rotates its token key, the members follow (WP-12.6)"
        dc run --rm lab assert "${profile}" rotation || failed "a member did not follow the token key's rotation"
        step "${profile}: the Control Plane stopped, the members decide on what they hold"
        dc stop control-plane >/dev/null 2>&1 || failed "the Control Plane did not stop"
        dc run --rm lab assert "${profile}" offline || failed "a member stopped deciding without its Control Plane"
    fi
    if [ "${profile}" = temporal-replicas ]; then
        step "${profile}: failover, the first replica stopped"
        dc stop temporal-a >/dev/null 2>&1
        dc run --rm lab assert "${profile}" failover || failed "an assertion failed after failover"
    fi

    if [ "${KEEP:-0}" = 1 ] && [ "${profile}" = "${last}" ]; then
        echo "kept: COMPOSE_PROFILES=${profile} docker compose -f docker-compose.lab.yml -p ${project} …"
    else
        dc down -v --remove-orphans >/dev/null 2>&1
    fi
    echo "ok: ${profile}"
}

for profile in "${profiles[@]}"; do
    run_profile "${profile}"
done
printf '\nok: compose-lab (%s)\n' "${profiles[*]}"
