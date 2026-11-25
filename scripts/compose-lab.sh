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
# token revoked and the token keys rotated. BACKEND=postgresql-s3 runs the split-plane profile with
# its Control Plane on PostgreSQL and S3 (`docker-compose.lab.postgresql-s3.yml`, iteration 03,
# WP-28.1): the Data Plane on files, as always. Two Control Plane instances serve it behind one
# address (`docker-compose.lab.replicas.yml`, WP-28.6), and the profile is proved again with each
# of them stopped in turn; DRILLS=1 then runs the resilience drills on them (WP-29.1): the database
# stopped, answering nothing and restarted, S3 stopped, an instance killed while it rotates keys
# and revokes tokens, rotations and revocations at once on both, and a load. BACKEND=import runs it with its Control Plane on
# files first (`docker-compose.lab.import.yml`), stops it, imports its volume into PostgreSQL and
# S3 with `permguard migrate import`, serves it from there and proves the profile again. The
# all-in-one and the multi-data-plane prove the evidence freshness, from a decision's answer to its
# durable acknowledgement by the Control Plane (iteration 04): LAB_FRESHNESS_SAMPLES samples, six by
# default, the worst held to bench/slo.json's `freshness_ms`; LAB_FRESHNESS_P99_MS=0 only measures.
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
    case "${BACKEND:-files}" in
    files) ;;
    postgresql-s3 | import)
        [ "${profile}" = split-plane ] || {
            echo "compose-lab: BACKEND=${BACKEND} runs the split-plane profile alone" >&2
            exit 64
        }
        files+=(-f docker-compose.lab.postgresql-s3.yml)
        [ "${BACKEND}" != postgresql-s3 ] || files+=(-f docker-compose.lab.replicas.yml)
        ;;
    *)
        echo "compose-lab: no backend ${BACKEND}; one of files, postgresql-s3, import" >&2
        exit 64
        ;;
    esac
    # What serves after an import: the backend, without the phase on files before it.
    local served=("${files[@]}")
    [ "${BACKEND:-files}" != import ] || files+=(-f docker-compose.lab.import.yml)
    if [ "${ROTATION:-0}" = 1 ] && [ "${profile}" = all-in-one ]; then
        files+=(-f docker-compose.lab.rotation.yml)
    fi
    dc() { COMPOSE_PROFILES="${profile}" docker compose "${files[@]}" -p "${project}" "$@"; }
    dc_served() { COMPOSE_PROFILES="${profile}" docker compose "${served[@]}" -p "${project}" "$@"; }
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

    # Evidence freshness (iteration 04, WP-32.2): the worst sample held to the product's target
    # (bench/slo.json), `local_p99` for a Host to itself and `member_p99` for a member to its
    # coordinator, scaled as the latency is on an engine nested in a virtual machine.
    # LAB_FRESHNESS_P99_MS overrides it; `0` measures without gating.
    freshness() {
        local key objective
        key=member_p99
        [ "$1" != all-in-one ] || key=local_p99
        objective="${LAB_FRESHNESS_P99_MS:-$(jq -r --arg key "${key}" --arg scale "${LAB_P99_OBJECTIVE_SCALE:-1}" \
            '.freshness_ms[$key] * ($scale | tonumber) | floor' bench/slo.json)}"
        [ "${objective}" != 0 ] || objective=""
        dc run --rm -e "LAB_FRESHNESS_P99_MS=${objective}" \
            -e "LAB_FRESHNESS_SAMPLES=${LAB_FRESHNESS_SAMPLES:-6}" \
            -e "LAB_FRESHNESS_TIMEOUT=${LAB_FRESHNESS_TIMEOUT:-120}" lab assert "$1" freshness
    }

    # The resilience drills (WP-29.1): the servers stopped, paused and killed from here, what each
    # drill proves asserted from the lab's tools, its log under ARTIFACTS.
    run_drills() {
        drill() { dc run --rm lab assert "${profile}" "drill-$1" || failed "the drill $1 failed"; }
        postgres() { dc ps -q lab-postgres; }
        step "${profile}: resilience drills"
        drill before
        dc stop lab-postgres >/dev/null 2>&1 || failed "the database did not stop"
        drill database-down
        dc up -d --no-deps --wait lab-postgres >/dev/null 2>&1 || failed "the database did not start"
        drill database-back
        # Frozen: the process paused, its connections open and silent.
        docker pause "$(postgres)" >/dev/null || failed "the database was not paused"
        drill database-unanswering
        docker unpause "$(postgres)" >/dev/null || failed "the database was not unpaused"
        drill database-back
        # Cut: the database gone from the network the instances reach it on.
        docker network disconnect "${project}_default" "$(postgres)" >/dev/null ||
            failed "the database was not cut from the network"
        drill database-unanswering
        docker network connect --alias lab-postgres "${project}_default" "$(postgres)" >/dev/null ||
            failed "the database was not put back on the network"
        drill database-back
        dc restart lab-postgres >/dev/null 2>&1 || failed "the database did not restart"
        dc up -d --no-deps --wait lab-postgres >/dev/null 2>&1 || failed "the database did not answer again"
        drill database-back
        dc stop lab-s3 >/dev/null 2>&1 || failed "S3 did not stop"
        drill s3-down
        dc up -d --no-deps lab-s3 >/dev/null 2>&1 || failed "S3 did not start"
        drill s3-back
        # control-plane-2 killed while the churn rotates and revokes through it.
        dc run --rm lab assert "${profile}" drill-churn >"${artifacts}/drill-churn.log" 2>&1 &
        local churn=$!
        sleep 12
        docker kill "$(dc ps -q control-plane-2)" >/dev/null || failed "control-plane-2 was not killed"
        wait "${churn}" || failed "the churn failed (${artifacts}/drill-churn.log)"
        sed -n 's/^[^|]*| //p' "${artifacts}/drill-churn.log" | grep -v '^$' | tail -n 3 || true
        dc up -d --no-deps --wait control-plane-2 >/dev/null 2>&1 || failed "control-plane-2 did not serve again"
        drill churn-check
        drill concurrent
        drill load
        step "${profile}: what it must prove, after the drills"
        dc run --rm lab assert "${profile}" || failed "an assertion failed after the drills"
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
    if [ "${BACKEND:-files}" = postgresql-s3 ]; then
        step "${profile}: two Control Plane instances behind one address"
        dc run --rm lab assert "${profile}" replicas || failed "the instances are not one Control Plane"
        local instance
        for instance in control-plane control-plane-2; do
            step "${profile}: ${instance} stopped, the other instance serves"
            dc stop "${instance}" >/dev/null 2>&1 || failed "${instance} did not stop"
            dc run --rm lab assert "${profile}" || failed "an assertion failed with ${instance} stopped"
            dc up -d --no-deps --wait "${instance}" 2>/dev/null || failed "${instance} did not serve again"
        done
        if [ "${DRILLS:-0}" = 1 ]; then
            run_drills
        fi
    fi
    if [ "${BACKEND:-files}" = import ]; then
        step "${profile}: the Control Plane's volume imported into postgresql-s3"
        dc run --rm lab assert "${profile}" before-import || failed "the identity on files was not read"
        dc stop control-plane >/dev/null 2>&1 || failed "the Control Plane did not stop"
        dc_served run --rm --no-deps control-plane import permguard-control-plane \
            /opt/permguard/lab/control-plane.yml || failed "the import of the volume failed"
        dc_served up -d --no-deps --wait control-plane 2>/dev/null ||
            failed "the Control Plane did not serve from postgresql-s3"
        # Read whole first: `grep -q` stopping the pipe early would fail it under `pipefail`.
        local served_log
        served_log="$(dc_served logs --no-color control-plane 2>/dev/null)" || true
        grep -q '"storage.database_ready"' <<<"${served_log}" ||
            failed "the Control Plane did not open the database"
        step "${profile}: what it must prove, served from postgresql-s3"
        dc_served run --rm lab assert "${profile}" imported || failed "the imported identity differs"
        dc_served run --rm lab assert "${profile}" || failed "an assertion failed after the import"
        step "${profile}: the offline commands on postgresql-s3, the Control Plane stopped"
        dc_served stop control-plane >/dev/null 2>&1 || failed "the Control Plane did not stop"
        dc_served run --rm --no-deps control-plane offline permguard-control-plane \
            /opt/permguard/lab/control-plane.yml || failed "an offline command failed"
        dc_served up -d --no-deps --wait control-plane 2>/dev/null ||
            failed "the Control Plane did not serve again after the offline commands"
        dc_served run --rm lab assert "${profile}" imported || failed "the identity differs after a restart"
    fi
    if [ "${ROTATION:-0}" = 1 ] && [ "${profile}" = all-in-one ]; then
        step "${profile}: decisions across key rotations"
        dc run --rm lab assert "${profile}" rotation || failed "an assertion failed across rotations"
    fi
    if [ "${profile}" = all-in-one ]; then
        step "${profile}: service accounts, keys and tokens of the Authority Plane"
        dc run --rm lab assert "${profile}" authority || failed "an Authority Plane assertion failed"
        step "${profile}: evidence freshness to its own Control Plane (iteration 04)"
        freshness "${profile}" || failed "the evidence freshness passed its objective"
    fi
    if [ "${profile}" = multi-data-plane ]; then
        step "${profile}: decisions by the Authority Plane's tokens"
        dc run --rm lab assert "${profile}" tokens || failed "a token assertion failed"
        step "${profile}: evaluation latency with token verification on (WP-14.1)"
        # The objective is the product's (bench/slo.json), as stated on a Linux host. A job on an
        # engine nested in a virtual machine says so with LAB_P99_OBJECTIVE_SCALE, a multiple of
        # it, and the Linux job keeps proving the objective itself.
        objective="$(jq -r --arg scale "${LAB_P99_OBJECTIVE_SCALE:-1}" '.p99_ms.required * ($scale | tonumber)' bench/slo.json)"
        dc run --rm -e "LAB_P99_OBJECTIVE_MS=${objective}" lab assert "${profile}" latency ||
            failed "the evaluation latency passed its objective"
        step "${profile}: evidence freshness from a member to its coordinator (iteration 04)"
        freshness "${profile}" || failed "the evidence freshness passed its objective"
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
