#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The restore drill (WP-7.7): a Data Plane loses its volume and comes back from its last backup,
# on the Compose lab's split-plane profile.
#
#   scripts/drill-restore.sh [record]
#
# `record` is where the drill's JSON record is written (default `drill-restore.json`). In turn:
#
#   the split-plane lab starts and proves what it always proves (`scripts/compose-lab.sh`)
#   an application-consistent backup of the Data Plane: prepare, the copy, finalize
#   decisions the backup does not hold, shipped to the coordinator
#   the Data Plane stops; its volume is lost and the snapshot put back, verified against its
#   manifest under the pinned identity; the lost Host is fenced and the snapshot restored in `dr`
#   the Data Plane starts: the same Host, memberships active, serving its ledger; the snapshot's run,
#   behind what the coordinator acknowledged, is fenced off by the coordinator, which takes none of
#   its records and keeps every one it acknowledged
#
# The record's `finding` names what the drill found and the procedure does not yet cover: a fenced
# run has no operator path to its approved successor, so shipping stays suspended.
#
# It needs what `scripts/compose-lab.sh` needs; NO_BUILD=1 and PERMGUARD_LAB_IMAGE work the same,
# and the logs of a failed drill are written under ARTIFACTS (default `target/compose-lab`).
set -euo pipefail

record="$(cd "$(dirname "${1:-drill-restore.json}")" && pwd)/$(basename "${1:-drill-restore.json}")"
cd "$(git rev-parse --show-toplevel)"
export PERMGUARD_LAB_IMAGE="${PERMGUARD_LAB_IMAGE:-permguard/lab:local}"
artifacts="${ARTIFACTS:-target/compose-lab}"
mkdir -p "${artifacts}"
project=permguard-lab-split-plane
data_volume="${project}_data-plane-state"

dc() { COMPOSE_PROFILES=split-plane docker compose -f docker-compose.lab.yml -p "${project}" "$@"; }
step() { printf '\n== %s\n' "$*"; }
failed() {
    dc logs --no-color --timestamps >"${artifacts}/drill-restore.log" 2>&1 || true
    echo "FAIL: drill-restore: $* (logs in ${artifacts}/drill-restore.log)" >&2
    grep -v -e '"level":"INFO"' -e '^lab-' "${artifacts}/drill-restore.log" | tail -n 20 >&2 || true
    [ "${KEEP:-0}" = 1 ] || dc down -v --remove-orphans >/dev/null 2>&1 || true
    exit 1
}
# However the drill ends, the lab comes down, unless KEEP=1 asks to look at it.
trap '[ "${KEEP:-0}" = 1 ] || dc down -v --remove-orphans >/dev/null 2>&1 || true' EXIT
healthy() { # service
    local container deadline=$((SECONDS + 300))
    container="$(dc ps -q "$1")"
    while [ "$(docker inspect -f '{{.State.Health.Status}}' "${container}" 2>/dev/null)" != healthy ]; do
        [ "${SECONDS}" -lt "${deadline}" ] || return 1
        sleep 2
    done
}

KEEP=1 scripts/compose-lab.sh split-plane

dc run --rm -v "${data_volume}:/drill/data-plane:ro" lab assert split-plane backup ||
    failed "the backup phase failed"

step "restore drill: the Data Plane stopped"
dc stop data-plane >/dev/null 2>&1
dc run --rm -v "${data_volume}:/var/lib/permguard" lab assert split-plane restore ||
    failed "the restore phase failed"

step "restore drill: the Data Plane started on the restored volume"
dc start data-plane >/dev/null 2>&1
healthy data-plane || failed "the restored Data Plane did not become healthy"
dc run --rm lab assert split-plane restored || failed "the restored phase failed"

result="$(dc run --rm --entrypoint cat lab /lab/state/drill/result.json)" || failed "no result"
jq -n --argjson result "${result}" --arg image "${PERMGUARD_LAB_IMAGE}" \
    --arg commit "$(git rev-parse HEAD)" \
    '{drill: "restore", mode: "dr", topology: "compose split-plane", commit: $commit, image: $image,
      result: "passed",
      backup: "application-consistent: prepare, copy inside the barrier, finalize; verified offline against its manifest, the exported bundle and the pinned identity",
      restored: $result,
      checks: ["the same host_id and identity, restored as a new incarnation (previous_boot_id recorded)",
               "memberships active after the restore, pinning the coordinator",
               "the ledger served: a permit and a deny, each recorded",
               "the snapshot run, behind the coordinator, fenced off: none of its records taken, every acknowledged record kept, the shipping membership suspended",
               "volume verify: 0 findings"],
      finding: $result.finding}' >"${record}"
# The restore is proven; shipping after it is not, and the record says why (status.md, WP-7.7).
echo "::warning title=drill-restore finding::$(jq -r .finding <<<"${result}")"
echo "ok: drill-restore (${record})"
