#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The split-brain drill (WP-7.7, H-05): the successor of a Host cannot write until fencing
# completes.
#
#   scripts/drill-split-brain.sh <server-binary> [record]
#
# `server-binary` is a `permguard-all-in-one` (or a Plane binary: the volume rules are the Host's);
# `record` is where the drill's JSON record is written (default `drill-split-brain.json`). On one
# volume, in turn:
#
#   a predecessor starts and writes: it claims the volume and records its identity and audit
#   a successor started beside it is refused before it writes: the volume's lock is held
#   a claim moved beside it is refused: the claim never moves while a holder runs
#   the predecessor stops; the claim moves forward; the successor starts and writes
#   the successor stops; `volume verify` reads every journal frame by frame: no stale writer
#
# What it does not prove, and the record says so (`scope`): both processes share one machine and
# one filesystem, where the lock reaches the successor. A storage that attaches a lost node's
# volume to another node must revoke the lost writer itself; that is proven only on that storage,
# as `scripts/chart-takeover.sh` records.

set -euo pipefail

server="${1:?usage: scripts/drill-split-brain.sh <server-binary> [record]}"
record="${2:-drill-split-brain.json}"
work="$(mktemp -d)"
predecessor=""
successor=""
cleanup() {
    for pid in "${predecessor}" "${successor}"; do
        if [ -n "${pid}" ]; then kill "${pid}" 2>/dev/null || true; fi
    done
    rm -rf "${work}"
}
trap cleanup EXIT

port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
volume="${work}/volume"
mkdir -p "${volume}"

# A Host with no Plane: the volume's claim, its lock, its identity and its audit are the Host's.
configure() { # name, port
    printf 'working_dir: %s\ndevelopment_mode: true\nautogenerate: true\nassurance: { profile: development }\nlog: { level: info, format: json }\nhost: { addr: "127.0.0.1:%s" }\nruntime: { planes: [] }\n' \
        "${volume}" "$2" >"${work}/$1.yml"
}
ready() { # port, pid
    local deadline=$((SECONDS + 60))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        curl -fsS -o /dev/null "http://127.0.0.1:$1/readyz" 2>/dev/null && return 0
        kill -0 "$2" 2>/dev/null || return 1
        sleep 0.25
    done
    return 1
}
stop() { # pid
    kill -TERM "$1"
    wait "$1" 2>/dev/null || true
}
fail() {
    echo "drill-split-brain: $*" >&2
    exit 1
}

configure predecessor "$(port)"
configure successor "$(port)"
p_port="$(sed -n 's/.*addr: "127.0.0.1:\([0-9]*\)".*/\1/p' "${work}/predecessor.yml")"
s_port="$(sed -n 's/.*addr: "127.0.0.1:\([0-9]*\)".*/\1/p' "${work}/successor.yml")"

"${server}" volume claim --volume "${volume}" --generation 1 >/dev/null
env -u PERMGUARD_CONFIG "${server}" "${work}/predecessor.yml" >"${work}/predecessor.log" 2>&1 &
predecessor=$!
ready "${p_port}" "${predecessor}" || fail "the predecessor did not start: $(tail -5 "${work}/predecessor.log")"

# Beside a running holder: the successor is refused before it writes anything.
successor_refused=false
if env -u PERMGUARD_CONFIG "${server}" "${work}/successor.yml" >"${work}/beside.log" 2>&1; then
    fail "a successor started beside its predecessor"
fi
grep -q "held by another process" "${work}/beside.log" && successor_refused=true
"${successor_refused}" || fail "the successor failed for another reason: $(tail -3 "${work}/beside.log")"
grep -q '"volume.claimed"' "${work}/beside.log" && fail "the refused successor claimed the volume"

claim_refused=false
if "${server}" volume claim --volume "${volume}" --generation 2 >"${work}/claim-beside.log" 2>&1; then
    fail "the claim moved beside its holder"
fi
grep -q "held by another process" "${work}/claim-beside.log" && claim_refused=true
"${claim_refused}" || fail "the claim failed for another reason: $(tail -3 "${work}/claim-beside.log")"

# Fencing completes: the predecessor stops, the claim moves forward, and only then the successor writes.
stop "${predecessor}"
predecessor=""
"${server}" volume claim --volume "${volume}" --generation 2 >/dev/null
env -u PERMGUARD_CONFIG "${server}" "${work}/successor.yml" >"${work}/successor.log" 2>&1 &
successor=$!
ready "${s_port}" "${successor}" || fail "the successor did not start after the fence: $(tail -5 "${work}/successor.log")"
successor_served=true
stop "${successor}"
successor=""

verify="$("${server}" volume verify --volume "${volume}" 2>&1)" || fail "volume verify found: ${verify}"
findings="$(sed -n 's/.* \([0-9][0-9]*\) findings.*/\1/p' <<<"${verify}" | tail -1)"
[ "${findings}" = 0 ] || fail "volume verify: ${verify}"

jq -n --arg version "$("${server}" --version 2>/dev/null | head -1)" \
    --argjson successor_refused "${successor_refused}" --argjson claim_refused "${claim_refused}" \
    --argjson successor_served "${successor_served}" --argjson findings "${findings}" \
    '{drill: "split-brain", requirement: "H-05: the successor cannot write until fencing completes",
      binary: $version, result: "passed",
      successor_refused_beside_predecessor: $successor_refused,
      claim_refused_beside_holder: $claim_refused,
      successor_served_after_fence: $successor_served,
      volume_verify_findings: $findings,
      scope: "one machine and one filesystem, where the volume lock reaches the successor; provider fencing of a lost node is not proven by this run"}' \
    >"${record}"
echo "ok: drill-split-brain (${record})"
