#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# A whole tour of Permguard from the command line, on a disposable all-in-one in Docker:
#
#   scripts/cli-tour.sh            the tour, then everything it made removed
#   KEEP=1 scripts/cli-tour.sh     the container and the workspace kept, to go on by hand
#
#   1. the all-in-one started              5. a zone, a ledger, the policies applied
#   2. the administrator's key             6. decisions asked
#   3. a service account, its scopes       7. the decisions read back from the control plane
#   4. its access key and its token        8. everything removed (unless KEEP=1)
#
# Needs Docker and the `permguard` CLI of the image's version (PG names another binary, a build of
# this checkout among them). The policies are this repository's examples/basics (EXAMPLE names
# another workspace). Ports 15443 to 18443 on 127.0.0.1, never a lab's.
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/permguard/permguard/all-in-one:0.1.26}"
PG="${PG:-permguard}"
EXAMPLE="${EXAMPLE:-$(cd "$(dirname "$0")/.." && pwd)/examples/basics}"
NAME="${NAME:-permguard-tour}"
WORK="${WORK:-$(mktemp -d -t permguard-tour)}"
HOST=https://127.0.0.1:15443       # Server Host, over TLS: discovery
HOST_API=https://127.0.0.1:15444   # Host API, over TLS: keys, memberships, lifecycle
CONTROL=http://127.0.0.1:16443     # control plane: zones, ledgers, policies, decision log
DATA=http://127.0.0.1:17443        # data plane: decisions
AUTHORITY=https://127.0.0.1:18443  # Authority Plane, over TLS: service accounts and tokens

step() { printf '\n== %s\n' "$*"; }
cleanup() {
    [ "${KEEP:-0}" = 1 ] && { echo "kept: container ${NAME}, workspace ${WORK}"; return; }
    docker rm -f "${NAME}" >/dev/null 2>&1 || true
    docker volume rm "${NAME}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------
step "1. the all-in-one, in Docker"
mkdir -p "${WORK}/config"
cat > "${WORK}/config/config.yml" <<'YAML'
development_mode: true
autogenerate: true
assurance: { profile: development }
log: { level: info, format: terminal }
host:
  addr: 0.0.0.0:5443
  tls: { cert: tls/server.pem, key: tls/server.key }
  authz:
    public:
      - operations: [catalog.read, catalog.write, policy.push, evidence.read]
        selector: "plane/control/*"
      - operations: [decision.evaluate, event.submit, streams.read]
        selector: "plane/data/*"
admin:
  addr: 0.0.0.0:5444
  # An access token is enough; a client certificate under the Host's authority too.
  tls: { cert: tls/server.pem, key: tls/server.key, client_ca: tls/ca.pem, client_auth: optional }
runtime: { planes: [authority, control, data] }
# The Authority Plane: its first start makes `admin`, its key in planes/authority/admin.key.
authority: { url: "https://127.0.0.1:18443" }
authorityPlane:
  public:
    http: { enabled: true, addr: 0.0.0.0:8443, tls: { cert: tls/server.pem, key: tls/server.key } }
    grpc: { enabled: true, addr: 0.0.0.0:8443, tls: { cert: tls/server.pem, key: tls/server.key } }
controlPlane:
  public:
    http: { enabled: true, addr: 0.0.0.0:6443 }
    grpc: { enabled: true, addr: 0.0.0.0:6443 }
  decisions: { enabled: "true", directory: data/decisions/store, retention: "7d" }
dataPlane:
  public:
    http: { enabled: true, addr: 0.0.0.0:7443 }
    grpc: { enabled: true, addr: 0.0.0.0:7443 }
  mirrors: { enabled: "true", interval: "2s" }
  decisions:
    log: { enabled: "true", mode: required, sample: { permits: "1.0" } }
operations:
  keys: { enabled: true, publish_ahead: 5m, rotate_every: 1h, retain: 1d }
  secrets: { provider: directory, coordinator_root_ref: zone-root }
  # The decision log carries subjects pseudonymised, never raw.
  audit:
    retention: 7d
    pseudonym: { enabled: true, key_ref: audit-pseudonym, key_version: "v1" }
YAML
docker volume create "${NAME}" >/dev/null
docker create --name "${NAME}" -v "${NAME}:/var/lib/permguard" \
    -p 127.0.0.1:15443:5443 -p 127.0.0.1:15444:5444 -p 127.0.0.1:16443:6443 -p 127.0.0.1:17443:7443 \
    -p 127.0.0.1:18443:8443 \
    -e PERMGUARD_CONTROL_HTTP_ADVERTISED_URL="${CONTROL}" \
    -e PERMGUARD_DATA_HTTP_ADVERTISED_URL="${DATA}" \
    -e PERMGUARD_AUTHORITY_HTTP_ADVERTISED_URL="${AUTHORITY}" \
    -e PERMGUARD_ADMIN_ADVERTISED_URL="${HOST_API}" \
    "${IMAGE}" /etc/permguard/config.yml >/dev/null
docker cp "${WORK}/config/." "${NAME}:/etc/permguard"
docker start "${NAME}" >/dev/null
# The authority the Host made for itself as it started: every TLS listener is checked against it.
for _ in $(seq 1 60); do docker cp "${NAME}:/var/lib/permguard/tls/ca.pem" "${WORK}/ca.pem" 2>/dev/null && break; sleep 1; done
CA=(--tls-ca-file "${WORK}/ca.pem")
for _ in $(seq 1 60); do "${PG}" "${CA[@]}" discover "${HOST}" >/dev/null 2>&1 && break; sleep 1; done
"${PG}" "${CA[@]}" discover "${HOST}"

# ---------------------------------------------------------------------------------------------
step "2. the administrator's key, which the Authority Plane wrote at its first start"
for _ in $(seq 1 60); do docker cp "${NAME}:/var/lib/permguard/planes/authority/admin.key" "${WORK}/admin.key" 2>/dev/null && break; sleep 1; done
chmod 0600 "${WORK}/admin.key"
# Every `authority` command below acts as `admin`: its token obtained with its key, over TLS.
authority() {
    "${PG}" "${CA[@]}" --authority-endpoint "${AUTHORITY}" --secret-key-file "${WORK}/admin.key" authority "$@"
}
authority service-accounts get admin

# ---------------------------------------------------------------------------------------------
step "3. a service account and its scopes"
authority service-accounts create billing --description "the billing service" \
    --scope 'decision.evaluate@plane/data/*'
authority scopes get billing
authority service-accounts list

# ---------------------------------------------------------------------------------------------
step "4. its access key, the secret written once and never printed, and a token"
authority keys create billing --secret-out "${WORK}/billing.key"
authority keys list billing
"${PG}" "${CA[@]}" --authority-endpoint "${AUTHORITY}" --secret-key-file "${WORK}/billing.key" \
    authority token --out "${WORK}/billing.jwt"
authority tokens list --account billing

# ---------------------------------------------------------------------------------------------
step "5. a zone, a ledger, and the basics workspace's policies applied to it"
"${PG}" --control-endpoint "${CONTROL}" zones create tour
"${PG}" --control-endpoint "${CONTROL}" ledgers create --zone tour basics
# The example's files only: a `.permguard/` left by an earlier run of it is not copied.
mkdir -p "${WORK}/basics"
(cd "${EXAMPLE}" && tar --exclude ./.permguard -cf - .) | (cd "${WORK}/basics" && tar -xf -)
# The workspace reaches the control plane through its remote `origin`, and asks the data plane
# named on `check`.
ws() { "${PG}" -w "${WORK}/basics" "$@"; }
# The data plane serves in the clear here, where no token travels: its decisions are public, a
# development convenience; over TLS billing's token would ask them.
check() { "${PG}" -w "${WORK}/basics" --data-endpoint "${DATA}" check "$@"; }
ws init basics --language cedar,rego
ws remote add origin "${CONTROL}"
ws validate
ws test
ws checkout origin/tour/basics
ws plan
ws apply -m "the basics policies"
ws verify
ws history
ws status

# ---------------------------------------------------------------------------------------------
step "6. decisions, once the data plane mirrored the ledger"
for _ in $(seq 1 30); do check -f requests/permit.json >/dev/null 2>&1 && break; sleep 2; done
check -f requests/permit.json
check -f requests/deny.json
check -f requests/gateway-permit.json

# ---------------------------------------------------------------------------------------------
step "7. the decisions, read back from the control plane"
sleep 5
"${PG}" --control-endpoint "${CONTROL}" decisions list --zone tour --ledger basics
"${PG}" --control-endpoint "${CONTROL}" decisions list --zone tour --ledger basics --decision deny

step "done"
