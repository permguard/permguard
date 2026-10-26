#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The drain controller on a real cluster (TD-2), on kind.
#
#   scripts/chart-reclaim-e2e.sh [data-plane image] [control-plane image] [cli image]
#
# Defaults `permguard/{data-plane,control-plane,cli}:e2e`, built from the repository's Dockerfile
# with PACKAGE and BIN. A control plane and one group of two replicas that keep evidence, each with
# its Host listener (mutual TLS from Secrets this script mints), and the drain controller's CronJob
# every minute. The group scales `2 → 1`, and each step is named as it runs:
#
#   the controller creates a fenced drain Job for the retained claim
#   the drain Job claims a new generation, recovers and prints a signed drain receipt
#   a receipt the coordinator cannot vouch for keeps the claim (it holds no membership of the replica)
#   a forced timeout never deletes an evidence claim (the Job held by an unschedulable Pod until
#     its deadline ends it; the controller keeps the claim and the Job)
#
# It needs docker, kind, kubectl, helm, jq and openssl. The cluster is deleted at the end unless
# KEEP=1.
set -euo pipefail

data_plane="${1:-permguard/data-plane:e2e}"
control_plane="${2:-permguard/control-plane:e2e}"
cli="${3:-permguard/cli:e2e}"
cluster="${CLUSTER:-permguard-reclaim}"
namespace=permguard
release=pg
group=e2e
workload="${release}-permguard-data-plane-${group}"
claim="state-${workload}-1"
job="${workload}-drain-1"

for tool in docker kind kubectl helm jq openssl; do
    command -v "${tool}" >/dev/null || { echo "chart-reclaim-e2e: ${tool} is required" >&2; exit 2; }
done
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
k() { kubectl --namespace "${namespace}" "$@"; }
# A log read whole before it is searched: `grep -q` on a pipe would end `kubectl logs` early, and
# under `pipefail` a match would read as a failure.
log_of() { k logs "$@" 2>/dev/null || true; }

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true; rm -f "${TMPDIR:-/tmp}/kubeconfig-${cluster}"; fi
}
trap cleanup EXIT

step "a disposable cluster, ${cluster}"
# The disposable cluster's own kubeconfig: the caller's, and its current context, are left as they are.
export KUBECONFIG="${TMPDIR:-/tmp}/kubeconfig-${cluster}"
echo "kubeconfig ${KUBECONFIG}"
kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
kind create cluster --name "${cluster}" --wait 120s
for image in "${data_plane}" "${control_plane}" "${cli}"; do
    kind load docker-image "${image}" --name "${cluster}"
done
k create namespace "${namespace}" >/dev/null 2>&1 || kubectl create namespace "${namespace}"

step "a private authority, the Host listeners' certificates and the controller's"
pki="$(mktemp -d)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=permguard-e2e-ca" -keyout "${pki}/ca.key" -out "${pki}/ca.crt" 2>/dev/null
issue() { # name, subject, SANs, usage
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=$2" -keyout "${pki}/$1.key" -out "${pki}/$1.csr" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" >"${pki}/$1.ext"
    openssl x509 -req -in "${pki}/$1.csr" -CA "${pki}/ca.crt" -CAkey "${pki}/ca.key" \
        -CAcreateserial -days 2 -extfile "${pki}/$1.ext" -out "${pki}/$1.crt" 2>/dev/null
    k create secret generic "$1" --type=kubernetes.io/tls \
        --from-file=tls.crt="${pki}/$1.crt" --from-file=tls.key="${pki}/$1.key" \
        --from-file=ca.crt="${pki}/ca.crt" >/dev/null
}
issue control-plane-host "${release}-permguard-control-plane-host" \
    "DNS:${release}-permguard-control-plane-host,DNS:${release}-permguard-control-plane-host.${namespace}.svc,DNS:${release}-permguard-control-plane-host.${namespace}.svc.cluster.local" \
    "serverAuth,clientAuth"
issue data-plane-host "${workload}" \
    "DNS:*.${workload}-headless.${namespace}.svc.cluster.local,DNS:*.${workload}-headless" \
    "serverAuth,clientAuth"
issue reclaim-operator "reclaim" "URI:spiffe://permguard-e2e/reclaim" "clientAuth"

values="$(mktemp)"
cat >"${values}" <<EOF
developmentMode: true
autogenerate: true
image: { registry: "", pullPolicy: IfNotPresent, tag: e2e }
controlPlane:
  repository: "${control_plane%:*}"
  assurance: { profile: development }
  hostListener: { enabled: true, tls: { secretName: control-plane-host } }
  # A lab-only shortcut: the coordinator's memberships and frontiers are readable by anybody, so the
  # controller reaches its verdict without an operator grant. Never in a deployment.
  extraConfig:
    host:
      principals:
        - san_uri: spiffe://permguard-e2e/reclaim
      authz:
        public:
          - { operations: [membership.read], selector: host }
          - { operations: [streams.read], selector: "plane/data/*" }
dataPlane:
  repository: "${data_plane%:*}"
  hostListener: { enabled: true, tls: { secretName: data-plane-host } }
  drainController:
    enabled: true
    repository: "${cli%:*}"
    schedule: "* * * * *"
    jobDeadlineSeconds: 90
    tls: { secretName: reclaim-operator }
  groups:
    - name: ${group}
      selector: plane/data/*
      replicas: 2
      assurance: { profile: development }
      evidence: { mode: required }
      persistence: { enabled: true, size: 64Mi }
      extraConfig:
        operations:
          keys: { enabled: "true", publish_ahead: 5m, rotate_every: 1h, retain: 1d }
          secrets: { provider: directory, coordinator_root_ref: zone-root }
          audit: { pseudonym: { enabled: true, key_ref: audit-pseudonym, key_version: "v1" } }
EOF

step "a control plane and a group of two replicas that keep evidence"
helm install "${release}" charts/permguard --namespace "${namespace}" --values "${values}" --wait --timeout 6m
k rollout status "statefulset/${workload}" --timeout 300s

step "the controller creates a fenced drain Job for the retained claim"
k scale "statefulset/${workload}" --replicas 1
k wait --for=delete "pod/${workload}-1" --timeout 180s
for _ in $(seq 60); do k get job "${job}" >/dev/null 2>&1 && break; sleep 5; done
k get job "${job}" >/dev/null || fail "no drain Job ${job} after five minutes"
echo "drain Job ${job} created"

step "the drain Job claims a new generation, recovers and prints a signed drain receipt"
k wait --for=condition=Complete "job/${job}" --timeout 300s || {
    k logs "job/${job}" --all-containers >&2 || true
    fail "the drain Job did not complete"
}
claimed="$(log_of "job/${job}" -c claim)"
grep "is claimed at generation" <<<"${claimed}" || fail "the Job claimed no generation"
grep -q '^{"drain_receipt"' <<<"$(log_of "job/${job}" -c data-plane)" || fail "the Job printed no receipt"
echo "the receipt is printed"

step "a receipt the coordinator cannot vouch for keeps the claim"
# The coordinator holds no membership of this replica: nothing pins the identity the receipt names.
for _ in $(seq 24); do
    pass="$(k get pods -l app.kubernetes.io/component=drain-controller --sort-by=.metadata.creationTimestamp -o name | tail -1)"
    [ -n "${pass}" ] && grep -q "\"claim\":\"${claim}\".*\"outcome\":\"kept\"" <<<"$(log_of "${pass}")" && break
    sleep 5
done
reported="$(log_of "${pass}" | grep "\"claim\":\"${claim}\"" || true)"
[ -n "${reported}" ] || fail "the controller reported nothing for ${claim}"
echo "${reported}"
grep "\"outcome\":\"kept\"" <<<"${reported}" | grep -q "holds no membership" ||
    fail "the controller did not keep ${claim} for the missing membership"
k get pvc "${claim}" >/dev/null || fail "${claim} was deleted"
echo "${claim} kept"

step "a forced timeout never deletes an evidence claim"
# The next drain Job cannot be scheduled: its deadline ends it, which is a forced timeout.
k delete job "${job}" --wait=true >/dev/null
template="$(k get configmap "${workload}-drain-job" -o jsonpath='{.data.job\.json}')"
held="$(jq -c '.spec.template.spec.nodeSelector = {"permguard.com/none": "true"}' <<<"${template}")"
k create configmap "${workload}-drain-job" --from-literal=job.json="${held}" --dry-run=client -o yaml | k apply -f - >/dev/null
for _ in $(seq 60); do k get job "${job}" >/dev/null 2>&1 && break; sleep 5; done
k wait --for=condition=Failed "job/${job}" --timeout 300s >/dev/null || fail "the held Job did not fail"
reason="$(k get job "${job}" -o jsonpath='{.status.conditions[?(@.type=="Failed")].reason}')"
echo "the drain Job failed: ${reason}"
[ "${reason}" = "DeadlineExceeded" ] || fail "the Job failed for ${reason}, not its deadline"
for _ in $(seq 24); do
    pass="$(k get pods -l app.kubernetes.io/component=drain-controller --sort-by=.metadata.creationTimestamp -o name | tail -1)"
    grep -q "DeadlineExceeded" <<<"$(log_of "${pass}")" && break
    sleep 5
done
reported="$(log_of "${pass}" | grep "\"claim\":\"${claim}\"" || true)"
echo "${reported}"
grep -q "never authorizes" <<<"${reported}" || fail "the controller did not report the forced timeout"
k get pvc "${claim}" >/dev/null || fail "${claim} was deleted after a forced timeout"
k get job "${job}" >/dev/null || fail "the failed Job was deleted"
echo "${claim} and the failed Job kept"

printf '\nok: chart-reclaim-e2e\n'
