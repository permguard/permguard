#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The storage takeover qualification gate (TD-2, H-05): kill the active replica during writes and
# prove that its successor writes only after the old writer is gone and that recovery finds no
# stale-writer frame.
#
#   scripts/chart-takeover.sh [image] [record]
#
# `image` is a data plane image (default `permguard/data-plane:e2e`); `record` is where the
# qualification record is written (default `takeover-qualification.json`), the `evidence` a group's
# `persistence.takeover` names. On a disposable kind cluster by default; with KUBECONFIG and
# NO_KIND=1 against the cluster and the STORAGE_CLASS being qualified.
#
# Each round force-deletes the replica's Pod while its server is starting — opening its identity,
# its key rings, its audit trail and its streams, writing all of them — and waits for the successor:
#
#   the successor's claim init container moves the claim strictly forward, and only once the old
#     writer released the volume (an attempt beside it fails on the volume's lock and is retried)
#   the successor starts, so recovery refused nothing: no stale-writer frame, no claim behind data
#
# After the rounds the replica is stopped and `volume verify` checks every journal of the volume
# frame by frame, offline.
#
# What it does not prove, and the record says so (`scope`): it kills the Pod, not the node, and on
# one node the successor is held off by the volume's advisory lock on the same filesystem, which
# exists on no other node and through no CSI attach. Provider fencing — the storage revoking a lost
# node's writer before it attaches the successor — is proven only on that storage, by stopping and
# partitioning the replica's node in a multi-node cluster, which this script does not do.
set -euo pipefail

image="${1:-permguard/data-plane:e2e}"
record="${2:-takeover-qualification.json}"
rounds="${ROUNDS:-6}"
cluster="${CLUSTER:-permguard-takeover}"
namespace=permguard
release=pg
group=takeover
workload="${release}-permguard-data-plane-${group}"
storage_class="${STORAGE_CLASS:-standard}"

for tool in kubectl helm jq; do
    command -v "${tool}" >/dev/null || { echo "chart-takeover: ${tool} is required" >&2; exit 2; }
done
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

if [ "${NO_KIND:-0}" != "1" ]; then
    command -v kind >/dev/null || { echo "chart-takeover: kind is required" >&2; exit 2; }
    cleanup() { if [ "${KEEP:-0}" != "1" ]; then kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true; fi; }
    trap cleanup EXIT
    step "a disposable cluster, ${cluster}"
    kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
    kind create cluster --name "${cluster}" --wait 120s
    kind load docker-image "${image}" --name "${cluster}"
fi
kubectl create namespace "${namespace}" 2>/dev/null || true

values="$(mktemp)"
cat >"${values}" <<EOF
developmentMode: true
autogenerate: true
controlPlane: { enabled: false }
image: { registry: "", pullPolicy: IfNotPresent, tag: "${image##*:}" }
dataPlane:
  repository: "${image%:*}"
  groups:
    - name: ${group}
      selector: plane/data/*
      replicas: 1
      assurance: { profile: development }
      evidence: { mode: required }
      persistence: { enabled: true, size: 64Mi, storageClass: "${storage_class}" }
      podDisruptionBudget: { enabled: false }
      extraConfig:
        operations:
          keys: { enabled: "true", publish_ahead: 5m, rotate_every: 1h, retain: 1d }
          secrets: { provider: directory, coordinator_root_ref: zone-root }
          audit: { pseudonym: { enabled: true, key_ref: audit-pseudonym, key_version: "v1" } }
EOF

step "one replica that keeps evidence"
helm install "${release}" charts/permguard --namespace "${namespace}" --values "${values}" --wait --timeout 5m
kubectl --namespace "${namespace}" rollout status "statefulset/${workload}" --timeout 300s

generation() {
    kubectl --namespace "${namespace}" logs "${workload}-0" -c claim |
        sed -n 's/.*is claimed at generation \([0-9]*\).*/\1/p' | tail -1
}
last="$(generation)"
[ -n "${last}" ] || fail "the first start claimed no generation"
echo "claimed at generation ${last}"
generations="${last}"
retries=0

for round in $(seq "${rounds}"); do
    step "round ${round}: kill the replica while it starts and writes"
    # The server opens and writes its volume in its first seconds: kill it inside them.
    kubectl --namespace "${namespace}" delete pod "${workload}-0" --wait=false >/dev/null
    kubectl --namespace "${namespace}" wait --for=condition=Initialized "pod/${workload}-0" --timeout 180s >/dev/null 2>&1 || true
    sleep "0.$((RANDOM % 9 + 1))"
    kubectl --namespace "${namespace}" delete pod "${workload}-0" --grace-period=0 --force >/dev/null 2>&1 || true
    kubectl --namespace "${namespace}" rollout status "statefulset/${workload}" --timeout 300s >/dev/null
    kubectl --namespace "${namespace}" wait --for=condition=Ready "pod/${workload}-0" --timeout 300s >/dev/null
    now="$(generation)"
    [ -n "${now}" ] && [ "${now}" -gt "${last}" ] ||
        fail "round ${round}: the successor's claim ${now:-none} did not move past ${last}"
    restarts="$(kubectl --namespace "${namespace}" get pod "${workload}-0" -o jsonpath='{.status.initContainerStatuses[0].restartCount}')"
    retries=$((retries + ${restarts:-0}))
    served="$(kubectl --namespace "${namespace}" logs "${workload}-0" -c data-plane 2>/dev/null || true)"
    if grep -Eiq 'stale_writer|stale writer|claim_behind_data' <<<"${served}"; then
        fail "round ${round}: recovery reported a stale writer"
    fi
    echo "successor claimed generation ${now} (claim attempts beside the old writer: ${restarts:-0})"
    generations="${generations},${now}"
    last="${now}"
done

step "stop the replica and verify its volume offline"
kubectl --namespace "${namespace}" scale "statefulset/${workload}" --replicas 0
kubectl --namespace "${namespace}" wait --for=delete "pod/${workload}-0" --timeout 180s
cat <<EOF | kubectl --namespace "${namespace}" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: verify-${group}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532 }
      containers:
        - name: verify
          image: ${image}
          imagePullPolicy: IfNotPresent
          args: ["volume", "verify", "--volume", "/var/lib/permguard/volume"]
          volumeMounts: [{ name: state, mountPath: /var/lib/permguard }]
      volumes:
        - name: state
          persistentVolumeClaim: { claimName: state-${workload}-0 }
EOF
if ! kubectl --namespace "${namespace}" wait --for=condition=Complete "job/verify-${group}" --timeout 300s; then
    kubectl --namespace "${namespace}" logs "job/verify-${group}" >&2 || true
    fail "volume verify found something on the volume"
fi
kubectl --namespace "${namespace}" logs "job/verify-${group}" | tail -5

nodes="$(kubectl get nodes -o name | wc -l | tr -d ' ')"
driver="$(kubectl get storageclass "${storage_class}" -o jsonpath='{.provisioner}')"
jq -n \
    --arg driver "${driver}" \
    --arg storage_class "${storage_class}" \
    --arg kubernetes "$(kubectl version -o json | jq -r '.serverVersion.gitVersion')" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson rounds "${rounds}" \
    --argjson nodes "${nodes}" \
    --argjson retries "${retries}" \
    --arg generations "${generations}" \
    '{gate: "storage takeover (TD-2, H-05)", at: $at, kubernetes: $kubernetes, driver: $driver,
      storageClass: $storage_class, nodes: $nodes, kill_rounds: $rounds,
      claim_generations: ($generations | split(",") | map(tonumber)),
      successor_claims_refused_beside_the_old_writer: $retries,
      stale_writer_frames: 0, volume_verify: "clean",
      scope: (if $nodes > 1 then "pod kill on a multi-node cluster; node kill and partition not run by this script" else "pod kill on one node: the volume lock, not provider fencing, serialized the successor" end),
      provider_fencing: "not proven by this run"}' >"${record}"
step "qualification record ${record}"
cat "${record}"
printf '\nok: chart-takeover\n'
