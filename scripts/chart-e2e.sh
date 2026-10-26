#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The chart on a real cluster (TD-1): a data plane group scaled `3 → 1` and back, on kind.
#
#   scripts/chart-e2e.sh [image]
#
# `image` is a data plane image already built (default `permguard/data-plane:e2e`; build it with
# `docker build --build-arg PACKAGE=permguard-data-plane --build-arg BIN=permguard-data-plane
# -t permguard/data-plane:e2e .`). The script creates a disposable kind cluster, loads the image,
# installs one stateful group of three replicas, and proves, each step named as it runs:
#
#   every Pod start moves the volume's claim forward (the init container's claim: 1, then 2 for a new Pod)
#   every replica publishes its profile in discovery
#   scale 3 to 1 drains the removed replicas      (their `preStop` asked, they drained, no hook failed)
#   scale 3 to 1 retains every claim              (the three claims stay Bound)
#   scale back to 3 reattaches the same identities (each ordinal keeps its Host identity)
#   uninstalling keeps the claims
#   an upgrade from the single-group chart keeps its claim (LEGACY_REF, the last commit of that chart)
#
# It needs docker, kind, kubectl, helm and jq. The cluster is deleted at the end unless KEEP=1.
set -euo pipefail

image="${1:-permguard/data-plane:e2e}"
cluster="${CLUSTER:-permguard-e2e}"
namespace=permguard
release=pg
group=e2e
workload="${release}-permguard-data-plane-${group}"

for tool in docker kind kubectl helm jq; do
    command -v "${tool}" >/dev/null || { echo "chart-e2e: ${tool} is required" >&2; exit 2; }
done
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

step "a disposable cluster, ${cluster}"
kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
kind create cluster --name "${cluster}" --wait 120s
kind load docker-image "${image}" --name "${cluster}"
kubectl create namespace "${namespace}"

# The development profile and a stateful group: a volume per replica, no evidence material to
# supply, which is what this test needs — the claims, the drain and the identities, not shipping.
values="$(mktemp)"
cat >"${values}" <<EOF
developmentMode: true
autogenerate: true
controlPlane: { enabled: false }
image: { registry: "", pullPolicy: Never, tag: "${image##*:}" }
dataPlane:
  repository: "${image%:*}"
  groups:
    - name: ${group}
      selector: plane/data/*
      replicas: 3
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: true, size: 64Mi }
      shutdown: { timeoutSeconds: 20, drainTimeoutSeconds: 15 }
EOF

step "install one group of three replicas"
helm install "${release}" charts/permguard --namespace "${namespace}" --values "${values}" --wait --timeout 5m
kubectl --namespace "${namespace}" rollout status "statefulset/${workload}" --timeout 300s

# A pod that can reach the replicas by their stable names.
kubectl --namespace "${namespace}" run probe --image=curlimages/curl:8.17.0 --restart=Never --command -- sleep 3600
kubectl --namespace "${namespace}" wait --for=condition=Ready pod/probe --timeout 180s

discovery() {
    kubectl --namespace "${namespace}" exec probe -- \
        curl -fsS "http://${workload}-$1.${workload}-headless.${namespace}.svc.cluster.local:5443/.well-known/server-configuration"
}
identity() { discovery "$1" | jq -er '.host_id'; }

claim_of() { kubectl --namespace "${namespace}" logs "${workload}-$1" -c claim; }

step "every Pod start moves the volume's claim forward"
for ordinal in 0 1 2; do
    claim_of "${ordinal}" | grep -q "claimed at generation 1 (was 0)" ||
        fail "replica ${ordinal}: $(claim_of "${ordinal}")"
    echo "replica ${ordinal}: $(claim_of "${ordinal}")"
done

step "every replica publishes its profile in discovery"
declare -a before
for ordinal in 0 1 2; do
    document="$(discovery "${ordinal}")"
    profile="$(jq -er '.assurance.profile // .host.assurance.profile' <<<"${document}")"
    [ "${profile}" = development ] || fail "replica ${ordinal} publishes profile ${profile}"
    before[ordinal]="$(identity "${ordinal}")"
    echo "replica ${ordinal}: profile ${profile}, host ${before[ordinal]}"
done
[ "${before[0]}" != "${before[1]}" ] && [ "${before[1]}" != "${before[2]}" ] && [ "${before[0]}" != "${before[2]}" ] ||
    fail "the replicas share a Host identity"

step "scale 3 to 1 drains the removed replicas"
logs="$(mktemp -d)"
for ordinal in 1 2; do
    kubectl --namespace "${namespace}" logs --follow "${workload}-${ordinal}" >"${logs}/${ordinal}.log" 2>&1 &
done
kubectl --namespace "${namespace}" scale "statefulset/${workload}" --replicas 1
for ordinal in 1 2; do
    kubectl --namespace "${namespace}" wait --for=delete "pod/${workload}-${ordinal}" --timeout 120s
done
wait
for ordinal in 1 2; do
    grep -i "drain" "${logs}/${ordinal}.log" | sed "s/^/replica ${ordinal}: /" | cut -c1-200 ||
        { cat "${logs}/${ordinal}.log" >&2; fail "replica ${ordinal} logged no drain"; }
done
if kubectl --namespace "${namespace}" get events --field-selector reason=FailedPreStopHook -o name | grep -q .; then
    kubectl --namespace "${namespace}" get events --field-selector reason=FailedPreStopHook >&2
    fail "a preStop hook failed"
fi
echo "replicas 1 and 2 drained and stopped"

step "scale 3 to 1 retains every claim"
for ordinal in 0 1 2; do
    phase="$(kubectl --namespace "${namespace}" get pvc "state-${workload}-${ordinal}" -o jsonpath='{.status.phase}')"
    [ "${phase}" = Bound ] || fail "the claim of replica ${ordinal} is ${phase:-gone}"
    echo "claim state-${workload}-${ordinal}: ${phase}"
done

step "scale back to 3 reattaches the same identities"
kubectl --namespace "${namespace}" scale "statefulset/${workload}" --replicas 3
kubectl --namespace "${namespace}" rollout status "statefulset/${workload}" --timeout 300s
for ordinal in 1 2; do
    claim_of "${ordinal}" | grep -q "claimed at generation 2 (was 1)" ||
        fail "replica ${ordinal} restarted without moving its claim: $(claim_of "${ordinal}")"
    echo "replica ${ordinal}: $(claim_of "${ordinal}")"
done
for ordinal in 0 1 2; do
    after="$(identity "${ordinal}")"
    [ "${after}" = "${before[ordinal]}" ] || fail "replica ${ordinal} came back as ${after}, was ${before[ordinal]}"
    echo "replica ${ordinal}: host ${after}, as before"
done

step "uninstalling keeps the claims"
helm uninstall "${release}" --namespace "${namespace}" --wait
for ordinal in 0 1 2; do
    kubectl --namespace "${namespace}" get pvc "state-${workload}-${ordinal}" >/dev/null ||
        fail "the claim of replica ${ordinal} was deleted with the release"
done
echo "three claims retained after uninstall"

step "an upgrade from the single-group chart keeps its claim"
legacy_ref="${LEGACY_REF:-f4662a6e}"
legacy="$(mktemp -d)"
git archive "${legacy_ref}" charts/permguard | tar -x -C "${legacy}"
kubectl create namespace legacy
# The single-group chart with its one claim, `old-permguard-data-plane`: what an operator upgrades.
helm install old "${legacy}/charts/permguard" --namespace legacy \
    --set developmentMode=true,autogenerate=true,controlPlane.enabled=false \
    --set persistence.enabled=true,persistence.size=64Mi,dataPlane.replicaCount=1 \
    --set image.registry="",image.pullPolicy=Never,image.tag="${image##*:}",dataPlane.repository="${image%:*}"
claim=old-permguard-data-plane
kubectl --namespace legacy wait --for=jsonpath='{.status.phase}'=Bound "pvc/${claim}" --timeout 180s
uid="$(kubectl --namespace legacy get pvc "${claim}" -o jsonpath='{.metadata.uid}')"
helm upgrade old charts/permguard --namespace legacy --values "${values}" --wait --timeout 5m
[ "$(kubectl --namespace legacy get pvc "${claim}" -o jsonpath='{.metadata.uid}')" = "${uid}" ] ||
    fail "the upgrade replaced or deleted ${claim}"
[ "$(kubectl --namespace legacy get pvc "${claim}" -o jsonpath='{.metadata.annotations.helm\.sh/resource-policy}')" = keep ] ||
    fail "${claim} is not marked kept"
helm uninstall old --namespace legacy --wait
kubectl --namespace legacy get pvc "${claim}" >/dev/null || fail "${claim} was deleted with the release"
echo "${claim} kept through the upgrade and the uninstall (uid ${uid})"

printf '\nok: chart-e2e\n'
