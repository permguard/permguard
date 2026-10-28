#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The supply-chain gate at deploy (TD-4), on kind: with `imageVerification` on, an image that is not
# attested, or attested by another source, never reaches Ready.
#
#   scripts/chart-supply-chain.sh [verifier image]
#
# `verifier image` is the image `docker/verifier/Dockerfile` builds (default
# `permguard/verifier:e2e`). GH_TOKEN is a GitHub token the attestation API is read with; it goes
# into a Secret through a private file and is never printed. Each case installs one stateless data
# plane group whose image is the case's, by digest, and names each step as it runs:
#
#   an unattested image never reaches Ready      (busybox: no attestation at all)
#   a wrong-source image never reaches Ready     (an image GitHub attests for another repository)
#   another builder, another tag, never Ready    (Permguard 0.1.5, attested by `release-pipeline.yml`
#                                                 at `v0.1.5`, under the chart's default policy and
#                                                 under another tag)
#   the release image passes under its identity  (the control: the same digest verifies under the
#                                                 builder and tag that attested it, so the refusals
#                                                 above are the policy's)
#
# Permguard 0.1.5 is the image: its release attested every image, `release-pipeline.yml` the builder;
# 0.1.6's images carry no attestation (status.md, TD-4), and no `release-build.yml` release exists.
#
# It needs docker, kind, kubectl, helm and jq, and the network: the images are pulled from their
# registries and the attestations read from api.github.com. The cluster is deleted at the end
# unless KEEP=1.
set -euo pipefail

verifier="${1:-permguard/verifier:e2e}"
cluster="${CLUSTER:-permguard-supply-chain}"
: "${GH_TOKEN:?a GitHub token, GH_TOKEN, to read the attestations with}"

# Pinned by digest: what each case runs is exactly what it verifies.
unattested="docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
# Attested for another repository: GitHub attests this image for `actions/runner`.
foreign="ghcr.io/actions/actions-runner@sha256:e275409999c37162649aa050ca573f03eab2eabcb3a1e7fcc47548de6b4f9690"
# Permguard 0.1.5's data plane, and the identity its release attested it under.
release="ghcr.io/permguard/permguard/data-plane@sha256:3722087ba7da7ca655b8c247232536e6c6278f165c717766f4bdda501b404997"
release_workflow="permguard/permguard/.github/workflows/release-pipeline.yml"
release_ref="refs/tags/v0.1.5"

for tool in docker kind kubectl helm jq; do
    command -v "${tool}" >/dev/null || {
        echo "chart-supply-chain: ${tool} is required" >&2
        exit 2
    }
done
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

token_file=""
cleanup() {
    [ -z "${token_file}" ] || rm -f "${token_file}"
    if [ "${KEEP:-0}" != "1" ]; then
        kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true; rm -f "${TMPDIR:-/tmp}/kubeconfig-${cluster}"
        docker rm -f "${cluster}-registry" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

step "a disposable cluster, ${cluster}, and the verifier in a registry beside it"
# The chart names the verifier by digest, and an image loaded into a node has none a kubelet can
# pull by: the verifier goes to a registry on the cluster's network, as kind documents.
registry="${cluster}-registry"
docker rm -f "${registry}" >/dev/null 2>&1 || true
docker run -d --restart=always -p "127.0.0.1:${REGISTRY_PORT:-5001}:5000" --name "${registry}" \
    "docker.io/library/registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373" >/dev/null
# The disposable cluster's own kubeconfig: the caller's, and its current context, are left as they are.
export KUBECONFIG="${TMPDIR:-/tmp}/kubeconfig-${cluster}"
echo "kubeconfig ${KUBECONFIG}"
kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
kind create cluster --name "${cluster}" --wait 120s --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
local_name="localhost:${REGISTRY_PORT:-5001}"
for node in $(kind get nodes --name "${cluster}"); do
    docker exec "${node}" mkdir -p "/etc/containerd/certs.d/${local_name}"
    printf '[host."http://%s:5000"]\n' "${registry}" |
        docker exec -i "${node}" cp /dev/stdin "/etc/containerd/certs.d/${local_name}/hosts.toml"
done
docker network connect kind "${registry}" 2>/dev/null || true
docker tag "${verifier}" "${local_name}/permguard-verifier:e2e"
docker push "${local_name}/permguard-verifier:e2e" >/dev/null
verifier_digest="$(docker buildx imagetools inspect "${local_name}/permguard-verifier:e2e" | awk '/^Digest:/ {print $2; exit}')"
[ -n "${verifier_digest}" ] || fail "the registry holds the verifier under no digest"
verifier_ref="${local_name}/permguard-verifier@${verifier_digest}"
echo "verifier ${verifier_ref}"

token_file="$(mktemp)"
chmod 0600 "${token_file}"
printf '%s' "${GH_TOKEN}" >"${token_file}"

# One release per case, in its own namespace: a stateless development group, so the verifier is
# its only init container, running `image` (a digest reference) under `policy`.
install() { # namespace, image, extra helm arguments...
    local namespace="$1" image="$2"
    shift 2
    kubectl create namespace "${namespace}" >/dev/null
    kubectl --namespace "${namespace}" create secret generic gh-token --from-file=token="${token_file}" >/dev/null
    helm install pg charts/permguard --namespace "${namespace}" \
        --set developmentMode=true,autogenerate=true,controlPlane.enabled=false \
        --set image.registry= \
        --set "dataPlane.repository=${image%@*},dataPlane.digest=${image#*@}" \
        --set imageVerification.enabled=true,imageVerification.tokenSecret.name=gh-token \
        --set "imageVerification.verifier.image=${verifier_ref}" \
        --set 'dataPlane.groups[0].name=case,dataPlane.groups[0].selector=plane/data/*' \
        --set 'dataPlane.groups[0].assurance.profile=development,dataPlane.groups[0].evidence.mode=disabled' \
        --set 'dataPlane.groups[0].persistence.enabled=false,dataPlane.groups[0].replicas=1' \
        --set 'dataPlane.groups[0].podDisruptionBudget.enabled=false' \
        "$@" >/dev/null
}

pod_of() { kubectl --namespace "$1" get pods -l app.kubernetes.io/component=data-plane -o name | head -1; }

# The verifier's verdict on the case of `namespace`: `refused` once it failed and the Pod is not
# Ready, `passed` once it completed; it waits for one or the other.
verdict() {
    local namespace="$1" pod state
    for _ in $(seq 90); do
        pod="$(pod_of "${namespace}")"
        if [ -n "${pod}" ]; then
            state="$(kubectl --namespace "${namespace}" get "${pod}" -o json |
                jq -r '.status.initContainerStatuses[]? | select(.name == "verify-image") |
                       (.lastState.terminated // .state.terminated // {}) | .exitCode // empty')"
            # `gh` exits 1 when it refuses; anything else — a kill, an OOM — is no verdict.
            case "${state}" in
            0) echo passed && return ;;
            1) echo refused && return ;;
            [2-9]* | 1[0-9]*) echo undecided && return ;;
            esac
        fi
        sleep 2
    done
    echo undecided
}

# The verifier's refusal of the case of `namespace` says `reason`: refused for the policy, not for a
# transient failure that happened to exit the same way.
refused_for() { # namespace, reason
    local namespace="$1" reason="$2" pod log
    pod="$(pod_of "${namespace}")"
    log="$({ kubectl --namespace "${namespace}" logs "${pod}" -c verify-image --previous 2>/dev/null ||
        kubectl --namespace "${namespace}" logs "${pod}" -c verify-image 2>/dev/null; } || true)"
    grep -q -- "${reason}" <<<"${log}" || fail "${namespace}: refused, but not for \`${reason}\`: ${log}"
}

never_ready() { # namespace
    local namespace="$1" pod ready started
    pod="$(pod_of "${namespace}")"
    # Long enough for a kubelet to have retried the init container and started anything it would.
    sleep 20
    ready="$(kubectl --namespace "${namespace}" get "${pod}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"
    started="$(kubectl --namespace "${namespace}" get "${pod}" -o json |
        jq -r '[.status.containerStatuses[]? | select(.state.running or .state.terminated or .lastState.terminated)] | length')"
    [ "${ready}" != "True" ] || fail "${namespace}: the Pod became Ready"
    [ "${started}" = 0 ] || fail "${namespace}: a container started behind a failed verification"
    { kubectl --namespace "${namespace}" logs "${pod}" -c verify-image --previous 2>/dev/null ||
        kubectl --namespace "${namespace}" logs "${pod}" -c verify-image 2>/dev/null; } | tail -2 || true
}

step "an unattested image never reaches Ready"
install unattested "${unattested}"
[ "$(verdict unattested)" = refused ] || fail "the verifier did not refuse ${unattested}"
refused_for unattested "HTTP 404"
never_ready unattested
echo "${unattested}: refused, the Pod never Ready, no container started"

step "a wrong-source image never reaches Ready"
install wrong-source "${foreign}"
[ "$(verdict wrong-source)" = refused ] || fail "the verifier did not refuse ${foreign} under Permguard's policy"
# Not attested under permguard/permguard: the lookup is scoped to the repository the policy names.
refused_for wrong-source "HTTP 404"
never_ready wrong-source
echo "${foreign}: attested for actions/runner, refused under permguard/permguard's"

# The attestation found, and not the one the policy asks for: the identity checks themselves, not
# the repository the lookup is scoped to.
step "a release image from another builder never reaches Ready"
install wrong-builder "${release}" --set "imageVerification.sourceRef=${release_ref}"
[ "$(verdict wrong-builder)" = refused ] || fail "the verifier accepted ${release} from a builder the policy does not name"
refused_for wrong-builder "verifying with issuer"
never_ready wrong-builder
echo "${release}: attested by ${release_workflow}, refused under the chart's default builder"

step "a release image from another tag never reaches Ready"
install wrong-ref "${release}" --set "imageVerification.signerWorkflow=${release_workflow}" \
    --set "imageVerification.sourceRef=refs/tags/v0.1.6"
[ "$(verdict wrong-ref)" = refused ] || fail "the verifier accepted ${release} for a tag it was not built from"
refused_for wrong-ref "expected SourceRepositoryRef to be refs/tags/v0.1.6"
never_ready wrong-ref
echo "${release}: built from ${release_ref}, refused for refs/tags/v0.1.6"

step "the release image passes under the identity that attested it"
install control "${release}" --set "imageVerification.signerWorkflow=${release_workflow}" \
    --set "imageVerification.sourceRef=${release_ref}"
[ "$(verdict control)" = passed ] || fail "the verifier refused ${release} under ${release_workflow}@${release_ref}"
echo "${release}: verified under ${release_workflow}@${release_ref}"

printf '\nok: chart-supply-chain\n'
