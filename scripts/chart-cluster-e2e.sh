#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The chart as a cluster (iteration 02, TD-5 and WP-14.1): one Control Plane, the IAM Host, and two
# Data Planes in two groups that join it by themselves from invitation Secrets, on kind. Each step is
# named as it runs:
#
#   the operator is the Control Plane's recovery administrator, bootstrapped offline on its volume
#   the catalog holds a ledger, its policies applied
#   each group's replica joins by itself from its Secret, and waits for its approval
#   the operator approves the exact Host each pending membership names (by its host id)
#   a service account's token decides on the member it is addressed to, and on no other
#   the operator's certificate never decides on a member
#   a revoked token is refused once the member holds the list that says so
#   the evaluation latency on a member, token verification on, within the TS-5 objective
#
#   scripts/chart-cluster-e2e.sh
#
# The images are `permguard/control-plane:e2e` and `permguard/data-plane:e2e`, built from the lab
# image (`docker build -f lab/compose/Dockerfile -t permguard/lab:local .`), which also runs the
# offline bootstrap. It needs docker, kind, kubectl, helm, jq, openssl, curl and the `permguard`
# CLI of this tree (`cargo build -p permguard-cli`). The cluster is deleted at the end unless KEEP=1.
set -euo pipefail

cluster="${CLUSTER:-permguard-cluster-e2e}"
namespace=pg
release=pg
for tool in docker kind kubectl helm jq openssl curl; do
    command -v "${tool}" >/dev/null || { echo "chart-cluster-e2e: ${tool} is required" >&2; exit 2; }
done
cd "$(git rev-parse --show-toplevel)"
cli="${PERMGUARD:-$(pwd)/target/debug/permguard}"
[ -x "${cli}" ] || { echo "chart-cluster-e2e: no permguard CLI at ${cli}: cargo build -p permguard-cli" >&2; exit 2; }
step() { printf '\n== %s\n' "$*"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

work="$(mktemp -d)"
forwards=()
cleanup() {
    for pid in ${forwards[@]+"${forwards[@]}"}; do kill "${pid}" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "${KEEP:-0}" != "1" ]; then
        kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
        rm -f "${TMPDIR:-/tmp}/kubeconfig-${cluster}"
        rm -rf "${work}"
    else
        echo "kept: the cluster ${cluster} and ${work}"
    fi
}
trap cleanup EXIT

step "images"
for plane in control-plane data-plane; do
    printf 'FROM permguard/lab:local\nUSER root\nRUN cp /usr/local/bin/permguard /usr/local/bin/permguard-cli && cp /usr/local/bin/permguard-%s /usr/local/bin/permguard\nUSER 65532:65532\nENTRYPOINT ["/usr/local/bin/permguard"]\nCMD ["/etc/permguard/config.yml"]\n' "${plane}" |
        docker build -q -t "permguard/${plane}:e2e" - >/dev/null
    log "permguard/${plane}:e2e"
done

step "a disposable cluster, ${cluster}"
export KUBECONFIG="${TMPDIR:-/tmp}/kubeconfig-${cluster}"
kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
kind create cluster --name "${cluster}" --wait 120s
for image in permguard/control-plane:e2e permguard/data-plane:e2e permguard/lab:local; do
    kind load docker-image "${image}" --name "${cluster}"
done
kubectl create namespace "${namespace}"
k() { kubectl --namespace "${namespace}" "$@"; }

step "an authority, the Hosts' certificates and the operator's"
(
    cd "${work}"
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
        -subj "/CN=permguard-e2e-ca" -keyout ca.key -out ca.crt 2>/dev/null
    issue() { # name, subjectAltName, extendedKeyUsage
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
            -keyout "$1.key" -out "$1.csr" 2>/dev/null
        printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$2" "$3" >"$1.ext"
        openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
            -extfile "$1.ext" -out "$1.crt" 2>/dev/null
    }
    issue control-plane "DNS:${release}-permguard-control-plane-host,DNS:${release}-permguard-control-plane,DNS:localhost,IP:127.0.0.1" "serverAuth,clientAuth"
    issue data-plane "DNS:localhost,IP:127.0.0.1,URI:spiffe://permguard-e2e/data-plane" "serverAuth,clientAuth"
    issue operator "URI:spiffe://permguard-e2e/operator" "clientAuth"
    openssl x509 -in operator.crt -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1 >operator.fp
)
for secret in cp-host:control-plane cp-public:control-plane dp-host:data-plane dp-public:data-plane; do
    k create secret generic "${secret%%:*}" --type kubernetes.io/tls \
        --from-file=tls.crt="${work}/${secret##*:}.crt" --from-file=tls.key="${work}/${secret##*:}.key" \
        --from-file=ca.crt="${work}/ca.crt" >/dev/null
done
log "secrets cp-host, cp-public, dp-host; the operator is $(cat "${work}/operator.fp")"

# Two groups, one zone each, one replica each, joining by themselves once their Secrets exist;
# none before the zones they serve exist.
values() { # pin, replicas, acme zone id, beta zone id
    local enabled=true
    [ -z "${3:-}" ] && enabled=false
    cat <<EOF
developmentMode: true
autogenerate: true
image: { registry: "", pullPolicy: Never, tag: e2e }
persistence: { enabled: true, size: 128Mi }
controlPlane:
  repository: permguard/control-plane
  assurance: { profile: development }
  tls: { secretName: cp-public }
  hostListener: { enabled: true, tls: { secretName: cp-host } }
  extraConfig:
    # The Host's rings and secrets, as the Compose lab states them: a coordinator signs its
    # memberships' manifests with \`host.operations\`, and routes no task session without it.
    operations:
      keys: { enabled: "true", publish_ahead: 5m, rotate_every: 1h, retain: 1d }
      secrets: { provider: directory, coordinator_root_ref: zone-root }
      audit: { pseudonym: { enabled: true, key_ref: audit-pseudonym, key_version: "v1" } }
    controlPlane:
      # The signing ring, as values-production.yaml states it: without it no NOTP is served.
      keys: { enabled: "true", directory: "operations/keys" }
      public:
        http: { tls: { client_ca: /etc/permguard-tls/ca.crt } }
        grpc: { tls: { client_ca: /etc/permguard-tls/ca.crt } }
dataPlane:
  enabled: ${enabled}
  repository: permguard/data-plane
  # TLS on the decision listener: a bearer token is never sent in the clear.
  tls: { secretName: dp-public }
  hostListener: { enabled: true, tls: { secretName: dp-host } }
  extraConfig:
    operations:
      keys: { enabled: "true", publish_ahead: 5m, rotate_every: 1h, retain: 1d }
      secrets: { provider: directory, coordinator_root_ref: zone-root }
      audit: { pseudonym: { enabled: true, key_ref: audit-pseudonym, key_version: "v1" } }
  groups:
    - name: eu
      selector: plane/data/zone/${3:-none}/*
      replicas: $2
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: true, size: 64Mi }
      join: { secret: eu-invitations, pinFingerprint: "$1" }
    - name: us
      selector: plane/data/zone/${4:-none}/*
      replicas: $2
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: true, size: 64Mi }
      join: { secret: us-invitations, pinFingerprint: "$1" }
EOF
}
placeholder="sha256:$(printf '0%.0s' $(seq 64))"
values "${placeholder}" 0 >"${work}/values.yaml"

step "the Control Plane, the IAM Host"
helm install "${release}" charts/permguard --namespace "${namespace}" --values "${work}/values.yaml" --wait --timeout 5m
cp="${release}-permguard-control-plane"
k rollout status "deployment/${cp}" --timeout 300s

step "the operator is the Control Plane's recovery administrator, bootstrapped offline on its volume"
k scale "deployment/${cp}" --replicas 0
k wait --for=delete pod -l "app.kubernetes.io/component=control-plane" --timeout 120s 2>/dev/null || true
claim="$(k get pvc -o json | jq -er --arg cp "${cp}" '.items[] | select(.metadata.name | startswith($cp)) | .metadata.name' | head -1)"
cat <<EOF | k apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata: { name: bootstrap-operator }
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      securityContext: { runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532 }
      containers:
        - name: bootstrap
          image: permguard/lab:local
          imagePullPolicy: Never
          command: ["permguard", "-o", "json", "host", "grants", "bootstrap", "--volume", "/var/lib/permguard/volume", "--fingerprint", "$(cat "${work}/operator.fp")"]
          volumeMounts: [{ name: state, mountPath: /var/lib/permguard }]
      volumes: [{ name: state, persistentVolumeClaim: { claimName: ${claim} } }]
EOF
k wait --for=condition=complete job/bootstrap-operator --timeout 120s ||
    { k logs job/bootstrap-operator >&2; fail "the offline bootstrap did not complete"; }
k scale "deployment/${cp}" --replicas 1
k rollout status "deployment/${cp}" --timeout 300s
log "granted offline on ${claim}"

forward() { # target, local port, remote port
    # A port another process holds would answer for this cluster: refused rather than reused.
    if (: <"/dev/tcp/127.0.0.1/$2") 2>/dev/null; then
        fail "port $2 is already taken on this computer"
    fi
    # kubectl itself in the background, so its pid is the one stopped at the end.
    kubectl --namespace "${namespace}" port-forward "$1" "$2:$3" >/dev/null 2>&1 &
    forwards+=("$!")
    for _ in $(seq 1 60); do (: <"/dev/tcp/127.0.0.1/$2") 2>/dev/null && return; sleep 1; done
    fail "no port-forward to $1"
}
forward "svc/${cp}-host" 15444 5444
forward "svc/${cp}" 16443 6443
pg() {
    "${cli}" -o json --tls-ca-file "${work}/ca.crt" --tls-cert-file "${work}/operator.crt" \
        --tls-key-file "${work}/operator.key" "$@"
}
host_api=https://localhost:15444
control=https://localhost:16443
principal="cert:sha256:$(cat "${work}/operator.fp")"
pg --host-endpoint "${host_api}" iam grants issue --principal "${principal}" \
    --operations membership.admin,membership.read,identity.read --selector host >/dev/null
pg --host-endpoint "${host_api}" iam grants issue --principal "${principal}" \
    --operations catalog.read,catalog.write,policy.push --selector "plane/control/*" >/dev/null
pin="$(pg --host-endpoint "${host_api}" host identity show | jq -er '.fingerprint')"
log "the IAM Host is ${pin}"

step "the catalog holds a ledger in each group's zone, its policies applied"
for name in acme beta; do
    pg --control-endpoint "${control}" zones create "${name}" >/dev/null
    pg --control-endpoint "${control}" ledgers create main --zone "${name}" >/dev/null
    workspace="${work}/workspace-${name}"
    mkdir -p "${workspace}"
    cp -R examples/basics/. "${workspace}"
    rm -rf "${workspace}/.permguard"
    pg -w "${workspace}" init main --language cedar,rego >/dev/null
    pg -w "${workspace}" remote add origin "${control}" >/dev/null
    pg -w "${workspace}" checkout "origin/${name}/main" >/dev/null
    pg -w "${workspace}" apply -m "the e2e's basics policies" >/dev/null
done
zone="$(pg --control-endpoint "${control}" zones list | jq -er '.zones[] | select(.name == "acme") | .id')"
beta="$(pg --control-endpoint "${control}" zones list | jq -er '.zones[] | select(.name == "beta") | .id')"
ledger="$(pg --control-endpoint "${control}" ledgers list --zone acme | jq -er '.ledgers[] | select(.name == "main") | .id')"
log "acme/main (${zone}/${ledger}) and beta/main applied"
values "${pin}" 0 "${zone}" "${beta}" >"${work}/values.yaml"
helm upgrade "${release}" charts/permguard --namespace "${namespace}" --values "${work}/values.yaml" --timeout 5m >/dev/null

step "each group's replica joins by itself from its Secret, and waits for its approval"
for group in eu us; do
    # One invitation per membership the group's ConfigMap states: `control`, and `data` when the
    # group has tasks of its own.
    membership="$(k get configmap "${release}-permguard-data-plane-${group}-membership" -o json)"
    files=()
    for kind in control data; do
        selector="$(jq -r --arg kind "${kind}" '.data[$kind + ".selector"] // empty' <<<"${membership}")"
        [ -n "${selector}" ] || continue
        jq -r --arg kind "${kind}" '.data[$kind + ".tasks.json"]' <<<"${membership}" >"${work}/${group}-${kind}-tasks.json"
        (umask 077 && pg --host-endpoint "${host_api}" host members invite create --selector "${selector}" \
            --tasks "${work}/${group}-${kind}-tasks.json" --name "${group}-0" --group "${group}" \
            --min-assurance development --coordinator-address "https://${release}-permguard-control-plane-host:5444" \
            >"${work}/${kind}-0")
        files+=(--from-file="${kind}-0=${work}/${kind}-0")
    done
    k create secret generic "${group}-invitations" "${files[@]}" >/dev/null
    rm -f "${work}/control-0" "${work}/data-0"
done
values "${pin}" 1 "${zone}" "${beta}" >"${work}/values.yaml"
helm upgrade "${release}" charts/permguard --namespace "${namespace}" --values "${work}/values.yaml" --timeout 5m
deadline=$((SECONDS + 300))
# Both replicas joined: each name among the pending memberships, whatever their number.
until pg --host-endpoint "${host_api}" host members pending | jq -e '[.members[].name] | index("eu-0") != null and index("us-0") != null' >/dev/null; do
    [ "${SECONDS}" -lt "${deadline}" ] || { k get pods >&2; k logs "${release}-permguard-data-plane-eu-0" --tail 40 >&2 || true; fail "the replicas did not join"; }
    sleep 3
done
log "eu-0 and us-0 joined, pending"

step "the operator approves the exact Host each pending membership names"
port=25443
for group in eu us; do
    # The forward in this shell, so the end of the run stops it.
    forward "pod/${release}-permguard-data-plane-${group}-0" "${port}" 5443
    host_id="$(curl -fsS "http://127.0.0.1:${port}/.well-known/server-configuration" | jq -er '.host_id' | tr -d '-')"
    port=$((port + 1))
    # Every membership the replica joined with, each its own approval.
    for pending in $(pg --host-endpoint "${host_api}" host members pending |
        jq -c --arg name "${group}-0" '.members[] | select(.name == $name) | {membership_id, revision, host: .member.host_id}'); do
        [ "$(jq -r '.host' <<<"${pending}" | tr -d '-')" = "${host_id}" ] ||
            fail "${group}-0: a pending membership names $(jq -r '.host' <<<"${pending}"), the replica is ${host_id}"
        pg --host-endpoint "${host_api}" host members approve "$(jq -r '.membership_id' <<<"${pending}")" \
            --expected-revision "$(jq -r '.revision' <<<"${pending}")" >/dev/null
    done
    log "${group}-0: ${host_id} approved"
done
deadline=$((SECONDS + 150))
until [ "$(pg --host-endpoint "${host_api}" host members list | jq '[.members[] | select(.role == "coordinator" and .status == "active")] | length')" -ge 2 ]; do
    [ "${SECONDS}" -lt "${deadline}" ] || fail "the approved memberships are not active"
    sleep 3
done
member_of() { pg --host-endpoint "${host_api}" host members list | jq -er --arg name "$1" '.members[] | select(.name == $name) | .member_id'; }
eu="$(member_of eu-0)"
us="$(member_of us-0)"
log "members eu-0 ${eu}, us-0 ${us}"

step "a service account's token decides on the member it is addressed to, and on no other"
pg --host-endpoint "${host_api}" iam service-accounts create e2e --owner e2e >/dev/null
pg --host-endpoint "${host_api}" iam grants issue --principal sa:e2e \
    --operations decision.evaluate --selector "plane/data/*" >/dev/null
(umask 077 && pg --host-endpoint "${host_api}" iam credentials create e2e --secret-out "${work}/e2e.secret" >/dev/null)
token_for() { # member, file
    rm -f "$2"
    pg --iam-endpoint "${host_api}" --client-id e2e --client-secret-file "${work}/e2e.secret" \
        iam token --scope decision.evaluate --audience "member:$1" --target "plane/data/*" --out "$2" >/dev/null
}
token_for "${eu}" "${work}/eu.jwt"
forward "pod/${release}-permguard-data-plane-eu-0" 27443 7443
forward "pod/${release}-permguard-data-plane-us-0" 27444 7443
decide() { # port, token file or none
    local bearer=()
    [ "$2" != none ] && bearer=(--token-file "$2")
    "${cli}" -o json ${bearer[@]+"${bearer[@]}"} --tls-ca-file "${work}/ca.crt" \
        --data-endpoint "https://localhost:$1" check --ignore-workspace \
        -f examples/basics/requests/permit.json --zone "${zone}" --ledger "${ledger}" 2>&1 || true
}
deadline=$((SECONDS + 240))
until jq -e '.evaluated == true and .decision == true' >/dev/null 2>&1 <<<"$(decide 27443 "${work}/eu.jwt")"; do
    [ "${SECONDS}" -lt "${deadline}" ] || fail "eu-0 does not decide on its token: $(decide 27443 "${work}/eu.jwt")"
    sleep 3
done
log "eu-0 decides on a token addressed to it"
grep -q unauthenticated <<<"$(decide 27444 "${work}/eu.jwt")" || fail "us-0 decided on eu-0's token: $(decide 27444 "${work}/eu.jwt")"
log "us-0 refuses eu-0's token"

step "the operator's certificate never decides on a member"
answer="$(decide 27443 none)"
jq -e '.evaluated == true' >/dev/null 2>&1 <<<"${answer}" && fail "eu-0 decided with no token: ${answer}"
log "eu-0 refuses a request with no token"

step "the evaluation latency on a member, token verification on, within the TS-5 objective"
header="${work}/eu.header"
(umask 077 && printf 'authorization: Bearer %s\n' "$(cat "${work}/eu.jwt")" >"${header}")
request="$(jq -c --arg zone "${zone}" --arg ledger "${ledger}" '. + {zone: $zone, ledger: $ledger}' examples/basics/requests/permit.json)"
curl -fsS --cacert "${work}/ca.crt" -H "@${work}/eu.header" -H 'content-type: application/json' --data "${request}" \
    https://localhost:27443/access/v1/evaluation | jq -e '.decision == true' >/dev/null ||
    fail "the evaluation endpoint does not permit the sample request with the token"
# One connection, many requests: what a client with a pool sees, not a handshake per decision.
urls=()
# Every option is stated again after `--next`, which resets them, the output and its timing included.
for _ in $(seq 1 400); do urls+=(-o /dev/null -w '%{http_code} %{time_total}\n' --cacert "${work}/ca.crt" -H "@${header}" -H 'content-type: application/json' --data "${request}" https://localhost:27443/access/v1/evaluation --next); done
curl -sS "${urls[@]::${#urls[@]}-1}" >"${work}/latency"
[ "$(grep -vc '^200 ' "${work}/latency")" = 0 ] ||
    fail "not every decision was answered 200: $(cut -d' ' -f1 "${work}/latency" | sort | uniq -c | tr '\n' ' ')"
cut -d' ' -f2 "${work}/latency" | sort -n >"${work}/latency.sorted"
count="$(wc -l <"${work}/latency.sorted" | tr -d ' ')"
p50="$(awk -v n="${count}" 'NR == int(n * 0.50) + 1 { printf "%.1f", $1 * 1000 }' "${work}/latency.sorted")"
p99="$(awk -v n="${count}" 'NR == int(n * 0.99) + 1 { printf "%.1f", $1 * 1000 }' "${work}/latency.sorted")"
objective="$(jq -r '.p99_ms.disabled' bench/slo.json)"
log "${count} decisions on eu-0 with its token: p50 ${p50} ms, p99 ${p99} ms; objective p99 ${objective} ms"
awk -v p="${p99}" -v o="${objective}" 'BEGIN { exit !(p <= o) }' || fail "p99 ${p99} ms passes the ${objective} ms objective"

step "a revoked token is refused once the member holds the list that says so"
jti="$(cut -d. -f2 "${work}/eu.jwt" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d 2>/dev/null | jq -er '.jti')"
pg --host-endpoint "${host_api}" iam tokens revoke "${jti}" >/dev/null
started=${SECONDS}
until grep -q unauthenticated <<<"$(decide 27443 "${work}/eu.jwt")"; do
    [ $((SECONDS - started)) -lt 240 ] || fail "eu-0 still decides on the revoked ${jti}"
    sleep 5
done
log "eu-0 refuses ${jti} $((SECONDS - started)) s after its revocation"

printf '\nok: chart-cluster-e2e\n'
