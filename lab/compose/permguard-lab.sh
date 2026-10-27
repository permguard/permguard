#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The Compose lab's authority and its checks (TD-3), run inside the lab's network by the lab image.
#
#   permguard-lab pki                       the lab's certificate authority, every Host's certificate
#                                           and the operator's, once
#   permguard-lab serve <binary> <config>   one Host: claim its volume, grant the operator, serve
#   permguard-lab catalog <profile>         the zones, ledgers and policies a profile serves
#   permguard-lab enroll <profile>          every data plane of a profile, enrolled with exact
#                                           fingerprints over one-time invitations
#   permguard-lab assert <profile> [phase]  what the profile must prove
#
# A lab is an isolated test authority, and only a lab does what this script does: it issues every
# certificate, grants its operator on every volume before the Host starts, and approves the exact
# fingerprint it reads from each data plane over a channel its own authority verifies. A deployment
# approves through an operator or a workload attestation and never embeds an enrollment token.
#
# Every Host is reached by its Compose service name: no loopback alias, no host network, no fixed
# host port. The invitation tokens live in a private temporary file for the length of one join.
set -euo pipefail

lab="${LAB_DIR:-/lab}"
pki="${lab}/pki"
state="${lab}/state"
volume=/var/lib/permguard/volume
examples="${LAB_EXAMPLES:-/opt/permguard/examples}"
templates="${LAB_TEMPLATES:-/opt/permguard/lab}"
trust_domain=spiffe://permguard-lab

# Every Host a profile may run, by service name: each gets its certificate whatever the profile.
hosts=(control-plane all-in-one data-plane data-plane-a data-plane-b data-plane-acme data-plane-beta
    temporal-a temporal-b)

# The CLI keeps its configuration under HOME, which the lab's user does not have.
export HOME="${HOME:-/tmp}"
[ -w "${HOME}" ] || export HOME=/tmp

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
step() { printf '\n== %s\n' "$*" >&2; }
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# The CLI as the lab's operator: its certificate, the lab's authority, JSON out.
pg() {
    permguard -o json --tls-ca-file "${pki}/ca.crt" --tls-cert-file "${pki}/operator.crt" \
        --tls-key-file "${pki}/operator.key" "$@"
}
host_endpoint() { printf 'https://%s:5444' "$1"; }
control_endpoint() { printf 'https://%s:6443' "$1"; }
data_endpoint() { printf 'https://%s:7443' "$1"; }

# Waits until `host` answers discovery: started, its listeners bound.
# Waits until `host` answers discovery and its Host listener accepts connections: the server opens
# its listeners one after another, and the lab's authority calls the Host listener next.
wait_up() {
    local host="$1" deadline=$((SECONDS + ${2:-180}))
    until curl -fsS -o /dev/null "http://${host}:5443/.well-known/server-configuration" 2>/dev/null &&
        (: <"/dev/tcp/${host}/5444") 2>/dev/null; do
        [ "${SECONDS}" -lt "${deadline}" ] || fail "${host} did not come up"
        sleep 2
    done
}

# Runs a step once per lab: a marker under the lab's state, written when the step succeeded.
once() {
    local marker="${state}/$1.done"
    shift
    [ -f "${marker}" ] && return 0
    "$@"
    touch "${marker}"
}

# ---------------------------------------------------------------------------------------------
# pki
# ---------------------------------------------------------------------------------------------

cmd_pki() {
    mkdir -p "${state}"
    if [ -f "${pki}/operator.fp" ]; then
        log "the lab authority already issued its certificates"
        return
    fi
    local work
    work="$(mktemp -d "${lab}/.pki.XXXXXX")"
    (
        umask 077
        cd "${work}"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
            -subj "/CN=permguard-lab-ca" -keyout ca.key -out ca.crt 2>/dev/null
        issue() { # name, subjectAltName, extendedKeyUsage
            openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
                -keyout "$1.key" -out "$1.csr" 2>/dev/null
            printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$2" "$3" >"$1.ext"
            openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 90 \
                -extfile "$1.ext" -out "$1.crt" 2>/dev/null
            rm -f "$1.csr" "$1.ext"
        }
        for host in "${hosts[@]}"; do
            issue "${host}" "DNS:${host},URI:${trust_domain}/${host}" "serverAuth,clientAuth"
        done
        issue operator "URI:${trust_domain}/operator" "clientAuth"
        # Each certificate's principal on a Host: the fingerprint of its certificate.
        for name in "${hosts[@]}" operator; do
            openssl x509 -in "${name}.crt" -outform DER | sha256sum | cut -d' ' -f1 >"${name}.fp"
        done
        # Nothing is issued after this: the authority's key goes with the run that used it.
        rm -f ca.key ca.srl
        chmod 0644 ./*.crt ./*.fp
    )
    rm -rf "${pki}"
    mv "${work}" "${pki}"
    log "the lab authority issued ${#hosts[@]} Host certificates and the operator's"
}

# ---------------------------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------------------------

# The listeners' environment of `host` running `binary`: where clients reach each listener, and the
# certificate the lab's authority issued to the service's name. What the server reads its
# configuration with, and so what an offline command reading that configuration needs too.
listener_env() {
    local host="$1" binary="$2"
    local listeners=(ADMIN)
    case "${binary}" in
    *control-plane) listeners+=(CONTROL_HTTP CONTROL_GRPC) ;;
    *data-plane) listeners+=(DATA_HTTP DATA_GRPC) ;;
    *all-in-one) listeners+=(CONTROL_HTTP CONTROL_GRPC DATA_HTTP DATA_GRPC) ;;
    esac
    # Where clients reach each listener: the service's name, the name its certificate carries.
    export "PERMGUARD_ADMIN_ADVERTISED_URL=https://${host}:5444"
    case "${listeners[*]}" in *CONTROL_HTTP*) export "PERMGUARD_CONTROL_HTTP_ADVERTISED_URL=https://${host}:6443" ;; esac
    case "${listeners[*]}" in *DATA_HTTP*) export "PERMGUARD_DATA_HTTP_ADVERTISED_URL=https://${host}:7443" ;; esac
    for listener in "${listeners[@]}"; do
        export "PERMGUARD_${listener}_TLS_CERT=${pki}/${host}.crt"
        export "PERMGUARD_${listener}_TLS_KEY=${pki}/${host}.key"
        export "PERMGUARD_${listener}_TLS_CLIENT_CA=${pki}/ca.crt"
    done
}

# `serve <binary> <config>`: what a Pod's init containers and its server are, in one container.
# The claim moves forward on every start (TD-1); the operator is granted once, offline, before the
# Host first serves; the listeners carry the certificate the lab's authority issued to this
# service's name.
cmd_serve() {
    local binary="$1" config="$2" host="${LAB_HOST:?the service name, LAB_HOST}"
    [ -f "${pki}/${host}.crt" ] || fail "the lab authority issued no certificate to ${host}"
    "${binary}" volume claim --volume "${volume}" --next --create
    if [ ! -f /var/lib/permguard/.lab-operator ]; then
        permguard -o json host grants bootstrap --volume "${volume}" \
            --fingerprint "$(cat "${pki}/operator.fp")" >/dev/null
        touch /var/lib/permguard/.lab-operator
        log "${host}: the lab operator is granted on this volume"
    fi
    listener_env "${host}" "${binary}"
    # The server refuses a `PERMGUARD_` name it does not know; the lab's own are not prefixed.
    unset LAB_HOST LAB_DIR LAB_EXAMPLES LAB_TEMPLATES
    exec "${binary}" "${config}"
}

# ---------------------------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------------------------

# The one lab profile among COMPOSE_PROFILES' comma-separated names: `observability` may stand beside
# it, a second lab profile may not.
profile_of() {
    local found="" name
    for name in ${1//,/ }; do
        case "${name}" in
        all-in-one | split-plane | multi-data-plane | multi-group | temporal-replicas)
            [ -z "${found}" ] || fail "two lab profiles at once: ${found} and ${name}"
            found="${name}"
            ;;
        esac
    done
    [ -n "${found}" ] ||
        fail "no lab profile in '${1}': start the lab with COMPOSE_PROFILES=<profile>, one of all-in-one, split-plane, multi-data-plane, multi-group, temporal-replicas"
    echo "${found}"
}

# The Host that holds the catalog in `profile`.
coordinator_of() {
    case "$1" in
    all-in-one) echo all-in-one ;;
    *) echo control-plane ;;
    esac
}

# The data planes of `profile`, each with the zone it serves.
data_planes_of() {
    case "$1" in
    all-in-one) echo "all-in-one:acme" ;;
    split-plane) echo "data-plane:acme" ;;
    multi-data-plane) echo "data-plane-a:acme data-plane-b:acme" ;;
    multi-group) echo "data-plane-acme:acme data-plane-beta:beta" ;;
    temporal-replicas) echo "temporal-a:acme temporal-b:acme" ;;
    *) fail "no profile ${1}" ;;
    esac
}

# The operator's online grants on a Host: what the lab's steps and checks use there. Not a boundary:
# `host grants bootstrap` made the operator each lab Host's recovery administrator (`authz.admin` on
# `host`), which is what a lab's test authority is.
grant_operator() {
    local host="$1" principal
    principal="cert:sha256:$(cat "${pki}/operator.fp")"
    local endpoint
    endpoint="$(host_endpoint "${host}")"
    # The backup operations and the key bundle are the restore drill's (`scripts/drill-restore.sh`).
    pg --host-endpoint "${endpoint}" host grants issue --principal "${principal}" \
        --operations membership.admin,membership.read,identity.read,streams.read,backup.manage,backup.read,keys.read \
        --selector host >/dev/null
    case "${host}" in
    control-plane | all-in-one)
        pg --host-endpoint "${endpoint}" host grants issue --principal "${principal}" \
            --operations catalog.read,catalog.write,policy.push \
            --selector "plane/control/*" >/dev/null
        ;;
    esac
    case "${host}" in
    control-plane)
        # What the coordinator holds of the members' streams.
        pg --host-endpoint "${endpoint}" host grants issue --principal "${principal}" \
            --operations streams.read --selector "plane/data/*" >/dev/null
        ;;
    *)
        pg --host-endpoint "${endpoint}" host grants issue --principal "${principal}" \
            --operations decision.evaluate,event.submit,streams.read \
            --selector "plane/data/*" >/dev/null
        ;;
    esac
    log "${host}: the operator's grants are issued"
}

zone_id() {
    pg --control-endpoint "$(control_endpoint "$1")" zones list |
        jq -er --arg name "$2" '.zones[] | select(.name == $name) | .id'
}

ledger_id() {
    pg --control-endpoint "$(control_endpoint "$1")" ledgers list --zone "$2" |
        jq -er --arg name "$3" '.ledgers[] | select(.name == $name) | .id'
}

# A zone, a ledger in it, and an example's policies applied to it.
ledger_with() {
    local coordinator="$1" zone="$2" ledger="$3" example="$4" languages="$5"
    local endpoint workspace
    endpoint="$(control_endpoint "${coordinator}")"
    zone_id "${coordinator}" "${zone}" >/dev/null 2>&1 ||
        pg --control-endpoint "${endpoint}" zones create "${zone}" >/dev/null
    ledger_id "${coordinator}" "${zone}" "${ledger}" >/dev/null 2>&1 ||
        pg --control-endpoint "${endpoint}" ledgers create "${ledger}" --zone "${zone}" >/dev/null
    workspace="$(mktemp -d)"
    cp -R "${examples}/${example}/." "${workspace}"
    rm -rf "${workspace}/.permguard"
    pg -w "${workspace}" init "${ledger}" --language "${languages}" >/dev/null
    pg -w "${workspace}" remote add origin "${endpoint}" >/dev/null
    pg -w "${workspace}" checkout "origin/${zone}/${ledger}" >/dev/null
    pg -w "${workspace}" apply -m "the lab's ${example} policies" >/dev/null
    rm -rf "${workspace}"
    log "${zone}/${ledger}: the ${example} policies are applied"
}

# The temporal replicas' one static file, rendered once the ledger they import exists: the
# subscription names it by id, which only the catalog knows.
render_temporal() {
    local coordinator="$1" zone ledger
    zone="$(zone_id "${coordinator}" acme)"
    ledger="$(ledger_id "${coordinator}" acme agent-governance)"
    sed -e "s/@ZONE_ID@/${zone}/" -e "s/@LEDGER_ID@/${ledger}/" \
        "${templates}/data-plane-temporal.yml" >"${state}/data-plane-temporal.yml.tmp"
    mv "${state}/data-plane-temporal.yml.tmp" "${state}/data-plane-temporal.yml"
    log "the temporal replicas' configuration names ${zone}/${ledger}"
}

cmd_catalog() {
    local profile coordinator
    profile="$(profile_of "${1:-}")"
    coordinator="$(coordinator_of "${profile}")"
    mkdir -p "${state}"
    wait_up "${coordinator}"
    once "grants-${coordinator}" grant_operator "${coordinator}"
    case "${profile}" in
    temporal-replicas)
        once "ledger-acme-agent-governance" ledger_with "${coordinator}" acme agent-governance dogwood-session-access dogwood
        render_temporal "${coordinator}"
        ;;
    multi-group)
        once "ledger-acme-main" ledger_with "${coordinator}" acme main basics cedar,rego
        once "ledger-beta-main" ledger_with "${coordinator}" beta main basics cedar,rego
        ;;
    *)
        once "ledger-acme-main" ledger_with "${coordinator}" acme main basics cedar,rego
        ;;
    esac
}

# ---------------------------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------------------------

fingerprint() {
    pg --host-endpoint "$(host_endpoint "$1")" host identity show | jq -er '.fingerprint'
}

# One membership task, as the invitation offers it.
task() { # id, type, provider role, consumer role, selector, resource type
    jq -nc --arg id "$1" --arg type "$2" --arg provider "$3" --arg consumer "$4" \
        --arg selector "$5" --arg resource "$6" \
        '{version: 1, task_id: $id, type: $type, provider_role: $provider, consumer_role: $consumer,
          selector: $selector, resource_types: [$resource], required: true,
          limits: {max_body_bytes: 1048576, max_concurrency: 4, max_rate_per_minute: 600,
                   max_batch_records: 1000, retention_seconds: 86400},
          assurance_requirements: []}'
}

# Enrolls `member` with the coordinator for `selector` and `tasks`: a one-time invitation that
# expects the member's exact fingerprint, a join that pins the coordinator's exact fingerprint,
# the approval of that revision, and the member's sync to the signed manifest.
membership() {
    local coordinator="$1" member="$2" selector="$3" tasks="$4"
    local active
    active="$(pg --host-endpoint "$(host_endpoint "${member}")" host members list |
        jq -r --arg selector "${selector}" \
            '[.members[] | select(.role == "member" and .status == "active" and .selector == $selector)] | length')"
    if [ "${active}" != 0 ]; then
        log "${member}: already a member for ${selector}"
        return
    fi
    local coordinator_fp member_fp private token tasks_file id revision status
    coordinator_fp="$(fingerprint "${coordinator}")"
    member_fp="$(fingerprint "${member}")"
    private="$(mktemp -d)"
    chmod 0700 "${private}"
    token="${private}/invitation.json"
    tasks_file="${private}/tasks.json"
    printf '%s\n' "${tasks}" >"${tasks_file}"
    if ! (
        umask 077
        pg --host-endpoint "$(host_endpoint "${coordinator}")" host members invite create \
            --selector "${selector}" --tasks "${tasks_file}" \
            --expect-fingerprint "${member_fp}" --min-assurance development >"${token}"
    ); then
        rm -rf "${private}"
        fail "${member}: the coordinator created no invitation"
    fi
    if ! id="$(pg --host-endpoint "$(host_endpoint "${member}")" --token-file "${token}" \
        host members join "$(host_endpoint "${coordinator}")" --pin-fingerprint "${coordinator_fp}" |
        jq -er '.membership_id')"; then
        # An invitation no join spent is revoked rather than left valid until it expires.
        pg --host-endpoint "$(host_endpoint "${coordinator}")" host members invite revoke \
            "$(jq -r '.invite_id' "${token}")" >/dev/null || true
        rm -rf "${private}"
        fail "${member}: the join failed; its invitation is revoked"
    fi
    # One-time: the token goes with the join that spent it.
    rm -rf "${private}"
    revision="$(pg --host-endpoint "$(host_endpoint "${coordinator}")" host members pending |
        jq -er --arg id "${id}" '.members[] | select(.membership_id == $id) | .revision')"
    pg --host-endpoint "$(host_endpoint "${coordinator}")" host members approve "${id}" \
        --expected-revision "${revision}" >/dev/null
    status="$(pg --host-endpoint "$(host_endpoint "${member}")" host members sync "${id}" | jq -r '.status')"
    [ "${status}" = active ] || fail "${member}: the membership ${id} is ${status} after its sync"
    log "${member}: member of ${coordinator} for ${selector} (${id}; ${member_fp} approved, ${coordinator_fp} pinned)"
}

# A data plane's two memberships: the policy it mirrors is in the Control Plane's tree, the
# evidence it ships in its own, and a membership's tasks stay inside one Plane's tree.
enroll_data_plane() {
    local coordinator="$1" member="$2" zone="$3" temporal="$4" zone_id
    wait_up "${member}"
    once "grants-${member}" grant_operator "${member}"
    zone_id="$(zone_id "${coordinator}" "${zone}")"
    local control="plane/control/zone/${zone_id}/*" data="plane/data/zone/${zone_id}/*"
    membership "${coordinator}" "${member}" "${control}" \
        "[$(task policy-mirror policy.mirror coordinator member "${control}" policy)]"
    local shipped
    shipped="$(task decisions-ship decisions.ship member coordinator "${data}" decision)"
    if [ "${temporal}" = temporal ]; then
        shipped="${shipped},$(task events-ship events.ship member coordinator "${data}" event)"
        shipped="${shipped},$(task events-import events.import coordinator member "${data}" event)"
    fi
    membership "${coordinator}" "${member}" "${data}" "[${shipped}]"
}

cmd_enroll() {
    local profile coordinator
    profile="$(profile_of "${1:-}")"
    coordinator="$(coordinator_of "${profile}")"
    [ "${profile}" = all-in-one ] && {
        log "the all-in-one serves its own catalog: nothing to enroll"
        return
    }
    local temporal=none
    [ "${profile}" = temporal-replicas ] && temporal=temporal
    for entry in $(data_planes_of "${profile}"); do
        enroll_data_plane "${coordinator}" "${entry%%:*}" "${entry##*:}" "${temporal}"
    done
}

# ---------------------------------------------------------------------------------------------
# assert
# ---------------------------------------------------------------------------------------------

# A decision from `host` on `zone/ledger` for one of the `basics` example's requests: the CLI's
# answer, whatever it is. A refusal is an answer too, so its status is not this function's.
decide() {
    local host="$1" zone="$2" ledger="$3" request="$4"
    pg --data-endpoint "$(data_endpoint "${host}")" check --ignore-workspace \
        -f "${examples}/basics/requests/${request}" --zone "${zone}" --ledger "${ledger}" 2>&1 || true
}

# Waits until `host` serves `zone/ledger`: its mirror verified and loaded the ledger.
wait_serving() {
    local host="$1" zone="$2" ledger="$3" deadline=$((SECONDS + ${4:-180})) answer
    while :; do
        answer="$(decide "${host}" "${zone}" "${ledger}" permit.json)"
        jq -e '.evaluated == true' >/dev/null 2>&1 <<<"${answer}" && return
        [ "${SECONDS}" -lt "${deadline}" ] || fail "${host} does not serve ${zone}/${ledger}: ${answer}"
        sleep 2
    done
}

# `host` answers `request` on `zone/ledger` with `expected` (true or false); prints the decision's id.
expect_decision() {
    local host="$1" zone="$2" ledger="$3" request="$4" expected="$5" answer
    answer="$(decide "${host}" "${zone}" "${ledger}" "${request}")"
    jq -e --argjson expected "${expected}" '.evaluated == true and .decision == $expected' \
        >/dev/null <<<"${answer}" ||
        fail "${host}: ${zone}/${ledger} ${request} is not ${expected}: ${answer}"
    jq -er '.id' <<<"${answer}"
}

# `host` refuses `zone/ledger` as a ledger it does not serve.
expect_not_served() {
    local host="$1" zone="$2" ledger="$3" answer
    answer="$(decide "${host}" "${zone}" "${ledger}" permit.json)"
    jq -e '.code == "ledger_not_served"' >/dev/null <<<"${answer}" ||
        fail "${host} answered for ${zone}/${ledger}, which its memberships do not cover: ${answer}"
}

cmd_assert() {
    local profile="${1:?the profile}" phase="${2:-}"
    case "${profile}" in
    all-in-one) assert_all_in_one ;;
    split-plane)
        case "${phase}" in
        "") assert_split_plane ;;
        *) drill_restore "${phase}" ;;
        esac
        ;;
    multi-data-plane) assert_multi_data_plane ;;
    multi-group) assert_multi_group ;;
    temporal-replicas) assert_temporal "${phase}" ;;
    *) fail "no profile ${profile}" ;;
    esac
    printf '\nproved: %s%s\n' "${profile}" "${phase:+ (${phase})}"
}

assert_all_in_one() {
    step "all-in-one: the development baseline"
    wait_serving all-in-one acme main
    expect_decision all-in-one acme main permit.json true >/dev/null
    expect_decision all-in-one acme main deny.json false >/dev/null
    log "a permit and a deny, as the policies say"
}

# The resource of `zone/ledger`'s decision stream: what both ends of `decisions.ship` name it by.
decisions_resource() {
    printf 'plane/data/zone/%s/ledger/%s' "$(zone_id control-plane "$1")" "$(ledger_id control-plane "$1" "$2")"
}

# A Host's id as the streams name a producer: the UUID's hex, without its dashes.
producer_of() {
    pg --host-endpoint "$(host_endpoint "$1")" host identity show | jq -er '.host_id | gsub("-"; "")'
}

frontier() { # host, resource
    pg --host-endpoint "$(host_endpoint "$1")" host streams frontier data decisions --resource "$2"
}

# Waits until every run `host` wrote on `resource` is sealed and acknowledged through its last
# record: nothing it recorded is left on it unshipped. Prints the records it holds.
wait_shipped() {
    local host="$1" resource="$2" deadline=$((SECONDS + ${3:-240})) answer
    while :; do
        answer="$(frontier "${host}" "${resource}")"
        if jq -e '[.producer[] | select(.last_seq > 0)] | length > 0 and
                  all(.sealed == .last_seq and .acknowledged == .last_seq)' >/dev/null <<<"${answer}"; then
            jq '[.producer[].last_seq] | add' <<<"${answer}"
            return
        fi
        [ "${SECONDS}" -lt "${deadline}" ] || fail "${host} still holds unshipped records: ${answer}"
        sleep 5
    done
}

# What the coordinator holds of `producer`'s runs on `resource`: the records it acknowledged.
held_from() { # resource, producer
    frontier control-plane "$1" |
        jq --arg producer "$2" '[.consumer[] | select(.producer == $producer) | .acked] | add // 0'
}

# Both ends of every membership of `member` name the exact fingerprints the enrollment approved and
# pinned: the coordinator holds the member's, the member pins the coordinator's.
assert_enrolled() {
    local member="$1" member_fp coordinator_fp
    member_fp="$(fingerprint "${member}")"
    coordinator_fp="$(fingerprint control-plane)"
    pg --host-endpoint "$(host_endpoint "${member}")" host members list |
        jq -e --arg fp "${coordinator_fp}" \
            '[.members[] | select(.role == "member")] | length == 2 and
             all(.status == "active" and .coordinator.fingerprint == $fp)' >/dev/null ||
        fail "${member}: its memberships do not pin ${coordinator_fp}"
    pg --host-endpoint "$(host_endpoint control-plane)" host members list |
        jq -e --arg fp "${member_fp}" \
            '[.members[] | select(.role == "coordinator" and .member.fingerprint == $fp)] | length == 2 and
             all(.status == "active")' >/dev/null ||
        fail "the coordinator holds no two active memberships of ${member} (${member_fp})"
    log "${member}: two active memberships; the coordinator holds ${member_fp}, the member pins ${coordinator_fp}"
}

assert_split_plane() {
    step "split-plane: exact identities, enrolled with nobody in the loop"
    assert_enrolled data-plane
    # One-time invitations, each expecting the member's exact fingerprint, each spent by its join.
    pg --host-endpoint "$(host_endpoint control-plane)" host members invite list |
        jq -e --arg fp "$(fingerprint data-plane)" \
            '.invites | length == 2 and
             all(.max_uses == 1 and .status == "consumed" and .expected_fingerprint == $fp)' >/dev/null ||
        fail "the invitations are not two one-time ones for the member's fingerprint, both spent"
    log "two one-time invitations, each for the member's exact fingerprint, each spent by its join"

    step "split-plane: decisions answered from the mirror"
    wait_serving data-plane acme main
    expect_decision data-plane acme main permit.json true >/dev/null
    expect_decision data-plane acme main deny.json false >/dev/null
    log "a permit and a deny, as the policies the Data Plane mirrored say"

    step "split-plane: the evidence shipped, verified and attributed"
    local resource producer recorded held
    resource="$(decisions_resource acme main)"
    producer="$(producer_of data-plane)"
    recorded="$(wait_shipped data-plane "${resource}")"
    held="$(held_from "${resource}" "${producer}")"
    [ "${held}" = "${recorded}" ] ||
        fail "the coordinator acknowledged ${held} of the ${recorded} records ${producer} wrote"
    pg --host-endpoint "$(host_endpoint control-plane)" host streams signers data decisions --resource "${resource}" |
        jq -e --arg producer "${producer}" \
            '[.runs[] | select(.producer == $producer) | .spans[].kid] | length > 0 and all(startswith("data.attest:"))' \
            >/dev/null || fail "the coordinator verified ${producer}'s batches under no data.attest key"
    # The coordinator is configured with no store and no producer key file (the static check in
    # `crates/permguard-conformance/tests/compose.rs`): what verified the batches is the ring the
    # membership pinned.
    log "the coordinator holds all ${recorded} records of ${producer}, verified under its pinned data.attest ring"
}

# The restore drill (WP-7.7, `scripts/drill-restore.sh`), in four phases on the split-plane lab:
#
#   backup    online: an application-consistent backup of the Data Plane's volume, mounted read-only
#             at /drill/data-plane, then decisions the backup does not hold, shipped
#   restore   offline, the Data Plane stopped and its volume mounted: the volume lost, the snapshot
#             verified and put back, the lost Host fenced, the snapshot restored in `dr` mode, its
#             producer runs rolled over
#   fence     the restored Host's memberships fenced on the coordinator before it starts (P9)
#   restored  online again: the same Host and identity, serving its ledger, shipping what it
#             records in the successors of the runs the restore rolled over, its memberships active
#
# What each phase learnt is kept under the lab's state, `drill/`, for the next one and for the
# drill's record.
drill_restore() {
    local phase="$1" drill="${state}/drill" resource
    resource="$(decisions_resource acme main)"
    case "${phase}" in
    backup)
        step "restore drill: an application-consistent backup of the Data Plane"
        rm -rf "${drill}"
        mkdir -p "${drill}"
        local prepared identity snapshot_id
        identity="$(pg --host-endpoint "$(host_endpoint data-plane)" host identity show)"
        jq -er '.host_id' <<<"${identity}" >"${drill}/host_id"
        jq -er '.fingerprint' <<<"${identity}" >"${drill}/pin"
        prepared="$(pg --host-endpoint "$(host_endpoint data-plane)" host backup prepare \
            --token-out "${drill}/backup.token")"
        jq -er '.manifest' <<<"${prepared}" >"${drill}/manifest.txt"
        # The storage driver's snapshot, inside the barrier: the Host writes nothing until finalized.
        cp -a /drill/data-plane/volume "${drill}/snapshot"
        snapshot_id="drill:$(date -u +%Y%m%dT%H%M%SZ)"
        pg --host-endpoint "$(host_endpoint data-plane)" host backup finalize \
            --backup-token-file "${drill}/backup.token" --snapshot-id "${snapshot_id}" |
            jq -e '.state == "finalized"' >/dev/null || fail "the backup was not finalized"
        rm -f "${drill}/backup.token"
        # The runs the snapshot holds: what the restore rolls over.
        pg --host-endpoint "$(host_endpoint data-plane)" host streams runs data decisions \
            --resource "${resource}" | jq -c '[.runs[].run]' >"${drill}/snapshot_runs"
        # Kept outside the snapshot, as an operator keeps it.
        pg --host-endpoint "$(host_endpoint data-plane)" host keys bundle export --resource host \
            --out "${drill}/bundle.json" >/dev/null
        log "backup ${snapshot_id} finalized; the manifest, the bundle and the pin kept beside it"

        step "restore drill: decisions the backup does not hold"
        local recorded
        expect_decision data-plane acme main permit.json true >/dev/null
        expect_decision data-plane acme main deny.json false >/dev/null
        recorded="$(wait_shipped data-plane "${resource}")"
        echo "${recorded}" >"${drill}/recorded_before_loss"
        log "the Data Plane recorded and shipped ${recorded} records before its volume is lost"
        ;;
    restore)
        step "restore drill: the volume lost, the snapshot verified and put back"
        [ -f "${drill}/manifest.txt" ] || fail "no backup: run the backup phase first"
        find "${volume}" -mindepth 1 -delete
        cp -a "${drill}/snapshot/." "${volume}/"
        permguard -o json backup verify --volume "${volume}" --manifest "${drill}/manifest.txt" \
            --bundle "${drill}/bundle.json" --pin "$(cat "${drill}/pin")" |
            jq -e '.consistency == "application_consistent"' >/dev/null ||
            fail "the snapshot does not verify against its manifest"
        log "the snapshot verifies: application-consistent, under the pinned identity"

        step "restore drill: the lost Host fenced, the snapshot restored in dr mode"
        permguard-data-plane volume claim --volume "${volume}" --next >/dev/null
        listener_env data-plane permguard-data-plane
        local config=/opt/permguard/lab/data-plane.yml restored
        permguard -o json restore plan --mode dr --reason "the restore drill" --out "${drill}/restore.plan" \
            --volume "${volume}" --server-config "${config}" >/dev/null
        restored="$(permguard -o json restore run --mode dr --confirm-file "${drill}/restore.plan" \
            --volume "${volume}" --server-config "${config}")"
        jq -e --arg host "$(cat "${drill}/host_id")" \
            '.mode == "dr" and .host_id == $host and (.previous_boot_id | length) > 0' \
            >/dev/null <<<"${restored}" || fail "the dr restore did not keep the Host: ${restored}"
        # The next start is a new incarnation: a new boot id under the claim the fence moved; the
        # snapshot's runs rolled over, so the restored Host appends to none of them.
        jq -e '.streams.runs_rolled_over >= 1 and (.streams.forked | length) == 0' >/dev/null \
            <<<"${restored}" || fail "the restore rolled no producer run over: ${restored}"
        jq -c '{previous_boot_id, plan_id, runs_rolled_over: .streams.runs_rolled_over}' \
            <<<"${restored}" >"${drill}/restored.json"
        local verify
        verify="$(permguard-data-plane volume verify --volume "${volume}" 2>&1)" ||
            fail "volume verify: ${verify}"
        grep -q ' 0 findings' <<<"${verify}" || fail "volume verify: ${verify}"
        log "restored in dr mode as the same Host; volume verify finds nothing"
        ;;
    fence)
        # P9: memberships fenced before remote work. The Host lost may still hold sessions on its
        # coordinator; the fence ends them and raises each membership's epoch, and the restored
        # Host syncs to the new one on its first session.
        step "restore drill: the restored Host's memberships fenced on the coordinator"
        local member_fp memberships fenced
        member_fp="$(cat "${drill}/pin")"
        memberships="$(pg --host-endpoint "$(host_endpoint control-plane)" host members list |
            jq -c --arg fp "${member_fp}" \
                '[.members[] | select(.role == "coordinator" and .member.fingerprint == $fp) |
                  {id: .membership_id, revision, epoch}]')"
        jq -e 'length == 2' >/dev/null <<<"${memberships}" ||
            fail "the coordinator does not hold the restored Host's two memberships: ${memberships}"
        fenced=0
        while read -r membership; do
            pg --host-endpoint "$(host_endpoint control-plane)" host members fence \
                "$(jq -r .id <<<"${membership}")" --expected-revision "$(jq -r .revision <<<"${membership}")" \
                --reason "the restore drill: the Host was restored in dr mode" |
                jq -e --argjson epoch "$(jq .epoch <<<"${membership}")" \
                    '.status == "active" and .epoch == $epoch + 1' >/dev/null ||
                fail "the membership ${membership} was not fenced"
            fenced=$((fenced + 1))
        done < <(jq -c '.[]' <<<"${memberships}")
        log "${fenced} memberships fenced: active, each at its next epoch"
        ;;
    restored)
        step "restore drill: the same Host, serving and shipping again"
        local identity producer member_fp held answer member_runs coordinator_runs
        identity="$(pg --host-endpoint "$(host_endpoint data-plane)" host identity show)"
        jq -e --arg host "$(cat "${drill}/host_id")" --arg pin "$(cat "${drill}/pin")" \
            '.host_id == $host and .fingerprint == $pin' >/dev/null <<<"${identity}" ||
            fail "the restored Host is not the Host that was backed up: ${identity}"
        assert_enrolled data-plane
        wait_serving data-plane acme main
        expect_decision data-plane acme main permit.json true >/dev/null
        expect_decision data-plane acme main deny.json false >/dev/null
        log "the restored Data Plane serves its ledger and records what it answers"

        # The restore rolled the snapshot's run over, so what the restored Host records lands in
        # a successor, a new run to the coordinator: every run shipped whole, the coordinator
        # keeping what it acknowledged of the snapshot's run and holding the successors whole.
        wait_shipped data-plane "${resource}" 300 >/dev/null
        producer="$(producer_of data-plane)"
        member_runs="$(pg --host-endpoint "$(host_endpoint data-plane)" host streams runs data decisions \
            --resource "${resource}")"
        coordinator_runs="$(pg --host-endpoint "$(host_endpoint control-plane)" host streams runs data decisions \
            --resource "${resource}")"
        # Every run holding records is held by the coordinator at least as far as the Host holds
        # it (the snapshot's further: what it acknowledged before the loss), and some run the
        # restore opened holds records, held whole.
        jq -e -n --argjson member "${member_runs}" --argjson coordinator "${coordinator_runs}" \
            --arg producer "${producer}" --argjson snapshot "$(cat "${drill}/snapshot_runs")" \
            'def held($run): [$coordinator.runs[] | select(.producer == $producer and .run == $run)][0].acked // 0;
             [$member.runs[] | select(.last_seq > 0)] as $holding |
             all($holding[]; held(.run) >= .last_seq) and
             any($holding[]; (.run | IN($snapshot[]) | not) and held(.run) == .last_seq)' >/dev/null ||
            fail "the coordinator does not hold the restored Host's runs: ${member_runs} ${coordinator_runs}"
        held="$(held_from "${resource}" "${producer}")"
        [ "${held}" -gt "$(cat "${drill}/recorded_before_loss")" ] ||
            fail "the coordinator holds ${held} records of ${producer}, no more than before the loss"
        member_fp="$(fingerprint data-plane)"
        answer="$(pg --host-endpoint "$(host_endpoint control-plane)" host members list)"
        jq -e --arg fp "${member_fp}" \
            '[.members[] | select(.role == "coordinator" and .member.fingerprint == $fp)] |
             length == 2 and all(.status == "active")' >/dev/null <<<"${answer}" ||
            fail "a membership of the restored Host is not active: ${answer}"
        log "shipping resumed: the runs the restore opened held whole, ${held} records held in all, both memberships active"

        jq -n --arg host "$(cat "${drill}/host_id")" --argjson held "${held}" \
            --argjson before "$(cat "${drill}/recorded_before_loss")" \
            --slurpfile restored "${drill}/restored.json" \
            '{host_id: $host, previous_boot_id: $restored[0].previous_boot_id, plan_id: $restored[0].plan_id,
              runs_rolled_over: $restored[0].runs_rolled_over, recorded_before_loss: $before,
              held_by_coordinator: $held, shipping: "resumed"}' \
            >"${drill}/result.json"
        ;;
    *) fail "no restore drill phase ${phase}" ;;
    esac
}

assert_multi_data_plane() {
    step "multi-data-plane: two independently identified Data Planes"
    assert_enrolled data-plane-a
    assert_enrolled data-plane-b
    local a b
    a="$(producer_of data-plane-a)"
    b="$(producer_of data-plane-b)"
    [ "${a}" != "${b}" ] || fail "the two Data Planes share the Host ${a}"
    [ "$(fingerprint data-plane-a)" != "$(fingerprint data-plane-b)" ] || fail "one fingerprint"
    log "data-plane-a is ${a}, data-plane-b is ${b}: one static file, two identities"

    step "multi-data-plane: per-producer streams, each attributed"
    wait_serving data-plane-a acme main
    wait_serving data-plane-b acme main
    expect_decision data-plane-a acme main permit.json true >/dev/null
    expect_decision data-plane-a acme main deny.json false >/dev/null
    expect_decision data-plane-b acme main permit.json true >/dev/null
    local resource recorded_a recorded_b
    resource="$(decisions_resource acme main)"
    recorded_a="$(wait_shipped data-plane-a "${resource}")"
    recorded_b="$(wait_shipped data-plane-b "${resource}")"
    frontier control-plane "${resource}" |
        jq -e --arg a "${a}" --arg b "${b}" '[.consumer[].producer] | unique == ([$a, $b] | sort)' >/dev/null ||
        fail "the coordinator's streams of ${resource} are not exactly ${a}'s and ${b}'s"
    [ "$(held_from "${resource}" "${a}")" = "${recorded_a}" ] || fail "${a}'s records are not all held"
    [ "$(held_from "${resource}" "${b}")" = "${recorded_b}" ] || fail "${b}'s records are not all held"
    log "the coordinator holds ${recorded_a} records under ${a} and ${recorded_b} under ${b}"

    step "multi-data-plane: no record of one producer lost to the other"
    local before after
    before="$(frontier control-plane "${resource}" | jq -c --arg b "${b}" '[.consumer[] | select(.producer == $b)]')"
    expect_decision data-plane-a acme main permit.json true >/dev/null
    expect_decision data-plane-a acme main permit.json true >/dev/null
    recorded_a="$(wait_shipped data-plane-a "${resource}")"
    [ "$(held_from "${resource}" "${a}")" = "${recorded_a}" ] || fail "${a}'s new records are not held"
    after="$(frontier control-plane "${resource}" | jq -c --arg b "${b}" '[.consumer[] | select(.producer == $b)]')"
    [ "${before}" = "${after}" ] || fail "${b}'s stream changed while only ${a} shipped: ${before} → ${after}"
    log "${a} shipped and was acknowledged through ${recorded_a}; ${b}'s stream is untouched: ${after}"
}

assert_multi_group() {
    step "multi-group: each group serves its zone, and only it"
    wait_serving data-plane-acme acme main
    wait_serving data-plane-beta beta main
    expect_decision data-plane-acme acme main permit.json true >/dev/null
    expect_decision data-plane-beta beta main permit.json true >/dev/null
    expect_not_served data-plane-acme beta main
    expect_not_served data-plane-beta acme main
    log "data-plane-acme answers acme and not beta; data-plane-beta the reverse"

    step "multi-group: each group's memberships reach its zone and nothing else"
    local group id fp
    for group in acme beta; do
        id="$(zone_id control-plane "${group}")"
        fp="$(fingerprint "data-plane-${group}")"
        pg --host-endpoint "$(host_endpoint control-plane)" host members list |
            jq -e --arg fp "${fp}" --arg id "${id}" \
                '[.members[] | select(.role == "coordinator" and .member.fingerprint == $fp)] as $held |
                 ($held | length) == 2 and
                 ($held | all(.selector | startswith("plane/control/zone/\($id)/") or startswith("plane/data/zone/\($id)/"))) and
                 ($held | all(.tasks | all(.selector | contains("/zone/\($id)/"))))' >/dev/null ||
            fail "data-plane-${group}'s memberships reach beyond zone ${group} (${id})"
        log "data-plane-${group}: both memberships and every task inside zone ${group}"
    done
}

# One Dogwood occurrence of the example to `host`'s temporal interface: the fixture's document
# with the event id `id` and the instant now, or `document` as given. Prints the answer.
submit() { # host, fixture, id
    local host="$1" fixture="$2" id="$3"
    jq --arg id "${id}" '.event.data.event_id = $id | .event.data.occurred_at = (now | todate)' \
        "${examples}/dogwood-session-access/${fixture}" | submit_document "${host}"
}

# The fixture's document as `user`'s, with the event id `id` and the instant now: a user of its own
# per check, so one check's history is never another's.
as_user() { # user, fixture, id
    jq --arg user "$1" --arg id "$3" \
        '.event.data.event_id = $id | .event.data.occurred_at = (now | todate)
         | .event.data.principal = "Drupe::OAuthUser::\"\($user)\""
         | .event.data.logged.input.user = $user
         | .event.data.request_context.input.user = $user' \
        "${examples}/dogwood-session-access/$2"
}

submit_document() { # host; the document on standard input
    curl -sS --cacert "${pki}/ca.crt" --cert "${pki}/operator.crt" --key "${pki}/operator.key" \
        -X POST "$(data_endpoint "$1")/temporal/v1alpha1/events" \
        -H 'content-type: application/json' --data-binary @-
}

# Waits until `host` decides on the temporal ledger: its mirror loaded it. Each probe is a read by
# a user of its own, which no check reads.
wait_serving_temporal() { # host, session
    local host="$1" deadline=$((SECONDS + 180)) attempt=0 answer
    while :; do
        attempt=$((attempt + 1))
        answer="$(as_user "probe-$2" requests/2-read-inside-window.json "$2-probe-${host}-${attempt}" |
            submit_document "${host}")"
        jq -e '.outcome == "decided"' >/dev/null 2>&1 <<<"${answer}" && return
        [ "${SECONDS}" -lt "${deadline}" ] || fail "${host} does not serve the temporal ledger: ${answer}"
        sleep 2
    done
}

# How long an occurrence recorded on one replica may take to decide on the other: the lab's bound
# under `shared-eventual`, not a consistency mode's. The member ships and imports on its periodic
# pass, a minute apart, so two passes and their latency fit inside it.
convergence_bound="${LAB_CONVERGENCE_SECONDS:-240}"

assert_temporal() {
    local phase="${1:-converge}" session
    case "${phase}" in
    converge)
        session="lab-$(date +%s)"
        echo "${session}" >"${state}/temporal-session"
        step "temporal-replicas: an occurrence on one replica decides on the other"
        wait_serving_temporal temporal-a "${session}"
        wait_serving_temporal temporal-b "${session}"
        local answer
        answer="$(submit temporal-b requests/1-read-before-login.json "${session}-read-before-login")"
        jq -e '.outcome == "decided" and .decision == false' >/dev/null <<<"${answer}" ||
            fail "temporal-b answered alice's first read with ${answer}"
        log "temporal-b denies alice's read: nothing has happened yet"
        answer="$(submit temporal-a events/1-login-request.json "${session}-login-request")"
        jq -e '.outcome == "decided"' >/dev/null <<<"${answer}" || fail "temporal-a: ${answer}"
        answer="$(submit temporal-a events/2-login-response.json "${session}-login-response")"
        jq -e '.outcome == "accepted"' >/dev/null <<<"${answer}" || fail "temporal-a: ${answer}"
        log "temporal-a recorded alice's login"
        local started=${SECONDS} attempt=0
        while :; do
            attempt=$((attempt + 1))
            answer="$(submit temporal-b requests/2-read-inside-window.json "${session}-read-${attempt}")"
            jq -e '.outcome == "decided" and .decision == true' >/dev/null <<<"${answer}" && break
            [ $((SECONDS - started)) -lt "${convergence_bound}" ] ||
                fail "alice's login on temporal-a did not decide on temporal-b within ${convergence_bound}s: ${answer}"
            sleep 5
        done
        log "temporal-b permits alice's read on the login temporal-a recorded, $((SECONDS - started))s later (bound ${convergence_bound}s): $(jq -c '.history' <<<"${answer}")"

        step "temporal-replicas: after convergence an equal occurrence is no conflict and a conflict blocks"
        # The same login, byte for byte, accepted by both replicas; and one login id carrying a
        # different occurrence on each. Recorded on temporal-a in that order, so once temporal-b
        # sees the conflict it has imported the equal one too.
        local equal="equal-${session}" conflict="conflict-${session}" document
        document="$(as_user "${equal}" events/2-login-response.json "${session}-equal-login")"
        for host in temporal-a temporal-b; do
            answer="$(submit_document "${host}" <<<"${document}")"
            jq -e '.outcome == "accepted"' >/dev/null <<<"${answer}" || fail "${host}: ${answer}"
        done
        document="$(as_user "${conflict}" events/2-login-response.json "${session}-conflict-login")"
        answer="$(submit_document temporal-a <<<"${document}")"
        jq -e '.outcome == "accepted"' >/dev/null <<<"${answer}" || fail "temporal-a: ${answer}"
        answer="$(jq '.event.data.logged.input.server = "s2" | .event.data.request_context.input.server = "s2"' \
            <<<"${document}" | submit_document temporal-b)"
        jq -e '.outcome == "accepted"' >/dev/null <<<"${answer}" ||
            fail "temporal-b refused its own occurrence before it imported the other: ${answer}"
        log "both replicas accepted the equal login; each accepted its own occurrence under one id"
        # The control: before the import, temporal-b's own occurrence permits its user, so the
        # denial below is the conflict's and not its document's.
        answer="$(as_user "${conflict}" requests/2-read-inside-window.json "${session}-conflict-read-0" |
            submit_document temporal-b)"
        jq -e '.outcome == "decided" and .decision == true' >/dev/null <<<"${answer}" ||
            fail "temporal-b's own login does not count before the import: ${answer}"
        started=${SECONDS}
        attempt=0
        while :; do
            attempt=$((attempt + 1))
            answer="$(as_user "${conflict}" requests/2-read-inside-window.json "${session}-conflict-read-${attempt}" |
                submit_document temporal-b)"
            jq -e '.outcome == "decided" and .decision == false' >/dev/null <<<"${answer}" && break
            [ $((SECONDS - started)) -lt "${convergence_bound}" ] ||
                fail "the conflicting login still counts on temporal-b after ${convergence_bound}s: ${answer}"
            sleep 5
        done
        log "the conflicting login is quarantined on temporal-b once it imported temporal-a's, $((SECONDS - started))s later"
        answer="$(as_user "${equal}" requests/2-read-inside-window.json "${session}-equal-read" | submit_document temporal-b)"
        jq -e '.outcome == "decided" and .decision == true' >/dev/null <<<"${answer}" ||
            fail "the equal login no longer counts on temporal-b after the import: ${answer}"
        # What this proves is that the equal login is not a conflict and still counts; that it
        # counts once needs a count-sensitive observable no example policy has (status.md).
        log "the equal login, held by both replicas, is no conflict and still counts: temporal-b permits its user"
        ;;
    failover)
        session="$(cat "${state}/temporal-session")"
        step "temporal-replicas: temporal-a stopped, temporal-b decides on its history alone"
        local answer
        answer="$(submit temporal-b requests/2-read-inside-window.json "${session}-read-failover")"
        jq -e '.outcome == "decided" and .decision == true' >/dev/null <<<"${answer}" ||
            fail "temporal-b no longer permits alice's read with temporal-a stopped: ${answer}"
        answer="$(submit temporal-b requests/4-read-other-user.json "${session}-read-bob")"
        jq -e '.outcome == "decided" and .decision == false' >/dev/null <<<"${answer}" ||
            fail "temporal-b permitted bob on alice's login: ${answer}"
        log "temporal-b still permits alice and denies bob, with temporal-a stopped"
        ;;
    *) fail "no phase ${phase}" ;;
    esac
}

command="${1:-}"
shift || true
case "${command}" in
pki) cmd_pki "$@" ;;
serve) cmd_serve "$@" ;;
catalog) cmd_catalog "$@" ;;
enroll) cmd_enroll "$@" ;;
assert) cmd_assert "$@" ;;
*)
    sed -n '5,13p' "$0" >&2
    exit 64
    ;;
esac
