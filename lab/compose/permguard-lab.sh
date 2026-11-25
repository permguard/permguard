#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The Compose lab's authority and its checks (TD-3), run inside the lab's network by the lab image.
#
#   permguard-lab pki                       the lab's certificate authority, every Host's certificate
#                                           and the operator's, once
#   permguard-lab serve <binary> <config>   one Host: claim its volume, bootstrap the operator's
#                                           certificate, serve
#   permguard-lab import <binary> <config>  the stopped Host's volume moved to the `postgresql-s3`
#                                           backend its configuration names
#   permguard-lab offline <binary> <config> the offline commands on that backend, the Host stopped:
#                                           its trails copied and verified, a cursor root rotated
#   permguard-lab catalog <profile>         the zones, ledgers and policies a profile serves
#   permguard-lab enroll <profile>          every data plane of a profile, enrolled with exact
#                                           fingerprints over one-time invitations
#   permguard-lab assert <profile> [phase]  what the profile must prove; the all-in-one's phases
#                                           are `rotation`, `authority`, `freshness` and
#                                           `tail-wait`, the multi-data-plane's `tokens`, `latency`,
#                                           `freshness`, `rotation` and `offline`
#
# A lab is an isolated test authority, and only a lab does what this script does: it issues every
# certificate, bootstraps its operator's certificate on every volume before the Host starts, acts as
# the Authority Plane's `admin` whose key it reads from the coordinator's volume, and approves the exact
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
    temporal-a temporal-b lab-postgres lab-s3)

# Where the lab's authority writes the `postgresql-s3` backend's secrets: the database's password,
# the bucket's secret and the key-encryption key that seals the Host's keys there.
backend="${lab}/backend"

# The CLI keeps its configuration under HOME, which the lab's user does not have.
export HOME="${HOME:-/tmp}"
[ -w "${HOME}" ] || export HOME=/tmp

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
step() { printf '\n== %s\n' "$*" >&2; }
fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# The CLI as the lab's operator's certificate alone, the lab's authority, JSON out: what a Host's
# bootstrap principal is, and nothing on a Plane.
pg_cert() {
    permguard -o json --tls-ca-file "${pki}/ca.crt" --tls-cert-file "${pki}/operator.crt" \
        --tls-key-file "${pki}/operator.key" "$@"
}

# The access key a key file names.
access_key_of() { sed -n 's/^access_key: //p' "$1"; }

# The coordinators' volumes, which the lab's tools mount read-only: where the Authority Plane's
# first start wrote `admin`'s key. A lab's concession; a deployment moves the key off the volume.
coordinators="${LAB_COORDINATORS:-/coordinators}"

# The coordinator that runs the Authority Plane and `admin`'s key file on its volume, once its first
# start wrote it: `<host> <file>`. With two Control Plane instances (WP-28.6) the one that made
# `admin` wrote it, and either is reached at the one address, `control-plane`.
admin_key() {
    local instance key
    for instance in all-in-one control-plane control-plane-2; do
        key="${coordinators}/${instance}/volume/planes/authority/admin.key"
        if [ -s "${key}" ]; then
            printf '%s %s\n' "${instance%-2}" "${key}"
            return 0
        fi
    done
    return 1
}

# Where the coordinator's Authority Plane is reached.
authority_endpoint() {
    local held
    held="$(admin_key)" || fail "no coordinator wrote admin's key"
    printf 'https://%s:8443' "${held%% *}"
}

# The CLI as the lab's operator: the connection its certificate's, every call the Authority Plane's
# `admin`'s, by the key its first start wrote, once the coordinator wrote it. The Authority Plane's
# endpoint is the environment's, so a call naming `--authority-endpoint` (gRPC) states its own.
pg() {
    local held key
    if held="$(admin_key)"; then
        key="${held#* }"
        local -x PERMGUARD_AUTHORITY_ENDPOINT="https://${held%% *}:8443"
        pg_cert --access-key "$(access_key_of "${key}")" --secret-key-file "${key}" "$@"
    else
        pg_cert "$@"
    fi
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
            local names="DNS:${host}"
            # On postgresql-s3 both Control Plane instances serve under the same certificate,
            # each reached by its own name too, an endpoint a Data Plane names (WP-28.7).
            if [ "${host}" = control-plane ] && [ "${LAB_BACKEND:-files}" = postgresql-s3 ]; then
                names="${names},DNS:control-plane-1,DNS:control-plane-2"
            fi
            issue "${host}" "${names},URI:${trust_domain}/${host}" "serverAuth,clientAuth"
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
    if [ "${LAB_BACKEND:-files}" = postgresql-s3 ]; then
        (
            umask 077
            mkdir -p "${backend}" "${lab}/s3/permguard"
            head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${backend}/postgres-password"
            head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${backend}/s3-secret"
            head -c 32 /dev/urandom >"${backend}/kek"
            # The Host's own secrets, written once for every instance (WP-28.6): material an
            # instance generated would be its own, and the database refuses another's.
            for name in audit-pseudonym zone-root; do
                head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${backend}/${name}"
            done
        )
        log "the lab authority wrote the postgresql-s3 backend's secrets, the Host's and its bucket"
    fi
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
    # The coordinator runs the Authority Plane: TLS under the lab's authority, no client
    # certificate asked, a client proving itself by its access key or its token.
    case "${host}" in
    control-plane | all-in-one)
        export "PERMGUARD_AUTHORITY_HTTP_ADVERTISED_URL=https://${host}:8443"
        export "PERMGUARD_AUTHORITY_HTTP_TLS_CERT=${pki}/${host}.crt"
        export "PERMGUARD_AUTHORITY_HTTP_TLS_KEY=${pki}/${host}.key"
        export "PERMGUARD_AUTHORITY_GRPC_TLS_CERT=${pki}/${host}.crt"
        export "PERMGUARD_AUTHORITY_GRPC_TLS_KEY=${pki}/${host}.key"
        ;;
    esac
    # Every Host fetches the Authority Plane's keys and lists, if it does not run it, under the
    # lab's authority.
    export "PERMGUARD_AUTHORITY_TLS_CA=${pki}/ca.crt"
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

# The `postgresql-s3` backend's secrets the lab's authority wrote, installed as files of this
# instance, beside its configuration: the database's password, the bucket's secret, the KEK, and
# the Host's pseudonymisation key and coordinator root, the same in every instance, as one Secret
# mounted in each.
backend_secrets() {
    local secrets="${volume}/operations/secrets" name
    mkdir -p "${secrets}"
    chmod 0700 "${volume}" "${volume}/operations" "${secrets}"
    for name in postgres-password s3-secret kek audit-pseudonym zone-root; do
        install -m 0600 "${backend}/${name}" "${secrets}/${name}"
    done
}

# `import <binary> <config>`: the stopped Host's volume moved into the `postgresql-s3` backend its
# configuration names (iteration 03, WP-28.1), offline, between its last start on files and its
# first on the backend, as an operator runs it.
cmd_import() {
    local binary="$1" config="$2" host="${LAB_HOST:?the service name, LAB_HOST}" imported
    [ "${PERMGUARD_STORAGE_BACKEND:-files}" = postgresql-s3 ] ||
        fail "the import's configuration names no postgresql-s3 backend"
    listener_env "${host}" "${binary}"
    imported="$(permguard -o json migrate import --volume "${volume}" --server-config "${config}")" ||
        fail "${host}: the import of its volume failed"
    jq -e '.stores | length > 0' >/dev/null <<<"${imported}" || fail "${host}: the import said nothing"
    log "${host}: its volume imported into postgresql-s3, deployment $(jq -r '.deployment' <<<"${imported}"):" \
        "$(jq -r '[.stores[] | select(.records > 0) | "\(.store) \(.records)"] | join(", ")' <<<"${imported}")"
}

# `offline <binary> <config>`: what an operator does on the `postgresql-s3` backend with the Host
# stopped (iteration 03, WP-28.1): the trails copied out of the database and the bucket and checked
# by the server binary's own verification, then the decision store's cursor root rotated.
cmd_offline() {
    local binary="$1" config="$2" host="${LAB_HOST:?the service name, LAB_HOST}" copy copied rotated
    [ "${PERMGUARD_STORAGE_BACKEND:-files}" = postgresql-s3 ] ||
        fail "the offline commands' configuration names no postgresql-s3 backend"
    listener_env "${host}" "${binary}"
    copy="$(mktemp -d)/audit"
    copied="$(permguard -o json host audit copy --server-config "${config}" --out "${copy}")" ||
        fail "${host}: its trails were not copied"
    jq -e '.trails > 0' >/dev/null <<<"${copied}" || fail "${host}: no trail was copied: ${copied}"
    "${binary}" audit verify --directory "${copy}/trails" --keys "${copy}/host.operations.keys.json" >&2 ||
        fail "${host}: the trails copied out of postgresql-s3 do not verify"
    log "${host}: $(jq -r '.trails' <<<"${copied}") trails copied out of postgresql-s3 verify under its host.operations keys"
    rotated="$(permguard -o json evidence rotate-cursor-root --store decisions --server-config "${config}")" ||
        fail "${host}: the decision store's cursor root did not rotate"
    log "${host}: the decision store's cursor root rotated: $(jq -r '.rotated' <<<"${rotated}")"
}

# `serve <binary> <config>`: what a Pod's init containers and its server are, in one container.
# The claim moves forward on every start (TD-1); the operator's certificate is bootstrapped once,
# offline, before the Host first serves; the listeners carry the certificate the lab's authority
# issued to this service's name.
cmd_serve() {
    local binary="$1" config="$2" host="${LAB_HOST:?the service name, LAB_HOST}"
    [ -f "${pki}/${host}.crt" ] || fail "the lab authority issued no certificate to ${host}"
    listener_env "${host}" "${binary}"
    if [ "${PERMGUARD_STORAGE_BACKEND:-files}" = postgresql-s3 ]; then
        # No volume: the Host's state is the database's and the bucket's. Its secrets are files of
        # this instance, beside its configuration, and the bootstrap is the database's.
        backend_secrets
        # The identity made in the database before the first start, as the chart's `identity`
        # init container makes it (WP-28.5); a database that holds one is said so.
        local provisioned
        provisioned="$(permguard -o json host identity provision --if-missing --server-config "${config}")" ||
            fail "${host}: the identity could not be made in the database"
        if [ "$(jq -r '.provisioned' <<<"${provisioned}")" != false ]; then
            log "${host}: the identity is made in the database, $(jq -r '.host_id' <<<"${provisioned}")"
        fi
        if [ ! -f /var/lib/permguard/.lab-operator ]; then
            permguard -o json host grants bootstrap --server-config "${config}" \
                --fingerprint "$(cat "${pki}/operator.fp")" >/dev/null
            touch /var/lib/permguard/.lab-operator
            log "${host}: the lab operator's certificate is the database's bootstrap principal"
        fi
    else
        "${binary}" volume claim --volume "${volume}" --next --create
        # Before an import, the Host on files keeps its keys sealed under the key-encryption key
        # it keeps on the backend after it, and reads the backend's secrets as the import does.
        [ ! -d "${backend}" ] || backend_secrets
        if [ ! -f /var/lib/permguard/.lab-operator ]; then
            permguard -o json host grants bootstrap --volume "${volume}" \
                --fingerprint "$(cat "${pki}/operator.fp")" >/dev/null
            touch /var/lib/permguard/.lab-operator
            log "${host}: the lab operator's certificate is this volume's bootstrap principal"
        fi
    fi
    # TD-5: a member whose invitations the catalog step wrote joins its coordinator by itself, its
    # coordinator pinned apart from them; the enroll step then approves the fingerprint it expects.
    local invited="${state}/join/${host}"
    if [ -f "${invited}/ready" ]; then
        export "PERMGUARD_HOST_JOIN_INVITATION_FILE=${invited}/control.json,${invited}/data.json"
        export "PERMGUARD_HOST_JOIN_PIN_FINGERPRINT=$(cat "${invited}/pin")"
        export "PERMGUARD_HOST_JOIN_NAME=${host}"
        export "PERMGUARD_HOST_JOIN_GROUPS=$(cat "${invited}/group")"
        log "${host}: joins its coordinator by itself from ${invited}"
    fi
    # WP-28.7: the Control Plane's instances a member names besides its memberships' address, by
    # the Host they serve, which discovery states.
    if [ -n "${LAB_COORDINATOR_ENDPOINTS:-}" ]; then
        local coordinator
        coordinator="$(curl -fsS http://control-plane:5443/.well-known/server-configuration |
            jq -er '.host_id')" || fail "${host}: the Control Plane states no Host id"
        export "PERMGUARD_HOST_COORDINATOR_ENDPOINTS=${coordinator} ${LAB_COORDINATOR_ENDPOINTS}"
        log "${host}: reaches ${coordinator} at ${LAB_COORDINATOR_ENDPOINTS}"
    fi
    # The server refuses a `PERMGUARD_` name it does not know; the lab's own are not prefixed.
    unset LAB_HOST LAB_DIR LAB_EXAMPLES LAB_TEMPLATES LAB_COORDINATOR_ENDPOINTS
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

# Waits until the coordinator's Authority Plane wrote `admin`'s key and answers with it.
wait_admin() {
    local deadline=$((SECONDS + 180))
    until admin_key >/dev/null && pg authority service-accounts get admin >/dev/null 2>&1; do
        [ "${SECONDS}" -lt "${deadline}" ] || fail "the Authority Plane's admin key was never written"
        sleep 2
    done
}

# The lab's service account (TA-5): what its samples and checks decide as, by tokens the command
# line obtains with its access key (TC-7).
lab_client() {
    pg authority service-accounts create lab-client --description "the lab's samples and checks" \
        --scope "decision.evaluate,event.submit@plane/data/*" >/dev/null
    rm -f "${state}/lab-client.key"
    pg authority keys create lab-client --secret-out "${state}/lab-client.key" >/dev/null
    log "the lab's service account lab-client: decision.evaluate and event.submit on plane/data/*"
}

# A token of lab-client, obtained at the Authority Plane and kept for half an hour: prints its
# file. Every Data Plane of the cluster verifies it alike.
token_for() {
    local dir="${state}/tokens" file
    file="${dir}/lab-client.jwt"
    if [ -f "${file}" ] && [ -z "$(find "${file}" -mmin +30)" ]; then
        echo "${file}"
        return
    fi
    mkdir -p "${dir}"
    chmod 0700 "${dir}"
    rm -f "${file}"
    pg_cert --authority-endpoint "$(authority_endpoint)" \
        --access-key "$(access_key_of "${state}/lab-client.key")" \
        --secret-key-file "${state}/lab-client.key" authority token \
        --scope "decision.evaluate event.submit" --out "${file}" >/dev/null ||
        fail "the Authority Plane issued lab-client no token"
    echo "${file}"
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
    # An example ships its manifest, which `init` adopts as it is: a name or languages beside it
    # that contradict it are refused. Named only for an example without one.
    if [ -f "${workspace}/manifest.yml" ]; then
        pg -w "${workspace}" init >/dev/null
    else
        pg -w "${workspace}" init "${ledger}" --language "${languages}" >/dev/null
    fi
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
    wait_admin
    once lab-client lab_client
    case "${profile}" in
    temporal-replicas)
        once "ledger-acme-agent-governance" ledger_with "${coordinator}" acme agent-governance dogwood-session-access dogwood
        render_temporal "${coordinator}"
        ;;
    multi-group)
        once "ledger-acme-main" ledger_with "${coordinator}" acme main basics cedar,rego
        once "ledger-beta-main" ledger_with "${coordinator}" beta main basics cedar,rego
        # TD-5: the two groups join by themselves, from the invitations written here, before
        # they start.
        once "invitations-data-plane-acme" invite_member "${coordinator}" data-plane-acme acme
        once "invitations-data-plane-beta" invite_member "${coordinator}" data-plane-beta beta
        ;;
    *)
        once "ledger-acme-main" ledger_with "${coordinator}" acme main basics cedar,rego
        ;;
    esac
}

# TD-5: the invitations `member` joins `coordinator` with by itself, one per membership — its
# Control Plane tree's for `policy.mirror`, its own for `decisions.ship` — written to the lab's
# state, readable by the server's user only, with the coordinator's fingerprint beside them, stated
# apart. A one-time invitation each, named for the member and its group.
invite_member() {
    local coordinator="$1" member="$2" zone="$3" zone_id dir
    zone_id="$(zone_id "${coordinator}" "${zone}")"
    dir="${state}/join/${member}"
    rm -rf "${dir}"
    mkdir -p "${dir}"
    chmod 0700 "${dir}"
    local control="plane/control/zone/${zone_id}/*" data="plane/data/zone/${zone_id}/*"
    invitation "${coordinator}" "${member}" "${zone}" "${control}" \
        "[$(task policy-mirror policy.mirror coordinator member "${control}" policy)]" "${dir}/control.json"
    invitation "${coordinator}" "${member}" "${zone}" "${data}" \
        "[$(task decisions-ship decisions.ship member coordinator "${data}" decision)]" "${dir}/data.json"
    fingerprint "${coordinator}" >"${dir}/pin"
    printf '%s' "${zone}" >"${dir}/group"
    touch "${dir}/ready"
    log "${member}: invited to ${coordinator} for ${zone} (${control}, ${data}); it joins by itself"
}

invitation() { # coordinator, member, group, selector, tasks, file
    local tasks
    tasks="$(mktemp)"
    printf '%s\n' "$5" >"${tasks}"
    (
        umask 077
        pg --host-endpoint "$(host_endpoint "$1")" host members invite create \
            --selector "$4" --tasks "${tasks}" --name "$2" --group "$3" \
            --min-assurance development >"$6"
    ) || fail "$2: the coordinator created no invitation for $4"
    rm -f "${tasks}"
    chmod 0400 "$6"
}

# TD-5: approves the memberships `member` joined by itself, after checking each pending one names
# the member's own fingerprint: the lab's isolated authority approves the exact Host it expects.
approve_joined() {
    local coordinator="$1" member="$2" deadline=$((SECONDS + 180)) fp pending count=0 id revision
    fp="$(fingerprint "${member}")"
    while :; do
        pending="$(pg --host-endpoint "$(host_endpoint "${coordinator}")" host members pending |
            jq -c --arg name "${member}" '[.members[] | select(.name == $name)]')"
        count="$(jq 'length' <<<"${pending}")"
        [ "${count}" -ge 2 ] && break
        [ "${SECONDS}" -lt "${deadline}" ] ||
            fail "${member}: ${count} of its 2 joins reached ${coordinator}"
        sleep 2
    done
    for id in $(jq -r '.[].membership_id' <<<"${pending}"); do
        [ "$(jq -r --arg id "${id}" '.[] | select(.membership_id == $id) | .member.fingerprint' <<<"${pending}")" = "${fp}" ] ||
            fail "${member}: the pending membership ${id} names another Host than ${fp}"
        revision="$(jq -r --arg id "${id}" '.[] | select(.membership_id == $id) | .revision' <<<"${pending}")"
        pg --host-endpoint "$(host_endpoint "${coordinator}")" host members approve "${id}" \
            --expected-revision "${revision}" >/dev/null
    done
    # The member reads its approval by itself, within a minute.
    deadline=$((SECONDS + 150))
    until [ "$(pg --host-endpoint "$(host_endpoint "${member}")" host members list |
        jq '[.members[] | select(.role == "member" and .status == "active")] | length')" -ge 2 ]; do
        [ "${SECONDS}" -lt "${deadline}" ] || fail "${member}: its approved memberships are not active"
        sleep 3
    done
    log "${member}: joined by itself, ${fp} approved, both memberships active"
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
    # A member's session reads its coordinator's memberships within 5 s of a change, on any of
    # its instances (WP-28.4): a sync that reaches another instance than the approval may read the
    # membership pending a moment longer, and the next one reads it active.
    local deadline=$((SECONDS + 15))
    while :; do
        status="$(pg --host-endpoint "$(host_endpoint "${member}")" host members sync "${id}" | jq -r '.status')"
        [ "${status}" = active ] && break
        [ "${status}" = pending ] && [ "${SECONDS}" -lt "${deadline}" ] ||
            fail "${member}: the membership ${id} is ${status} after its sync"
        sleep 2
    done
    log "${member}: member of ${coordinator} for ${selector} (${id}; ${member_fp} approved, ${coordinator_fp} pinned)"
}

# A data plane's two memberships: the policy it mirrors is in the Control Plane's tree, the
# evidence it ships in its own, and a membership's tasks stay inside one Plane's tree.
enroll_data_plane() {
    local coordinator="$1" member="$2" zone="$3" temporal="$4" zone_id
    wait_up "${member}"
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
        if [ -f "${state}/join/${entry%%:*}/ready" ]; then
            wait_up "${entry%%:*}"
            once "joined-${entry%%:*}" approve_joined "${coordinator}" "${entry%%:*}"
        else
            enroll_data_plane "${coordinator}" "${entry%%:*}" "${entry##*:}" "${temporal}"
        fi
    done
}

# ---------------------------------------------------------------------------------------------
# assert
# ---------------------------------------------------------------------------------------------

# A decision from `host` on `zone/ledger` for one of the `basics` example's requests: the CLI's
# answer, whatever it is. A refusal is an answer too, so its status is not this function's.
decide() {
    local host="$1" zone="$2" ledger="$3" request="$4" token="${5:-}"
    # A Data Plane decides by the Authority Plane's tokens: lab-client's, unless the caller names
    # another (`none` for no token at all, the operator's certificate alone).
    [ -n "${token}" ] || token="$(token_for)"
    if [ "${token}" = none ]; then
        pg_cert --data-endpoint "$(data_endpoint "${host}")" check --ignore-workspace \
            -f "${examples}/basics/requests/${request}" --zone "${zone}" --ledger "${ledger}" 2>&1 || true
        return
    fi
    pg_cert --token-file "${token}" --data-endpoint "$(data_endpoint "${host}")" check --ignore-workspace \
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
expect_decision() { # host, zone, ledger, request, expected, [token file]
    local host="$1" zone="$2" ledger="$3" request="$4" expected="$5" token="${6:-}" answer
    answer="$(decide "${host}" "${zone}" "${ledger}" "${request}" "${token}")"
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
    all-in-one)
        case "${phase}" in
        "") assert_all_in_one ;;
        rotation) assert_all_in_one_rotation ;;
        authority) assert_all_in_one_authority ;;
        freshness) assert_freshness all-in-one all-in-one acme main "$(own_resource all-in-one acme main)" ;;
        tail-wait) assert_tail_wait all-in-one ;;
        *) fail "no all-in-one phase ${phase}" ;;
        esac
        ;;
    split-plane)
        case "${phase}" in
        "") assert_split_plane ;;
        before-import | imported) assert_import "${phase}" ;;
        replicas) assert_replicas ;;
        drill-before) drill_before ;;
        drill-database-down) drill_database_down ;;
        drill-database-back) drill_database_back ;;
        drill-database-unanswering) drill_database_unanswering ;;
        drill-s3-down) drill_s3_down ;;
        drill-s3-back) drill_s3_back ;;
        drill-churn) drill_churn 30 ;;
        drill-churn-check) drill_churn_check ;;
        drill-concurrent) drill_concurrent ;;
        drill-load) drill_load ;;
        *) drill_restore "${phase}" ;;
        esac
        ;;
    multi-data-plane)
        case "${phase}" in
        "") assert_multi_data_plane ;;
        tokens) assert_tokens ;;
        latency) assert_latency ;;
        freshness) assert_freshness data-plane-a control-plane acme main "$(decisions_resource acme main)" ;;
        rotation) assert_tokens_rotation ;;
        offline) assert_tokens_offline ;;
        ship-before) ship_before ;;
        ship-decide) ship_decide ;;
        ship-drained) ship_drained ;;
        ship-report) ship_report ;;
        *) fail "no multi-data-plane phase ${phase}" ;;
        esac
        ;;
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
    wait_shipped all-in-one "$(own_resource all-in-one acme main)" >/dev/null
    log "its decisions reach its own Control Plane, sealed and acknowledged"
}

# The resource of `zone/ledger`'s decision stream on a Host that runs both Planes.
own_resource() { # host, zone, ledger
    printf 'plane/data/zone/%s/ledger/%s' "$(zone_id "$1" "$2")" "$(ledger_id "$1" "$2" "$3")"
}

# Across key rotations (BUG-0195): the keys replaced every two minutes
# (`docker-compose.lab.rotation.yml`), a decision every round is sealed and acknowledged by the
# Host's own Control Plane within its bound, and the Host never reports `degraded: shipping`.
# `data.attest` must rise by three epochs: three keys prepublished, and so activated, in the run.
assert_all_in_one_rotation() {
    local minutes="${LAB_ROTATION_MINUTES:-8}" resource first epoch deadline
    step "all-in-one: decisions across key rotations, ${minutes} minutes"
    wait_serving all-in-one acme main
    resource="$(own_resource all-in-one acme main)"
    first="$(ring_epoch all-in-one data.attest)"
    deadline=$((SECONDS + minutes * 60))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        expect_decision all-in-one acme main permit.json true >/dev/null
        wait_shipped all-in-one "${resource}" 120 >/dev/null
        pg --host-endpoint "$(host_endpoint all-in-one)" host status |
            jq -e '[.degraded[]? | select(.capability == "shipping")] | length == 0' >/dev/null ||
            fail "all-in-one reports degraded: shipping"
        sleep 15
    done
    epoch="$(ring_epoch all-in-one data.attest)"
    [ "${epoch}" -ge $((first + 3)) ] ||
        fail "data.attest went from epoch ${first} to ${epoch}: the keys did not rotate"
    log "every decision shipped while data.attest went from epoch ${first} to ${epoch}"
}

# ---------------------------------------------------------------------------------------------
# authority: service accounts, their keys, scopes and tokens, over both transports
# ---------------------------------------------------------------------------------------------

# The `kid` a token's header names.
kid_of() {
    cut -d. -f1 <<<"$1" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' |
        base64 -d 2>/dev/null | jq -r '.kid' 2>/dev/null || true
}

# The zones `key`'s account reads over `scheme`, the answer whatever it is.
zones_with() { # key file, scheme
    local scheme="${2:-https}"
    pg_cert --authority-endpoint "${scheme}://all-in-one:8443" \
        --access-key "$(access_key_of "$1")" --secret-key-file "$1" \
        --control-endpoint "${scheme}://all-in-one:6443" zones list 2>&1 || true
}

assert_all_in_one_authority() {
    local scheme key answer jti
    step "all-in-one: a service account, its key and its scopes, over HTTPS and gRPC"
    wait_admin
    for scheme in https grpcs; do
        local name="reader-${scheme}"
        key="${state}/${name}.key"
        rm -f "${key}"
        pg --authority-endpoint "${scheme}://all-in-one:8443" authority service-accounts create \
            "${name}" --scope "catalog.read@plane/control/*" >/dev/null ||
            fail "${scheme}: the account ${name} was not created"
        pg --authority-endpoint "${scheme}://all-in-one:8443" authority keys create "${name}" \
            --secret-out "${key}" >/dev/null || fail "${scheme}: no key for ${name}"
        rm -rf "${HOME}/.permguard/tokens"
        answer="$(zones_with "${key}" "${scheme}")"
        jq -e '.zones | length >= 1' >/dev/null 2>&1 <<<"${answer}" ||
            fail "${scheme}: ${name} does not read the catalog: ${answer}"
        answer="$(pg_cert --authority-endpoint "${scheme}://all-in-one:8443" \
            --access-key "$(access_key_of "${key}")" --secret-key-file "${key}" \
            --control-endpoint "${scheme}://all-in-one:6443" zones create lab-forbidden 2>&1 || true)"
        grep -Eq 'forbidden|permission_denied' <<<"${answer}" ||
            fail "${scheme}: ${name} wrote the catalog its scopes do not name: ${answer}"
        log "${scheme}: ${name} reads the catalog and is refused a write"

        pg authority service-accounts suspend "${name}" >/dev/null
        rm -rf "${HOME}/.permguard/tokens"
        answer="$(zones_with "${key}" "${scheme}")"
        grep -Eq 'unauthenticated|invalid_client' <<<"${answer}" ||
            fail "${scheme}: a suspended ${name} still reads: ${answer}"
        pg authority service-accounts resume "${name}" >/dev/null
        pg authority service-accounts delete "${name}" >/dev/null
        log "${scheme}: suspended, it is refused; deleted, its key goes with it"
    done

    step "all-in-one: a revoked token is refused at once"
    rm -f "${state}/tokens/lab-client.jwt"
    expect_decision all-in-one acme main permit.json true >/dev/null
    jti="$(jti_of "$(token_for)")"
    pg authority tokens revoke "${jti}" >/dev/null
    answer="$(decide all-in-one acme main permit.json "${state}/tokens/lab-client.jwt")"
    grep -q "unauthenticated" <<<"${answer}" ||
        fail "the all-in-one still decides on the token revoked ${jti}: ${answer}"
    rm -f "${state}/tokens/lab-client.jwt"
    expect_decision all-in-one acme main permit.json true >/dev/null
    log "${jti} is refused once revoked, and a new token decides"

    step "all-in-one: authority.tokens rotates and a token signed before still verifies"
    local before after epoch started
    rm -f "${state}/tokens/lab-client.jwt"
    before="${state}/tokens/before-rotation.jwt"
    cp "$(token_for)" "${before}"
    epoch="$(ring_epoch all-in-one authority.tokens)"
    pg --host-endpoint "$(host_endpoint all-in-one)" host keys rotate authority.tokens \
        --expected-epoch "${epoch}" >/dev/null || fail "authority.tokens did not rotate"
    started=${SECONDS}
    while :; do
        rm -f "${state}/tokens/lab-client.jwt"
        after="$(token_for)"
        [ "$(kid_of "$(cat "${after}")")" != "$(kid_of "$(cat "${before}")")" ] && break
        [ $((SECONDS - started)) -lt 600 ] || fail "authority.tokens still signs under its old key"
        sleep 10
    done
    expect_decision all-in-one acme main permit.json true "${after}" >/dev/null
    expect_decision all-in-one acme main permit.json true "${before}" >/dev/null
    rm -f "${before}"
    log "the new key signs $((SECONDS - started))s after the rotation; the retiring key still verifies"
}

expect_forbidden_or_refused() { # token file, who
    local scheme answer
    for scheme in https grpcs; do
        if answer="$(zones_as "$1" "${scheme}")"; then
            fail "$2 over ${scheme} listed the catalog: ${answer}"
        fi
    done
}

ring_epoch() { # host, ring
    pg --host-endpoint "$(host_endpoint "$1")" host keys show "$2" | jq -er '.epoch'
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
    acked_on control-plane "$1" "$2"
}

# What `host`, as a consumer, acknowledged of `producer`'s runs on `resource`.
acked_on() { # host, resource, producer
    frontier "$1" "$2" |
        jq --arg producer "$3" '[.consumer[] | select(.producer == $producer) | .acked] | add // 0'
}

# The records `host` produced on `resource`, every run of it.
recorded_on() { # host, resource
    frontier "$1" "$2" | jq '[.producer[].last_seq] | add // 0'
}

now_ms() { date +%s%3N; }

# The tail's wait (iteration 04, WP-33.1): a read of `host`'s decisions, from the end of what its
# Control Plane holds and asking to wait, answers with a decision made meanwhile as soon as its
# batch is acknowledged, not at the end of its wait. On the all-in-one, whose Control Plane serves
# the decision reads; the ingest that wakes the read is the one a coordinator runs for a member.
assert_tail_wait() { # host
    local host="$1"
    step "tail wait: a read waiting on ${host} answers with a decision made meanwhile"
    local held key token header base next answer decided took reading out="${state}/tail-wait.json"
    mkdir -p "${state}/tokens"
    chmod 0700 "${state}/tokens"
    held="$(admin_key)" || fail "no coordinator wrote admin's key"
    key="${held#* }"
    token="${state}/tokens/admin-tail.jwt"
    rm -f "${token}"
    pg_cert --authority-endpoint "$(authority_endpoint)" --access-key "$(access_key_of "${key}")" \
        --secret-key-file "${key}" authority token --out "${token}" >/dev/null ||
        fail "the Authority Plane issued admin no token"
    header="${state}/tokens/tail.header"
    (umask 077 && printf 'authorization: Bearer %s\n' "$(cat "${token}")" >"${header}")
    base="$(control_endpoint "${host}")/decisions/v1/zones/acme/ledgers/main/records"
    tail_read() {
        curl -sS --cacert "${pki}/ca.crt" --cert "${pki}/operator.crt" --key "${pki}/operator.key" \
            -H "@${header}" "$1"
    }
    wait_serving "${host}" acme main
    # The end of what the Control Plane holds now.
    next=""
    while :; do
        answer="$(tail_read "${base}?limit_records=1000${next:+&from=${next}}")"
        next="$(jq -er '.next' <<<"${answer}")" || fail "${host}'s decisions did not read: ${answer}"
        [ "$(jq -r '.more' <<<"${answer}")" = true ] || break
    done
    tail_read "${base}?from=${next}&wait_ms=20000" >"${out}" &
    reading=$!
    sleep 1
    expect_decision "${host}" acme main deny.json false >/dev/null
    decided="$(now_ms)"
    wait "${reading}" || fail "the waiting read failed"
    took=$(($(now_ms) - decided))
    rm -f "${header}"
    jq -e '.records | length > 0' "${out}" >/dev/null ||
        fail "the waiting read answered no record: $(cat "${out}")"
    log "the waiting read answered $(jq '.records | length' "${out}") record(s) ${took} ms after the decision"
    [ "${took}" -lt 5000 ] ||
        fail "the waiting read answered ${took} ms after the decision: the ingest did not wake it"
}

# Evidence freshness (iteration 04, WP-30.1): how long a decision recorded on `producer_host` waits
# before `consumer_host` acknowledges it durably, from the decision's answer, when its record is
# already durable, to the acknowledgement. The samples are spaced at random, so they fall anywhere
# in a shipping cycle. Prints p50, p95 and the worst; with LAB_FRESHNESS_P99_MS the worst sample is
# held to it, the gate of WP-32.2. A sample waits at most LAB_FRESHNESS_TIMEOUT seconds, 120 by
# default, two member passes.
assert_freshness() { # producer host, consumer host, zone, ledger, resource
    local producer_host="$1" consumer_host="$2" zone="$3" ledger="$4" resource="$5"
    local samples="${LAB_FRESHNESS_SAMPLES:-6}" timeout_ms=$((${LAB_FRESHNESS_TIMEOUT:-120} * 1000))
    local objective="${LAB_FRESHNESS_P99_MS:-}" out="${state}/freshness-${producer_host}.txt"
    local producer n target started waited count p50 p95 worst
    step "freshness: decisions on ${producer_host}, acknowledged by ${consumer_host}, ${samples} samples"
    wait_serving "${producer_host}" "${zone}" "${ledger}"
    producer="$(producer_of "${producer_host}")"
    : >"${out}"
    for n in $(seq 1 "${samples}"); do
        sleep "$((RANDOM % 7)).$((RANDOM % 10))"
        expect_decision "${producer_host}" "${zone}" "${ledger}" deny.json false >/dev/null
        started="$(now_ms)"
        target="$(recorded_on "${producer_host}" "${resource}")"
        while [ "$(acked_on "${consumer_host}" "${resource}" "${producer}")" -lt "${target}" ]; do
            waited=$(($(now_ms) - started))
            [ "${waited}" -lt "${timeout_ms}" ] ||
                fail "${consumer_host} did not acknowledge ${producer_host}'s record ${target} within ${waited} ms"
            sleep 0.1
        done
        waited=$(($(now_ms) - started))
        echo "${waited}" >>"${out}"
        log "sample ${n}: acknowledged ${waited} ms after the decision"
    done
    count="$(wc -l <"${out}" | tr -d ' ')"
    sort -n "${out}" >"${out}.sorted"
    p50="$(awk -v n="${count}" 'NR == int(n * 0.50) + 1' "${out}.sorted")"
    p95="$(awk -v n="${count}" 'NR == int(n * 0.95) + 1' "${out}.sorted")"
    worst="$(tail -n 1 "${out}.sorted")"
    log "evidence freshness ${producer_host} → ${consumer_host}: p50 ${p50} ms, p95 ${p95} ms, worst ${worst} ms over ${count} samples${objective:+; objective ${objective} ms}"
    [ -z "${objective}" ] || [ "${worst}" -le "${objective}" ] ||
        fail "the worst sample, ${worst} ms, passes the ${objective} ms objective"
}

# The shipping drills (iteration 04, WP-35.1): the coordinator stopped, cut from the network,
# frozen, killed in the middle of a burst and restored from a snapshot; a member killed in the
# middle of a burst; a burst from both members at once. The runner, scripts/compose-lab.sh, does to
# the servers what each drill names; these phases decide, and prove that every decision a member
# answered is recorded and held by the coordinator, measuring how long after the fault ended.
ship_dir="${state}/ship"
ship_members=(data-plane-a data-plane-b)

# before: the stream's resource, each member's producer and what it recorded so far, a token kept
# for the decisions the drills make while the Authority Plane does not answer.
ship_before() {
    local host resource
    rm -rf "${ship_dir}"
    mkdir -p "${ship_dir}"
    token_for >/dev/null
    resource="$(decisions_resource acme main)"
    echo "${resource}" >"${ship_dir}/resource"
    for host in "${ship_members[@]}"; do
        wait_serving "${host}" acme main
        producer_of "${host}" >"${ship_dir}/producer-${host}"
        recorded_on "${host}" "${resource}" >"${ship_dir}/base-${host}"
        echo 0 >"${ship_dir}/answered-${host}"
    done
    log "before the drills: $(for host in "${ship_members[@]}"; do printf '%s recorded %s; ' "${host}" "$(cat "${ship_dir}/base-${host}")"; done)"
}

# SHIP_COUNT decisions on each of SHIP_HOSTS, all at once, SHIP_WORKERS per host; a decision not
# answered, its member killed, ends its worker. What was answered is added to the member's count.
ship_decide() {
    local hosts="${SHIP_HOSTS:?the members}" count="${SHIP_COUNT:-20}" workers="${SHIP_WORKERS:-1}"
    local token="${state}/tokens/lab-client.jwt" host worker answered started took
    [ -f "${token}" ] || fail "no token of lab-client was kept for the drills"
    started="$(now_ms)"
    for host in ${hosts}; do
        for worker in $(seq 1 "${workers}"); do
            (
                made=0
                for _ in $(seq 1 "$((count / workers))"); do
                    decide "${host}" acme main deny.json "${token}" |
                        jq -e '.evaluated == true' >/dev/null 2>&1 || break
                    made=$((made + 1))
                done
                echo "${made}" >"${ship_dir}/made-${host}-${worker}"
            ) &
        done
    done
    wait
    took=$(($(now_ms) - started))
    for host in ${hosts}; do
        answered=0
        for worker in $(seq 1 "${workers}"); do
            answered=$((answered + $(cat "${ship_dir}/made-${host}-${worker}")))
            rm -f "${ship_dir}/made-${host}-${worker}"
        done
        echo $(($(cat "${ship_dir}/answered-${host}") + answered)) >"${ship_dir}/answered-${host}"
        log "${host}: ${answered} of ${count} decisions answered in ${took} ms"
    done
}

# Every decision each member answered since `before` is recorded on it and held by the
# coordinator, within SHIP_BOUND seconds: the time it took is recorded under SHIP_LABEL.
ship_drained() {
    local label="${SHIP_LABEL:?the drill}" bound_ms=$((${SHIP_BOUND:-120} * 1000))
    local resource host producer target recorded held started waited
    resource="$(cat "${ship_dir}/resource")"
    started="$(now_ms)"
    for host in "${ship_members[@]}"; do
        producer="$(cat "${ship_dir}/producer-${host}")"
        target=$(($(cat "${ship_dir}/base-${host}") + $(cat "${ship_dir}/answered-${host}")))
        while :; do
            recorded="$(recorded_on "${host}" "${resource}" 2>/dev/null)" || recorded=-1
            held="$(acked_on control-plane "${resource}" "${producer}" 2>/dev/null)" || held=-1
            [ "${recorded}" -ge "${target}" ] && [ "${held}" = "${recorded}" ] && break
            waited=$(($(now_ms) - started))
            [ "${waited}" -lt "${bound_ms}" ] ||
                fail "${label}: ${host} answered ${target}, recorded ${recorded}, the coordinator holds ${held}, ${waited} ms on"
            sleep 0.2
        done
    done
    waited=$(($(now_ms) - started))
    printf '%s|%s|%s\n' "${label}" "${waited}" \
        "$(for host in "${ship_members[@]}"; do printf '%s %s ' "${host}" "$(cat "${ship_dir}/answered-${host}")"; done)" \
        >>"${ship_dir}/results"
    log "${label}: every decision answered is recorded and held by the coordinator ${waited} ms after the fault ended"
}

ship_report() {
    step "shipping drills: what each recorded"
    local label waited answered
    while IFS='|' read -r label waited answered; do
        log "${label}: held ${waited} ms after the fault ended (answered since the start: ${answered})"
    done <"${ship_dir}/results"
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

# The import of the Control Plane's volume (iteration 03, WP-28.1), around `BACKEND=import`:
#
#   before-import  on files: the Control Plane's identity, kept under the lab's state
#   imported       on postgresql-s3: the same identity, served from the database and the bucket
assert_import() {
    local kept="${state}/import" identity
    identity="$(pg --host-endpoint "$(host_endpoint control-plane)" host identity show |
        jq -c '{host_id, fingerprint}')"
    case "$1" in
    before-import)
        mkdir -p "${kept}"
        printf '%s\n' "${identity}" >"${kept}/identity"
        log "the Control Plane on files is $(jq -r '.host_id' <<<"${identity}")"
        ;;
    imported)
        [ "${identity}" = "$(cat "${kept}/identity")" ] ||
            fail "the Control Plane served from postgresql-s3 is ${identity}, not $(cat "${kept}/identity")"
        log "the Control Plane served from postgresql-s3 is the Host it was on files, $(jq -r '.host_id' <<<"${identity}")"
        ;;
    esac
}

# Two Control Plane instances behind one address (iteration 03, WP-28.6), each reached by its own
# name and checked against the certificate of the address: one Host, one catalog.
assert_replicas() {
    local instances=(control-plane-1 control-plane-2) instance identity seen="" zones
    step "split-plane: two Control Plane instances, one Host"
    for instance in "${instances[@]}"; do
        identity="$(pg --host-endpoint "$(host_endpoint "${instance}")" \
            host identity show | jq -c '{host_id, fingerprint}')" ||
            fail "${instance} did not answer its identity"
        [ -z "${seen}" ] || [ "${identity}" = "${seen}" ] ||
            fail "${instance} is ${identity}, not ${seen}"
        seen="${identity}"
    done
    log "both instances are the Host $(jq -r '.host_id' <<<"${seen}")"

    step "split-plane: a zone made through one instance, read through the other"
    pg --control-endpoint "$(control_endpoint control-plane-2)" \
        zones create replicated >/dev/null || fail "control-plane-2 did not make the zone"
    zones="$(pg --control-endpoint "$(control_endpoint control-plane-1)" zones list)" ||
        fail "control-plane-1 did not list the zones"
    jq -e '[.zones[].name] | index("replicated") != null and index("acme") != null' <<<"${zones}" >/dev/null ||
        fail "control-plane-1 does not hold the zone control-plane-2 made"
    log "the zone made through control-plane-2 is read through control-plane-1 at once"
}

# ---------------------------------------------------------------------------------------------
# drills (iteration 03, WP-29.1)
# ---------------------------------------------------------------------------------------------

# The resilience drills of the two Control Plane instances on postgresql-s3, each a phase of the
# split-plane profile, run by `DRILLS=1 BACKEND=postgresql-s3 scripts/compose-lab.sh split-plane`,
# which stops, pauses and kills the servers between them. What each finds is logged as evidence,
# and kept under the lab's state, `drill/`, for the phase that checks it.
drill_dir="${state}/drill"
drill_instances=(control-plane-1 control-plane-2)

# The administrator's token, issued while the database answers, for the changes a drill asks of
# a Control Plane while it does not: what refuses them is then the Plane, not the token's issue.
drill_admin_token() {
    local held key file="${drill_dir}/admin.jwt"
    mkdir -p "${drill_dir}"
    held="$(admin_key)" || fail "no coordinator wrote admin's key"
    key="${held#* }"
    rm -f "${file}"
    pg_cert --authority-endpoint "$(authority_endpoint)" --access-key "$(access_key_of "${key}")" \
        --secret-key-file "${key}" authority token --out "${file}" >/dev/null ||
        fail "the Authority Plane issued admin no token"
    echo "${file}"
}

# A change of the catalog through `instance` with the token `file`: its answer, and whether it was
# made.
drill_change() { # instance, token file, zone
    pg_cert --token-file "$2" --control-endpoint "$(control_endpoint "$1")" zones create "$3" 2>&1
}

# Whether `instance` is ready, as a load balancer asks it: `ready` or `not ready`.
drill_state() {
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$1:5443/readyz" 2>/dev/null)" || true
    case "${code}" in
    200) echo ready ;;
    *) echo "not ready (${code:-no answer})" ;;
    esac
}

# Waits up to `seconds` for every instance to be `ready` or not: answers the seconds it took.
drill_readiness() { # ready|not, seconds
    local deadline=$((SECONDS + $2)) started=${SECONDS} instance state
    for instance in "${drill_instances[@]}"; do
        while :; do
            state="$(drill_state "${instance}")"
            case "$1:${state}" in
            ready:ready | not:not*) break ;;
            esac
            [ "${SECONDS}" -lt "${deadline}" ] || fail "${instance} is ${state} $2 s on"
            sleep 1
        done
    done
    echo $((SECONDS - started))
}

# A change of the catalog keeps being made, within `seconds`: the database answers again.
drill_changes_again() { # seconds, zone prefix
    local deadline=$((SECONDS + $1)) token instance
    token="$(drill_admin_token 2>/dev/null)" || true
    for instance in "${drill_instances[@]}"; do
        until [ -n "${token}" ] &&
            drill_change "${instance}" "${token}" "$2-${instance}-$(date +%s%N | cut -c1-13)" >/dev/null; do
            [ "${SECONDS}" -lt "${deadline}" ] || fail "${instance} makes no change $1 s after the drill"
            sleep 2
            [ -n "${token}" ] || token="$(drill_admin_token 2>/dev/null)" || true
        done
    done
}

# before: the token the drills change the catalog with, and every instance's state.
drill_before() {
    rm -rf "${drill_dir}"
    mkdir -p "${drill_dir}"
    drill_admin_token >/dev/null
    local instance
    for instance in "${drill_instances[@]}"; do
        log "${instance} is $(drill_state "${instance}")"
    done
}

# The database stopped: the Data Plane decides on what it holds; each instance refuses a change
# and issues no token, rather than answer from a copy in memory (E28).
drill_database_down() {
    local instance answer started
    step "drill: the database stopped"
    expect_decision data-plane acme main permit.json true >/dev/null
    expect_decision data-plane acme main deny.json false >/dev/null
    log "the Data Plane decides on the ledger it mirrored"
    for instance in "${drill_instances[@]}"; do
        started=${SECONDS}
        if answer="$(drill_change "${instance}" "${drill_dir}/admin.jwt" "drill-down-${instance}")"; then
            fail "${instance} made a change with the database stopped: ${answer}"
        fi
        log "${instance} refuses a change in $((SECONDS - started)) s: $(tr -d '\n' <<<"${answer}" | cut -c1-200)"
        if answer="$(pg_cert --authority-endpoint "https://${instance}:8443" \
            --access-key "$(access_key_of "${state}/lab-client.key")" \
            --secret-key-file "${state}/lab-client.key" authority token \
            --scope "decision.evaluate" --out "${drill_dir}/down.jwt" 2>&1)"; then
            fail "${instance} issued a token with the database stopped"
        fi
        log "${instance} issues no token: $(tr -d '\n' <<<"${answer}" | cut -c1-200)"
    done
    log "every instance is not ready $(drill_readiness not 30) s on (E28)"
}

# The database back: every instance makes a change again within a minute.
drill_database_back() {
    step "drill: the database back"
    local started=${SECONDS}
    log "every instance is ready $(drill_readiness ready 120) s after the database answered"
    drill_changes_again 120 drill-back
    log "every instance makes a change again, $((SECONDS - started)) s after the database answered"
}

# The database answering nothing, paused or cut from the network: no answer and no refusal. A
# change is refused within a bound, readiness is held, and decisions go on.
drill_database_unanswering() {
    local instance started code
    step "drill: the database answers nothing"
    expect_decision data-plane acme main permit.json true >/dev/null
    log "the Data Plane decides on the ledger it mirrored"
    for instance in "${drill_instances[@]}"; do
        started=${SECONDS}
        code=0
        within 300 "${drill_dir}/cut-${instance}.out"             drill_change "${instance}" "${drill_dir}/admin.jwt" "drill-cut-${instance}" || code=$?
        [ "${code}" != 124 ] || fail "${instance} held a change past 300 s"
        [ "${code}" != 0 ] ||
            fail "${instance} made a change with the database answering nothing: $(cat "${drill_dir}/cut-${instance}.out")"
        log "${instance} refuses a change in $((SECONDS - started)) s: $(tr -d '\n' <"${drill_dir}/cut-${instance}.out" | cut -c1-200)"
    done
    log "every instance is not ready $(drill_readiness not 60) s on (E28)"
}

# Runs a command with its output in `file`, stopped past `seconds`: its status, 124 when stopped.
within() { # seconds, file, command...
    local limit="$1" file="$2" waited=0 pid
    shift 2
    "$@" >"${file}" 2>&1 &
    pid=$!
    while kill -0 "${pid}" 2>/dev/null; do
        if [ "${waited}" -ge "${limit}" ]; then
            kill "${pid}" 2>/dev/null
            wait "${pid}" 2>/dev/null
            return 124
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "${pid}"
}

# A push of the basics example's policies to the ledger `ledger` of acme through
# control-plane-1, made or not: its status is the push's, its output the push's answer.
drill_push() { # ledger
    local endpoint workspace status=0
    endpoint="$(control_endpoint control-plane-1)"
    ledger_id control-plane-1 acme "$1" >/dev/null 2>&1 ||
        pg --control-endpoint "${endpoint}" ledgers create "$1" --zone acme >/dev/null 2>&1 || return 1
    workspace="$(mktemp -d)"
    cp -R "${examples}/basics/." "${workspace}"
    rm -rf "${workspace}/.permguard"
    if [ -f "${workspace}/manifest.yml" ]; then
        pg -w "${workspace}" init >/dev/null 2>&1 || status=1
    else
        pg -w "${workspace}" init "$1" --language cedar,rego >/dev/null 2>&1 || status=1
    fi
    [ "${status}" = 0 ] && pg -w "${workspace}" remote add origin "${endpoint}" >/dev/null 2>&1 || status=1
    [ "${status}" = 0 ] && pg -w "${workspace}" checkout "origin/acme/$1" >/dev/null 2>&1 || status=1
    [ "${status}" = 0 ] && { pg -w "${workspace}" apply -m "a drill's push" 2>&1 || status=1; }
    rm -rf "${workspace}"
    return "${status}"
}

# S3 stopped: a push of a ledger's policies is refused, decisions go on.
drill_s3_down() {
    local answer
    step "drill: S3 stopped"
    expect_decision data-plane acme main permit.json true >/dev/null
    if answer="$(drill_push drill-s3 2>&1)"; then
        fail "a push was taken with S3 stopped: ${answer}"
    fi
    log "a push is refused with S3 stopped: $(tr -d '\n' <<<"${answer}" | tail -c 200)"
    log "the Data Plane decides on the ledger it mirrored"
}

# S3 back: the push is taken.
drill_s3_back() {
    local deadline=$((SECONDS + 120))
    step "drill: S3 back"
    until drill_push drill-s3 >/dev/null 2>&1; do
        [ "${SECONDS}" -lt "${deadline}" ] || fail "no push is taken two minutes after S3 answered"
        sleep 3
    done
    log "a push is taken again once S3 answers"
}

# A token of lab-client, or of the account whose key file is `key`, issued by `instance` into
# `file`; its refusal, when refused, on standard output.
drill_token() { # instance, file, [key file]
    local key="${3:-${state}/lab-client.key}"
    pg_cert --authority-endpoint "https://$1:8443" \
        --access-key "$(access_key_of "${key}")" \
        --secret-key-file "${key}" authority token \
        --scope "decision.evaluate" --out "$2" 2>&1 >/dev/null
}

# control.attest as `instance` holds it: its epoch, its digest and its key ids, one line.
drill_ring() {
    drill_ring_of "$1" control.attest
}

# The ring `ring` as `instance` holds it, one line.
drill_ring_of() { # instance, ring
    pg --host-endpoint "$(host_endpoint "$1")" host keys show "$2" 2>/dev/null |
        jq -c '{epoch, digest, kids: [.keys[].kid]}'
}

# For `seconds`, rotations of control.attest and revocations of fresh tokens through
# control-plane-2, which the drill kills on the way: each one it answered is recorded, the epoch
# of a rotation and the jti of a revocation.
drill_churn() {
    local seconds="${1:-30}" deadline epoch file jti n=0
    step "drill: rotations and revocations through control-plane-2, killed on the way"
    deadline=$((SECONDS + seconds))
    : >"${drill_dir}/rotated"
    : >"${drill_dir}/revoked"
    drill_ring control-plane-1 >"${drill_dir}/ring-before"
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        n=$((n + 1))
        if epoch="$(pg --host-endpoint "$(host_endpoint control-plane-2)" host keys show control.attest 2>/dev/null | jq -er '.epoch')" &&
            pg --host-endpoint "$(host_endpoint control-plane-2)" host keys rotate control.attest \
                --expected-epoch "${epoch}" >/dev/null 2>&1; then
            echo "${epoch}" >>"${drill_dir}/rotated"
        fi
        file="${drill_dir}/churn-${n}.jwt"
        if drill_token control-plane-2 "${file}" >/dev/null && jti="$(jti_of "${file}")" &&
            pg --authority-endpoint "https://control-plane-2:8443" authority tokens revoke "${jti}" >/dev/null 2>&1; then
            echo "${jti} ${file}" >>"${drill_dir}/revoked"
        fi
        sleep 0.3
    done
    log "$(wc -l <"${drill_dir}/rotated" | tr -d ' ') rotations and $(wc -l <"${drill_dir}/revoked" | tr -d ' ') revocations answered in ${n} rounds"
}

# After the churn, both instances back: one ring on both, every key once, its epoch past the one
# it started at by the rotations answered, or by one more that committed unanswered; every
# revocation answered is in the store and refused by the Data Plane.
drill_churn_check() {
    local one other before rotated advanced jti file answer deadline
    step "drill: no key doubled, no revocation lost"
    one="$(drill_ring control-plane-1)"
    other="$(drill_ring control-plane-2)"
    [ -n "${one}" ] && [ "${one}" = "${other}" ] ||
        fail "the instances hold control.attest apart: ${one} and ${other}"
    jq -e '(.kids | length) == (.kids | unique | length)' <<<"${one}" >/dev/null ||
        fail "control.attest holds a key twice: ${one}"
    before="$(jq -r '.epoch' "${drill_dir}/ring-before")"
    rotated="$(wc -l <"${drill_dir}/rotated" | tr -d ' ')"
    advanced=$(($(jq -r '.epoch' <<<"${one}") - before))
    [ "${advanced}" -ge "${rotated}" ] && [ "${advanced}" -le $((rotated + 1)) ] ||
        fail "control.attest moved ${advanced} epochs for ${rotated} rotations answered"
    log "control.attest is one ring on both instances, every key once, ${advanced} epochs for ${rotated} rotations answered"
    local revoked
    revoked="$(pg --authority-endpoint "https://control-plane-1:8443" authority tokens list --status invalid |
        jq -r '.[].jti')"
    while read -r jti file; do
        [ -n "${jti}" ] || continue
        grep -qx "${jti}" <<<"${revoked}" || fail "the revocation of ${jti} was answered and is lost"
        deadline=$((SECONDS + 90))
        until answer="$(decide data-plane acme main permit.json "${file}")" &&
            grep -q "unauthenticated" <<<"${answer}"; do
            [ "${SECONDS}" -lt "${deadline}" ] || fail "the Data Plane still decides on ${jti}, revoked: ${answer}"
            sleep 3
        done
    done <"${drill_dir}/revoked"
    log "every revocation answered is in the store and refused by the Data Plane: $(wc -l <"${drill_dir}/revoked" | tr -d ' ')"
}

# Concurrent: two rotations of one epoch, one on each instance, of which one is made; revocations
# through both instances at once, every one kept.
drill_concurrent() {
    local ring epoch made instance n jti
    step "drill: concurrent rotations and revocations on both instances"
    # A ring rotated once waits for its successor to take over: each round is another ring.
    for ring in data.attest host.operations; do
        epoch="$(pg --host-endpoint "$(host_endpoint control-plane-1)" host keys show "${ring}" | jq -er '.epoch')"
        for instance in "${drill_instances[@]}"; do
            (pg --host-endpoint "$(host_endpoint "${instance}")" host keys rotate "${ring}" \
                --expected-epoch "${epoch}" >"${drill_dir}/race-${ring}-${instance}" 2>&1 &&
                echo made >>"${drill_dir}/race-${ring}-${instance}") &
        done
        wait
        made="$(cat "${drill_dir}"/race-"${ring}"-* | grep -cx made || true)"
        [ "${made}" = 1 ] || fail "two rotations of ${ring} at epoch ${epoch} made ${made}: $(cat "${drill_dir}"/race-"${ring}"-* | tr -d '\n' | cut -c1-300)"
        [ "$(drill_ring_of control-plane-1 "${ring}")" = "$(drill_ring_of control-plane-2 "${ring}")" ] ||
            fail "the instances hold ${ring} apart after the race"
    done
    log "twice, two rotations of one epoch on two instances made one, and one ring on both"
    : >"${drill_dir}/concurrent"
    for n in $(seq 1 10); do
        drill_token control-plane-1 "${drill_dir}/concurrent-${n}.jwt" >/dev/null || fail "no token ${n}"
        jti_of "${drill_dir}/concurrent-${n}.jwt" >>"${drill_dir}/concurrent"
    done
    n=0
    while read -r jti; do
        n=$((n + 1))
        instance="${drill_instances[$((n % 2))]}"
        (
            # `slow_down` is the bound of hashing work: asked again a second on, as a client is.
            while :; do
                if pg --authority-endpoint "https://${instance}:8443" authority tokens revoke "${jti}" \
                    >"${drill_dir}/revoke-${jti}" 2>&1; then
                    echo made >>"${drill_dir}/revoke-${jti}"
                    break
                fi
                grep -q '"slow_down"' "${drill_dir}/revoke-${jti}" || break
                echo slowed >>"${drill_dir}/revoke-slowed"
                sleep 1
            done
        ) &
    done <"${drill_dir}/concurrent"
    wait
    local invalid slowed
    invalid="$(pg --authority-endpoint "https://control-plane-2:8443" authority tokens list --status invalid |
        jq -r '.[].jti')"
    while read -r jti; do
        grep -qx made "${drill_dir}/revoke-${jti}" ||
            fail "the revocation of ${jti}, made with nine others at once, was refused: $(tr -d '\n' <"${drill_dir}/revoke-${jti}" | cut -c1-200)"
        grep -qx "${jti}" <<<"${invalid}" ||
            fail "the revocation of ${jti}, answered with nine others at once, is lost"
    done <"${drill_dir}/concurrent"
    slowed="$(wc -l <"${drill_dir}/revoke-slowed" 2>/dev/null | tr -d ' ' || echo 0)"
    log "ten revocations at once through both instances: all ten answered and kept; ${slowed:-0} asked again after slow_down"
}

# A short load through the one address: tokens issued and decisions answered by several clients
# at once, each its own service account, as clients are, the errors counted and the time
# measured. Each stays under the token endpoint's bound of 60 a minute for one access key
# (2-security/8), which answers `slow_down` past it.
drill_load() {
    local workers=6 each=20 started elapsed failed worker key
    step "drill: load through the one address"
    for worker in $(seq 1 "${workers}"); do
        key="${drill_dir}/load-${worker}.key"
        pg authority service-accounts get "drill-load-${worker}" >/dev/null 2>&1 ||
            pg authority service-accounts create "drill-load-${worker}" \
                --scope "decision.evaluate@plane/data/*" >/dev/null || fail "no account drill-load-${worker}"
        rm -f "${key}"
        pg authority keys create "drill-load-${worker}" --secret-out "${key}" >/dev/null ||
            fail "no key for drill-load-${worker}"
    done
    started=${SECONDS}
    for worker in $(seq 1 "${workers}"); do
        (
            local i failures=0 slowed=0 answer
            for i in $(seq 1 "${each}"); do
                while :; do
                    rm -f "${drill_dir}/load-${worker}.jwt"
                    answer="$(drill_token control-plane "${drill_dir}/load-${worker}.jwt" \
                        "${drill_dir}/load-${worker}.key")" && break
                    # The bound of concurrent work answers `slow_down`: asked again a second on,
                    # as a client is told to.
                    if grep -q '"slow_down"' <<<"${answer}"; then
                        slowed=$((slowed + 1))
                        sleep 1
                        continue
                    fi
                    failures=$((failures + 1))
                    break
                done
            done
            echo "${failures}" >"${drill_dir}/load-tokens-${worker}"
            echo "${slowed}" >"${drill_dir}/load-slowed-${worker}"
        ) &
    done
    wait
    elapsed=$((SECONDS - started))
    failed="$(cat "${drill_dir}"/load-tokens-* | awk '{ sum += $1 } END { print sum + 0 }')"
    [ "${failed}" = 0 ] || fail "${failed} of $((workers * each)) tokens failed under load"
    local slowed
    slowed="$(cat "${drill_dir}"/load-slowed-* | awk '{ sum += $1 } END { print sum + 0 }')"
    log "$((workers * each)) tokens by ${workers} clients at once through the one address in ${elapsed} s, none failed; ${slowed} answered slow_down by the bound of concurrent work and asked again"
    started=${SECONDS}
    for worker in $(seq 1 "${workers}"); do
        (
            local i failures=0 answer
            for i in $(seq 1 "${each}"); do
                answer="$(decide data-plane acme main permit.json "${drill_dir}/load-${worker}.jwt")"
                jq -e '.evaluated == true and .decision == true' >/dev/null 2>&1 <<<"${answer}" ||
                    failures=$((failures + 1))
            done
            echo "${failures}" >"${drill_dir}/load-decisions-${worker}"
        ) &
    done
    wait
    elapsed=$((SECONDS - started))
    failed="$(cat "${drill_dir}"/load-decisions-* | awk '{ sum += $1 } END { print sum + 0 }')"
    [ "${failed}" = 0 ] || fail "${failed} of $((workers * each)) decisions failed under load"
    log "$((workers * each)) decisions by ${workers} clients at once in ${elapsed} s, none failed"
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
        # TS-5: the snapshot is bound to the recovery key it was taken under, and another key never
        # restores it: refused before anything is written, no plan issued.
        local secrets="${volume}/operations/secrets" wrong="${state}/drill/wrong-key.yml" refused
        head -c 32 /dev/urandom >"${secrets}/backup-recovery-wrong"
        sed 's/recovery_key: backup-recovery,/recovery_key: backup-recovery-wrong,/' "${config}" >"${wrong}"
        grep -q 'recovery_key: backup-recovery-wrong,' "${wrong}" || fail "the wrong-key configuration was not written"
        if refused="$(permguard -o json restore plan --mode dr --reason "the wrong key" \
            --out "${drill}/wrong.plan" --volume "${volume}" --server-config "${wrong}" 2>&1)"; then
            fail "a restore under another recovery key was planned: ${refused}"
        fi
        grep -q 'recovery_key_mismatch' <<<"${refused}" || fail "the wrong key was refused otherwise: ${refused}"
        [ ! -e "${drill}/wrong.plan" ] || fail "a plan was issued under the wrong recovery key"
        rm -f "${secrets}/backup-recovery-wrong" "${wrong}"
        log "another recovery key is refused before anything is written (recovery_key_mismatch)"
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
        jq -c '{previous_boot_id, plan_id, runs_rolled_over: .streams.runs_rolled_over,
            recovery_key: "verified against the manifest; another key refused"}' \
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

# The `jti` of the token in `file`: its payload's, read without verifying, which the Authority
# Plane lists and revokes by.
jti_of() {
    cut -d. -f2 "$1" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' |
        base64 -d 2>/dev/null | jq -er '.jti'
}

# A Data Plane decides by the Authority Plane's tokens, verified under the keys and lists it
# fetched itself, and by nothing else.
assert_tokens() {
    step "tokens: one token of lab-client decides on every Data Plane"
    local token answer
    # A fresh token: the offline phase decides on it after the Control Plane stops.
    rm -f "${state}/tokens/lab-client.jwt"
    token="$(token_for)"
    expect_decision data-plane-a acme main permit.json true >/dev/null
    expect_decision data-plane-b acme main permit.json true >/dev/null
    log "lab-client's token decides on data-plane-a and data-plane-b"

    step "tokens: the operator's certificate administers a member, never decides there"
    answer="$(decide data-plane-a acme main permit.json none)"
    grep -Eq 'forbidden|permission_denied|unauthenticated' <<<"${answer}" ||
        fail "data-plane-a did not refuse a decision to the operator's certificate: ${answer}"
    pg_cert --host-endpoint "$(host_endpoint data-plane-a)" host status |
        jq -e '.degraded | any(.capability == "bootstrap")' >/dev/null ||
        fail "data-plane-a does not report its bootstrap principal's use"
    log "the operator, data-plane-a's bootstrap, is refused a decision; its use there is reported degraded: bootstrap"

    step "tokens: a revoked token is refused once the member holds the list that says so"
    local jti revoked="${state}/tokens/revoked.jwt" started=${SECONDS}
    cp "${token}" "${revoked}"
    rm -f "${token}"
    jti="$(jti_of "${revoked}")"
    pg authority tokens revoke "${jti}" >/dev/null
    while :; do
        answer="$(decide data-plane-a acme main permit.json "${revoked}")"
        grep -q "unauthenticated" <<<"${answer}" && break
        [ $((SECONDS - started)) -lt 240 ] ||
            fail "data-plane-a still decides on the token revoked ${jti}: ${answer}"
        sleep 5
    done
    rm -f "${revoked}"
    log "data-plane-a refuses ${jti} $((SECONDS - started))s after its revocation"
    expect_decision data-plane-a acme main permit.json true >/dev/null
    log "and decides again on a new token"
}

# WP-14.1: the evaluation latency on a member, its token verified on every request, against the
# TS-5 objective for its decision log (`required`, `LAB_P99_OBJECTIVE_MS`): one connection, many
# decisions, as a client with a pool sees it.
assert_latency() {
    step "latency: decisions on a member, token verification on, within the TS-5 objective"
    local token header request zone ledger objective="${LAB_P99_OBJECTIVE_MS:?the objective, from bench/slo.json}"
    token="$(token_for)"
    header="${state}/tokens/latency.header"
    (umask 077 && printf 'authorization: Bearer %s\n' "$(cat "${token}")" >"${header}")
    zone="$(zone_id control-plane acme)"
    ledger="$(ledger_id control-plane acme main)"
    request="$(jq -c --arg zone "${zone}" --arg ledger "${ledger}" '. + {zone: $zone, ledger: $ledger}' \
        "${examples}/basics/requests/permit.json")"
    local args=() n=0 count p50 p99
    # Every option is stated again after `--next`, which resets them, output and timing included.
    for n in $(seq 1 400); do
        args+=(--cacert "${pki}/ca.crt" --cert "${pki}/operator.crt" --key "${pki}/operator.key"
            -o /dev/null -w '%{http_code} %{time_total}\n'
            -H "@${header}" -H 'content-type: application/json' --data "${request}"
            "$(data_endpoint data-plane-a)/access/v1/evaluation")
        [ "${n}" -lt 400 ] && args+=(--next)
    done
    curl -sS "${args[@]}" >"${state}/latency.txt"
    rm -f "${header}"
    [ "$(grep -vc '^200 ' "${state}/latency.txt")" = 0 ] ||
        fail "not every decision was answered 200: $(sort "${state}/latency.txt" | cut -d' ' -f1 | uniq -c | tr '\n' ' ')"
    count="$(wc -l <"${state}/latency.txt" | tr -d ' ')"
    cut -d' ' -f2 "${state}/latency.txt" | sort -n >"${state}/latency.sorted"
    p50="$(awk -v n="${count}" 'NR == int(n * 0.50) + 1 { printf "%.1f", $1 * 1000 }' "${state}/latency.sorted")"
    p99="$(awk -v n="${count}" 'NR == int(n * 0.99) + 1 { printf "%.1f", $1 * 1000 }' "${state}/latency.sorted")"
    log "${count} decisions on data-plane-a with lab-client's token, decision log required: p50 ${p50} ms, p99 ${p99} ms; objective p99 ${objective} ms"
    awk -v p="${p99}" -v o="${objective}" 'BEGIN { exit !(p <= o) }' ||
        fail "p99 ${p99} ms passes the ${objective} ms objective"
}

# The Authority Plane rotates `authority.tokens`: its new key is published ahead, five minutes in
# the lab, and every Plane takes the new key set when it meets its `kid`; the retiring key stays in
# the set while it overlaps, so a token signed before the rotation still decides.
assert_tokens_rotation() {
    step "rotation: the Authority Plane rotates authority.tokens, every Plane follows"
    local before after epoch started
    rm -f "${state}/tokens/lab-client.jwt"
    before="${state}/tokens/before-rotation.jwt"
    cp "$(token_for)" "${before}"
    epoch="$(ring_epoch control-plane authority.tokens)"
    pg --host-endpoint "$(host_endpoint control-plane)" host keys rotate authority.tokens \
        --expected-epoch "${epoch}" >/dev/null || fail "the Authority Plane did not rotate authority.tokens"
    started=${SECONDS}
    while :; do
        rm -f "${state}/tokens/lab-client.jwt"
        after="$(token_for)"
        [ "$(kid_of "$(cat "${after}")")" != "$(kid_of "$(cat "${before}")")" ] && break
        [ $((SECONDS - started)) -lt 600 ] ||
            fail "authority.tokens still signs under its old key $((SECONDS - started))s after its rotation"
        sleep 10
    done
    log "authority.tokens went from epoch ${epoch} to $(ring_epoch control-plane authority.tokens): its new key signs $((SECONDS - started))s after the rotation"
    expect_decision data-plane-a acme main permit.json true "${after}" >/dev/null
    expect_decision data-plane-b acme main permit.json true "${after}" >/dev/null
    log "a token signed under the new key decides on data-plane-a and data-plane-b"
    expect_decision data-plane-a acme main permit.json true "${before}" >/dev/null
    rm -f "${before}"
    log "the token signed under the retiring key still decides on data-plane-a"
}

# WP-12.6: with the Control Plane stopped, a member still decides by the tokens and lists it holds.
assert_tokens_offline() {
    step "tokens: the Control Plane stopped, a member decides on what it holds"
    local token="${state}/tokens/lab-client.jwt"
    [ -f "${token}" ] || fail "no token of lab-client was kept before the Control Plane stopped"
    ! (: <"/dev/tcp/control-plane/5444") 2>/dev/null ||
        fail "the Control Plane still answers: the members' decisions prove nothing offline"
    expect_decision data-plane-b acme main permit.json true "${token}" >/dev/null
    log "data-plane-b decides on lab-client's token and its held status list, its Authority Plane stopped"
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
    # A member takes an occurrence by the Authority Plane's tokens: lab-client's.
    # The header is read from a file only the lab reads, so the token is never in an argument list.
    local token header
    token="$(token_for)"
    header="${token}.header"
    (umask 077 && printf 'authorization: Bearer %s\n' "$(cat "${token}")" >"${header}")
    # The listener takes mutual TLS: the connection is the operator's certificate, the decision the
    # token's, which a member routes first.
    curl -sS --cacert "${pki}/ca.crt" --cert "${pki}/operator.crt" --key "${pki}/operator.key" \
        -H "@${header}" \
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
import) cmd_import "$@" ;;
offline) cmd_offline "$@" ;;
catalog) cmd_catalog "$@" ;;
enroll) cmd_enroll "$@" ;;
assert) cmd_assert "$@" ;;
*)
    sed -n '5,13p' "$0" >&2
    exit 64
    ;;
esac
