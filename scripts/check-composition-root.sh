#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Fails when a non-composition crate constructs one of the swappable collaborators.
#
# The whole point of the crate split is that no crate resolves its own collaborators: it receives
# them. A composition root is the single place that names a concrete storage, audit sink, or server
# host, so a different binary can reuse the plane modules and supply its own. That property is
# invisible in the type system — nothing stops another crate from calling `MemoryStorage::new()` —
# so it is checked here.
#
# Test code may construct freely: a unit test has to build the thing it tests. A top-level
# `#[cfg(test)] mod tests { ... }` is therefore skipped, from its attribute to its closing brace in
# column 0 — which is where rustfmt puts it. Code after that module is scanned again.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSITION_ROOTS=(
    "crates/permguard-runtime/src/composition.rs"
    "crates/permguard-embedded/src/lib.rs"
    "crates/permguard-server/src/app.rs"
    "crates/permguard-server/src/plane/mod.rs"
    "crates/permguard-offline/src/factories.rs"
    "crates/permguard-offline/src/volume.rs"
    "crates/permguard-control-plane/src/plane.rs"
    "crates/permguard-postgres/src/testing.rs"
    "crates/permguard-s3/src/testing.rs"
    "crates/permguard-control-plane-server/src/main.rs"
    "crates/permguard-data-plane-server/src/main.rs"
    "crates/permguard-authority-plane-server/src/main.rs"
    "crates/permguard-data-plane/src/embedded.rs"
    "crates/permguard-cli/src/commands/host.rs"
    "crates/permguard-host/src/authz/mapper.rs"
    "crates/permguard-host/src/authz/oidc.rs"
)
CONSTRUCTORS='[^d]FileKeyProvider::new|Ring::open\(|files::stores\(|FileRing::to_read|VolumeHome \{|Identity::open\(|Identity::provision(_with)?\(|Witnesses::open|ZoneKeys::open|Host::builder|PlaneContext::new|PlaneHealth::new|GrantStore::open|PrincipalMapper::new|Authorization::new|Authorization::public_only|Authorization::permissive|ActorContext::new|HostApi::new|Replay::new|FileReplay::open|FileHolds::open|FileMembers::open|Witnesses::open|ZoneKeys::open|FileSlots::new|FileRing::open|FileVersionWitnesses::new|FileIdentity::open|FileHeld::open|FileWitnesses::open|FileDeliveredKeys::open|FileClockMark::open|FileSeen::open|FileBootstrap::open|DefaultServerHost::new|FileCatalog::new|FileLedgers::new|FileObjectStore::new|FileArchives::new|FileCursorRoots::new|PostgresClockMark::new|PostgresMutations::new|PostgresReplay::new|PostgresTrails::new|Bucket::connect|PostgresLedgers::new|PostgresArchives::new|PostgresIdentity::new|PostgresRing::new|PostgresMembers::new|PostgresCatalog::new|PostgresWitnesses::new|PostgresVersionWitnesses::new|PostgresHeld::new|PostgresHolds::new|PostgresSeen::new|PostgresBootstrap::new|PostgresAccounts::new|PostgresTokens::new|PostgresMarks::new|Database::connect|cursorkey::load(_root)?\(|MemoryStorage::new|TracingAuditSink::new|RecordingAuditSink::new|HmacPseudonymizer::new|DirectorySecretStore::new|EnvironmentSecretStore::new|DirectoryKeyManager::new|DirectoryKeyManager::with_clock'

# The files of the Host's file backend that make a store, or hand one to a composition root, for
# another of them, and what they may construct or call among themselves.
FILE_BACKEND=(
    "crates/permguard-host/src/identity/files.rs"
    "crates/permguard-host/src/keys/migration.rs"
    "crates/permguard-host/src/keys/ring/files.rs"
    "crates/permguard-host/src/keys/slots/files.rs"
    "crates/permguard-host/src/secrets/files.rs"
)
FILE_BACKEND_WAYS_IN='File[A-Za-z]+::|Ring::open\(|files::stores\(|Identity::open\(|Identity::provision(_with)?\(|Witnesses::open|ZoneKeys::open'

# Code outside test-only items, as `file:line: text`. A `#[cfg(test)]` attribute in column 0 skips
# the item it marks: a block (`mod tests {`, a function) up to its closing brace in column 0, or a
# single-line item (`#[cfg(test)] use …;`) alone. A condition that holds only in a test build,
# `#[cfg(all(test, …))]`, marks its item the same way. Comment lines are skipped.
NON_TEST_CODE='
    in_tests && /^\}/                     { in_tests = 0; next }
    in_tests                              { next }
    pending && /^#\[/                       { next }
    pending { pending = 0; if ($0 ~ /\{[[:space:]]*$/) { in_tests = 1 }; next }
    /^#\[cfg\((all\()?test[,)].*\][[:space:]]*$/ { pending = 1; next }
    /^#\[cfg\(test\)\]/ { if ($0 ~ /\{[[:space:]]*$/) { in_tests = 1 }; next }
    /^[[:space:]]*\/\//                    { next }
                                          { print FILENAME ":" FNR ": " $0 }
'

# The files a `#[cfg(test)] mod name;` loads are test code as a whole, as the durability check
# reads them: `name.rs` or `name/mod.rs` beside a `lib.rs`, `main.rs` or `mod.rs`, under `stem/`
# beside any other file. The `case` patterns open with a parenthesis because this runs inside a
# command substitution, where bash 3.2, the one macOS ships, reads a bare `)` as its end.
TEST_FILES="$(
    find "${ROOT}/crates" -type f -name '*.rs' -path '*/src/*' | sort | while IFS= read -r file; do
        case "$(basename "${file}")" in
            (lib.rs | main.rs | mod.rs) base="$(dirname "${file}")" ;;
            (*) base="${file%.rs}" ;;
        esac
        awk '
            /^#\[cfg\(test\)\][[:space:]]*$/ { pending = 1; next }
            pending && /^#\[/ { next }
            pending && match($0, /^(pub(\([a-z]+\))? )?mod [A-Za-z_][A-Za-z0-9_]*;/) {
                name = $0; sub(/^(pub(\([a-z]+\))? )?mod /, "", name); sub(/;.*$/, "", name); print name
            }
            { pending = 0 }
            /^#\[cfg\(test\)\] *(pub(\([a-z]+\))? )?mod [A-Za-z_][A-Za-z0-9_]*;/ {
                name = $0; sub(/^#\[cfg\(test\)\] *(pub(\([a-z]+\))? )?mod /, "", name); sub(/;.*$/, "", name); print name
            }
        ' "${file}" | while IFS= read -r name; do
            for candidate in "${base}/${name}.rs" "${base}/${name}/mod.rs"; do
                if [ -f "${candidate}" ]; then
                    printf '%s\n' "${candidate}"
                fi
            done
        done
    done
)"

violations=""

while IFS= read -r file; do
    relative="${file#"${ROOT}"/}"

    for root in "${COMPOSITION_ROOTS[@]}"; do
        if [ "${relative}" = "${root}" ]; then
            continue 2
        fi
    done

    if printf '%s\n' "${TEST_FILES}" | grep -qxF "${file}"; then
        continue
    fi

    # A file may construct the types it defines: a backend's file makes its own store for the
    # entry points it gives a composition root, and that is not a crate resolving a collaborator.
    # The Host's file backend is the files `FILE_BACKEND` names, together: one of them may
    # construct another's store or call another's way in, as a ring's records are opened with
    # the slots of its keys. No other file is the file backend, whatever it is called.
    in_file_backend=""
    for backend in "${FILE_BACKEND[@]}"; do
        if [ "${relative}" = "${backend}" ]; then
            in_file_backend="yes"
        fi
    done
    found="$(
        awk "${NON_TEST_CODE}" "${file}" | grep -E "${CONSTRUCTORS}" | while IFS= read -r line; do
            foreign=""
            # One constructor a line of `grep -o`: a pattern may hold a space, as a struct literal.
            while IFS= read -r constructor; do
                # A pattern that excludes a longer name by the character before it matches that
                # character too.
                constructor="${constructor#[^A-Za-z]}"
                if grep -qE "^pub struct ${constructor%%::*}([ <{(;]|\$)" "${file}"; then
                    continue
                fi
                if [ -n "${in_file_backend}" ] \
                    && printf '%s\n' "${constructor}" | grep -qE "^(${FILE_BACKEND_WAYS_IN})"; then
                    continue
                fi
                foreign="yes"
            done < <(printf '%s\n' "${line}" | grep -oE "${CONSTRUCTORS}")
            if [ -n "${foreign}" ]; then
                printf '%s\n' "${line}"
            fi
        done || true
    )"

    if [ -n "${found}" ]; then
        violations="${violations}${found}"$'\n'
    fi
done < <(
    find "${ROOT}/crates" -type f -name '*.rs' -path '*/src/*' | sort
)

if [ -n "${violations}" ]; then
    printf '%s' "${violations}" >&2
    printf 'error: collaborators may only be constructed in approved composition roots\n' >&2
    exit 1
fi

# A Plane reaches the Host's capabilities only through the handles its declaration was granted
# (P1), and sees the Host only through its own `PlaneContext` (P2): the split is by type, since
# `PlaneContext` has none of the Host's accessors. What the type system cannot say is that a Plane
# crate never names the Host's types at all — `ServerContext`, with the operations ring, the realms,
# the raw audit sink and the maintenance list, and `Health`, which sets the Host's own phase — so
# that is checked here, in the Plane crates' non-test code. `handles.rs` reads the Plane's own
# handles through its context; `plane_handles`, keyed by plane id, is the Host's.
PLANE_CRATES=(
    "crates/permguard-control-plane/src"
    "crates/permguard-control-plane-server/src"
    "crates/permguard-data-plane/src"
    "crates/permguard-data-plane-server/src"
    "crates/permguard-authority-plane/src"
    "crates/permguard-authority-plane-server/src"
)
HOST_ONLY='ServerContext|(^|[^A-Za-z_])Health([^A-Za-z_]|$)|(context|ctx|cx|server)\.keys\(\)|\.realms\(\)|(context|ctx|cx|server)\.audit\(\)|\.maintained_rings\(\)|\.with_plane_handles\(|\.with_maintained_ring\(|\.lifecycle\(\)|\.set_ready\(|\.set_live\('

# The composition root of an embedded process (`11-refactoring`, Embedded public API and
# lifecycle): it builds the Host's context for the Plane, as a server's entry point does, and is
# the one file of a Plane package that may.
PLANE_COMPOSITION_ROOTS=(
    "crates/permguard-data-plane/src/embedded.rs"
)

plane_violations=""
for crate in "${PLANE_CRATES[@]}"; do
    while IFS= read -r file; do
        for root in "${PLANE_COMPOSITION_ROOTS[@]}"; do
            if [ "${file#"${ROOT}"/}" = "${root}" ]; then
                continue 2
            fi
        done
        found="$(
            {
                awk "${NON_TEST_CODE}" "${file}" | grep -E "${HOST_ONLY}"
                awk "${NON_TEST_CODE}" "${file}" | grep -E 'plane_handles'
                # A Plane reads its own handles in its `handles` module, and nowhere else: one
                # place to see what the Plane was granted.
                if [ "$(basename "${file}")" != "handles.rs" ]; then
                    awk "${NON_TEST_CODE}" "${file}" | grep -E '\.handles::<'
                fi
            } || true
        )"
        if [ -n "${found}" ]; then
            plane_violations="${plane_violations}${found}"$'\n'
        fi
    done < <(find "${ROOT}/${crate}" -type f -name '*.rs' | sort)
done

if [ -n "${plane_violations}" ]; then
    printf '%s' "${plane_violations}" >&2
    printf 'error: a Plane sees the Host only through its PlaneContext and its handles\n' >&2
    exit 1
fi

printf 'ok: collaborators are constructed only in approved composition roots\n'
