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
    "crates/permguard-server/src/app.rs"
    "crates/permguard-server/src/plane/mod.rs"
    "crates/permguard-server/src/plane/factories.rs"
    "crates/permguard-control-plane/src/main.rs"
    "crates/permguard-data-plane/src/main.rs"
    "crates/permguard-cli/src/commands/host.rs"
    "crates/permguard-host/src/authz/mapper.rs"
    "crates/permguard-host/src/authz/oidc.rs"
)
CONSTRUCTORS='Host::builder|PlaneContext::new|PlaneHealth::new|GrantStore::open|PrincipalMapper::new|Authorization::new|Authorization::public_only|Authorization::permissive|ActorContext::new|HostApi::new|Replay::open|DefaultServerHost::new|FileCatalog::new|MemoryStorage::new|TracingAuditSink::new|RecordingAuditSink::new|FileAuditSink::new|HmacPseudonymizer::new|DirectorySecretStore::new|EnvironmentSecretStore::new|DirectoryKeyManager::new|DirectoryKeyManager::with_clock'

# Code outside test-only items, as `file:line: text`. A `#[cfg(test)]` attribute in column 0 skips
# the item it marks: a block (`mod tests {`, a function) up to its closing brace in column 0, or a
# single-line item (`#[cfg(test)] use …;`) alone. Comment lines are skipped.
NON_TEST_CODE='
    in_tests && /^\}/                     { in_tests = 0; next }
    in_tests                              { next }
    pending && /^#\[/                       { next }
    pending { pending = 0; if ($0 ~ /\{[[:space:]]*$/) { in_tests = 1 }; next }
    /^#\[cfg\(test\)\][[:space:]]*$/      { pending = 1; next }
    /^#\[cfg\(test\)\]/ { if ($0 ~ /\{[[:space:]]*$/) { in_tests = 1 }; next }
    /^[[:space:]]*\/\//                    { next }
                                          { print FILENAME ":" FNR ": " $0 }
'

violations=""

while IFS= read -r file; do
    relative="${file#"${ROOT}"/}"

    for root in "${COMPOSITION_ROOTS[@]}"; do
        if [ "${relative}" = "${root}" ]; then
            continue 2
        fi
    done

    found="$(
        awk "${NON_TEST_CODE}" "${file}" | grep -E "${CONSTRUCTORS}" || true
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
    "crates/permguard-data-plane/src"
)
HOST_ONLY='ServerContext|(^|[^A-Za-z_])Health([^A-Za-z_]|$)|(context|ctx|cx|server)\.keys\(\)|\.realms\(\)|(context|ctx|cx|server)\.audit\(\)|\.maintained_rings\(\)|\.with_plane_handles\(|\.with_maintained_ring\(|\.lifecycle\(\)|\.set_ready\(|\.set_live\('

plane_violations=""
for crate in "${PLANE_CRATES[@]}"; do
    while IFS= read -r file; do
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
