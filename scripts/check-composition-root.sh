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
    "crates/permguard-server/src/plane/mod.rs"
    "crates/permguard-server/src/plane/factories.rs"
    "crates/permguard-control-plane/src/main.rs"
    "crates/permguard-data-plane/src/main.rs"
)
CONSTRUCTORS='DefaultServerHost::new|FileCatalog::new|MemoryStorage::new|TracingAuditSink::new|RecordingAuditSink::new|FileAuditSink::new|HmacPseudonymizer::new|DirectorySecretStore::new|EnvironmentSecretStore::new|DirectoryKeyManager::new|DirectoryKeyManager::with_clock'

violations=""

while IFS= read -r file; do
    relative="${file#"${ROOT}"/}"

    for root in "${COMPOSITION_ROOTS[@]}"; do
        if [ "${relative}" = "${root}" ]; then
            continue 2
        fi
    done

    found="$(
        awk '
            /^#\[cfg\(test\)\]/ { in_tests = 1; next }
            in_tests && /^\}/    { in_tests = 0; next }
            in_tests             { next }
                                 { print FILENAME ":" FNR ": " $0 }
        ' "${file}" | grep -E "${CONSTRUCTORS}" || true
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

printf 'ok: collaborators are constructed only in approved composition roots\n'
