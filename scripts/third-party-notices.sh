#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Writes THIRD_PARTY_NOTICES.md from what the build actually links, and checks it is current.
#
# # Why this reads the resolved graph rather than the manifests
#
# `Cargo.toml` says what this workspace asks for; `Cargo.lock` and the resolved graph say what a
# build receives — the transitive closure, at the exact versions, after feature unification. A
# notices file written from the manifests names a fraction of what ships, which is worse than no
# file: it looks like disclosure and is not.
#
# Development dependencies are excluded on purpose. A notice covers what is distributed, and a test
# harness is not. Build dependencies ARE included: a build script that generates code puts its
# licence terms on the artifact even though it does not link into it.
#
# # Why the output is sorted and pinned
#
# The file is the input to a CI check that fails when it drifts from the graph. That check is only
# meaningful if a regeneration with unchanged dependencies produces byte-identical output, so the
# package list is sorted by name and version, and nothing timestamped or machine-specific is
# written into it.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

readonly OUTPUT="THIRD_PARTY_NOTICES.md"

usage() {
    cat >&2 <<'USAGE'
usage: third-party-notices.sh [--check]

  (no argument)  regenerate THIRD_PARTY_NOTICES.md in place
  --check        fail if the file is not what a regeneration would write
USAGE
}

checking="false"
case "${1-}" in
    "") ;;
    --check) checking="true" ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 2
        ;;
esac

for tool in cargo jq; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        printf 'error: %s is required to write the third-party notices\n' "${tool}" >&2
        exit 1
    fi
done

# The resolved graph, then the walk.
#
# `cargo metadata` returns every package it knows about, including ones no shipping target reaches.
# The walk below starts at the workspace members and follows only `normal` and `build` edges, so
# what comes out is the set a distributed artifact actually carries.
resolved="$(
    cargo metadata --format-version 1 --all-features --locked | jq -r '
        . as $meta
        | ($meta.workspace_members | map(.) | unique) as $ours
        | ($meta.resolve.nodes | map({key: .id, value: .}) | from_entries) as $nodes
        | ($meta.packages | map({key: .id, value: .}) | from_entries) as $packages
        # Breadth-first from the workspace members, over shipping edges only.
        | def walk($seen; $queue):
            if ($queue | length) == 0 then $seen
            else
                ($queue[0]) as $id
                | ($queue[1:]) as $rest
                | if ($seen | index($id)) then walk($seen; $rest)
                  else
                    ($nodes[$id].deps // []
                      | map(select(.dep_kinds // [] | any(.kind == null or .kind == "build")))
                      | map(.pkg)) as $next
                    | walk($seen + [$id]; $rest + $next)
                  end
            end;
          walk([]; $ours)
        # Our own crates are the subject of the notices, not an entry in them.
        | map(select(. as $id | $ours | index($id) | not))
        | map($packages[.])
        # A package that declares no `repository` may still be reachable: a git dependency carries
        # its origin in `source`. A registry source URL names the index rather than the project,
        # so it is dropped.
        | map({
            name: .name,
            version: .version,
            license: .license,
            source: (
              if (.repository // "") != "" then .repository
              elif ((.source // "") | startswith("git+")) then
                (.source | ltrimstr("git+") | split("#")[0])
              else ""
              end
            )
          })
        | unique_by([.name, .version])
        | sort_by([.name, .version])
    '
)"

table="$(
    printf '%s' "${resolved}" | jq -r '
        .[]
        | "| `\(.name)` | \(.version) | \(.license // "not declared") | \(if .source == "" then "—" else .source end) |"
    '
)"

# Packages whose manifest declares no SPDX expression. They are not necessarily unlicensed — the
# licence usually exists in the source tree and simply never reached the metadata — but they are
# the only entries a human has to resolve by hand, so they are named rather than left to be found
# among the hundreds above.
undeclared="$(
    printf '%s' "${resolved}" | jq -r '
        map(select(.license == null))
        | .[]
        | "- `\(.name)` \(.version) — \(if .source == "" then "no source declared either" else .source end)"
    '
)"

count="$(printf '%s' "${resolved}" | jq 'length')"

if [ -z "${undeclared}" ]; then
    undeclared_section="Every package above declares an SPDX licence expression."
else
    undeclared_section="$(
        cat <<UNDECLARED
The packages below declare no SPDX expression in their manifest. That is an upstream metadata
omission rather than an absence of licence: check the licence file in each source tree before a
distribution that relies on this list.

${undeclared}
UNDECLARED
    )"
fi

rendered="$(
    cat <<HEADER
<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Notices

Permguard is distributed under the Apache License, Version 2.0. It links the third-party packages
listed below, each under its own licence.

This file is generated from the resolved dependency graph — the transitive closure at the exact
versions a build receives — and is checked in CI. Do not edit it by hand: run \`task notices\`
(or \`make notices\`) instead.

Development dependencies are excluded: a notice covers what is distributed, and a test harness is
not. Build dependencies are included, because the terms of a build script travel with the artifact
it helped produce.

Licences are the SPDX expressions each package declares. Where a package declares none, the entry
says so and its repository is the authority.

## Packages

${count} packages.

| Package | Version | Licence | Source |
| ------- | ------- | ------- | ------ |
${table}

## Packages without a declared licence

${undeclared_section}

## Full licence texts

The full text of the Apache License 2.0 is in [LICENSE](LICENSE). The texts of the other licences
named above are published by their respective projects at the sources listed, and are reproduced in
the vendored copy of each package in the Cargo registry cache.

For licence questions, contact <opensource@permguard.com>.
HEADER
)"

if [ "${checking}" = "true" ]; then
    if [ ! -f "${OUTPUT}" ]; then
        printf 'error: %s does not exist. Run `task notices` and commit it.\n' "${OUTPUT}" >&2
        exit 1
    fi
    if ! printf '%s\n' "${rendered}" | diff -u "${OUTPUT}" - >/dev/null; then
        printf 'error: %s is out of date with the dependency graph.\n\n' "${OUTPUT}" >&2
        printf '%s\n' "${rendered}" | diff -u "${OUTPUT}" - >&2 || true
        printf '\nRun `task notices` and commit the result.\n' >&2
        exit 1
    fi

    printf 'ok: %s matches the dependency graph (%s packages)\n' "${OUTPUT}" "${count}"
    exit 0
fi

printf '%s\n' "${rendered}" >"${OUTPUT}"
printf 'wrote %s (%s packages)\n' "${OUTPUT}" "${count}"
