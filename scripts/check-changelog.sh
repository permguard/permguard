#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Fails when the version being released has no entry in CHANGELOG.md.
#
# Release notes are generated from commit subjects, and commit subjects are written for the person
# reviewing the diff. What changed *for somebody running this* — a renamed setting, a new exit
# status, a default that moved — is a different sentence, and it only gets written if something
# insists. This insists, at the one moment it is cheap to fix: before the artifacts are built.
#
#   scripts/check-changelog.sh v0.2.0

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tag="${1:-}"

if [ -z "${tag}" ]; then
    echo "usage: $0 v<major>.<minor>.<patch>" >&2
    exit 2
fi

version="${tag#v}"
changelog="CHANGELOG.md"

if [ ! -f "${changelog}" ]; then
    echo "there is no ${changelog}" >&2
    exit 1
fi

# The heading Keep a Changelog uses: `## [0.2.0] - 2026-08-22`.
if ! grep -qE "^## \[${version}\]" "${changelog}"; then
    echo "${changelog} has no entry for ${version}" >&2
    echo "add a '## [${version}] - <date>' section describing what changed for whoever runs this" >&2
    exit 1
fi

# An entry that is only a heading is an entry nobody wrote.
body="$(
    awk -v version="${version}" '
        $0 ~ "^## \\[" version "\\]" { inside = 1; next }
        inside && /^## / { exit }
        inside { print }
    ' "${changelog}" | grep -cE '^\s*[-*]' || true
)"

if [ "${body}" -eq 0 ]; then
    echo "the ${version} entry in ${changelog} lists nothing" >&2
    exit 1
fi

printf 'ok: %s describes %s in %s bullet(s)\n' "${changelog}" "${version}" "${body}"
