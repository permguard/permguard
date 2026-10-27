#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The evidence manifest of a release candidate (WP-7.13): every file the release carries, pinned
# by its SHA-256 to the commit it was built from, and the iteration exit gate's verdict over the
# evidence among them.
#
#   scripts/evidence-manifest.sh <directory> <tag> <commit> [manifest]
#
# <directory> holds the release's files, as `gh release download <tag>` leaves them. The manifest
# (default <directory>/evidence-manifest.json) names each file with its digest and size, and is
# `complete` only when every piece of evidence the gate requires is there and says it passed:
#
#   permguard-benchmark.json, permguard-gate.json   the performance report and the serving gate
#   drill-split-brain.json, drill-restore.json      the drills, the recovery-key restore among them
#   fuzz-release.json                               the release fuzz budget, without a crash
#   reproducibility.txt                             the independent rebuild's verdict, `reproducible: yes`
#   traceability.json                               the blueprint traced to code and tests
#   checksums.txt, provenance-files.json,
#   provenance-images.json, one *.sbom.json         the signed files, their provenance, the SBOM
#
# A record that is missing, or a note left in its place (`<name>.txt`), or a record whose `result`
# is not `passed`, leaves the gate incomplete and is named under `incomplete`; the manifest is still
# written, so what is missing is said, never hidden. The release pipeline attests the manifest;
# `scripts/verify-evidence.sh` recomputes every digest and fails closed.
set -euo pipefail

directory="${1:?usage: scripts/evidence-manifest.sh <directory> <tag> <commit> [manifest]}"
tag="${2:?usage: scripts/evidence-manifest.sh <directory> <tag> <commit> [manifest]}"
commit="${3:?usage: scripts/evidence-manifest.sh <directory> <tag> <commit> [manifest]}"
manifest="${4:-${directory}/evidence-manifest.json}"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

incomplete=()
# A JSON record: there, readable, and `"result": "passed"` (the benchmark report and the
# traceability report have no result field: being there, readable, is what they prove).
record() { # name [result-required]
    local name="$1" required="${2:-yes}" path="${directory}/$1"
    if [ ! -s "${path}" ]; then
        if [ -s "${directory}/${name%.json}.txt" ]; then
            incomplete+=("${name}: not produced; ${name%.json}.txt says why")
        else
            incomplete+=("${name}: missing")
        fi
        return
    fi
    if ! jq -e . "${path}" >/dev/null 2>&1; then
        incomplete+=("${name}: not JSON")
        return
    fi
    if [ "${required}" = yes ] && [ "$(jq -r '.result // empty' "${path}")" != passed ]; then
        incomplete+=("${name}: result is $(jq -c '.result // null' "${path}"), not passed")
    fi
}
present() { # name
    [ -s "${directory}/$1" ] || incomplete+=("$1: missing")
}

record permguard-benchmark.json no
record permguard-gate.json no
if [ -s "${directory}/permguard-gate.json" ] &&
    [ "$(jq -r '.passed // false' "${directory}/permguard-gate.json")" != true ]; then
    incomplete+=("permguard-gate.json: the serving gate did not pass")
fi
record drill-split-brain.json
record drill-restore.json
record fuzz-release.json
record traceability.json no
if [ ! -s "${directory}/reproducibility.txt" ]; then
    incomplete+=("reproducibility.txt: missing")
elif ! grep -qx 'reproducible: yes' "${directory}/reproducibility.txt"; then
    incomplete+=("reproducibility.txt: the independent rebuild did not reproduce the release")
fi
present checksums.txt
present provenance-files.json
present provenance-images.json
compgen -G "${directory}/*.sbom.json" >/dev/null || incomplete+=("*.sbom.json: no SBOM")

artifacts="$(
    find "${directory}" -maxdepth 1 -type f ! -name "$(basename "${manifest}")" -print |
        LC_ALL=C sort |
        while IFS= read -r path; do
            jq -n --arg name "$(basename "${path}")" --arg sha256 "$(sha256 "${path}")" \
                --argjson bytes "$(wc -c <"${path}" | tr -d ' ')" \
                '{name: $name, sha256: $sha256, bytes: $bytes}'
        done | jq -s .
)"
incomplete_json="$(printf '%s\n' "${incomplete[@]+"${incomplete[@]}"}" | jq -R 'select(length > 0)' | jq -s .)"

jq -n --arg tag "${tag}" --arg commit "${commit}" --argjson artifacts "${artifacts}" \
    --argjson incomplete "${incomplete_json}" \
    '{schema: "permguard.evidence-manifest.v1", tag: $tag, commit: $commit,
      complete: ($incomplete | length == 0), incomplete: $incomplete, artifacts: $artifacts}' \
    >"${manifest}"

if [ "${#incomplete[@]}" -eq 0 ]; then
    echo "ok: the exit gate's evidence of ${tag} (${commit}) is complete: ${manifest}"
else
    echo "incomplete: the exit gate's evidence of ${tag} (${commit}) lacks ${#incomplete[@]}:" >&2
    printf '  %s\n' "${incomplete[@]}" >&2
fi
