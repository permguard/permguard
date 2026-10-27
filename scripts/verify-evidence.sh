#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies a release candidate's evidence manifest (WP-7.13) and prints the exit gate's report.
#
#   scripts/verify-evidence.sh <directory> <repository> <tag>
#
# <directory> holds the release's files and its `evidence-manifest.json`, as
# `gh release download <tag>` leaves them. The manifest's own attestation is verified first
# (`gh attestation verify`, signed by <repository>'s `release-pipeline.yml` on a GitHub-hosted runner
# for the ref `refs/tags/<tag>`), so the manifest is the one the release pipeline signed for that
# release and no other; the manifest must name <tag> too. Then every file the manifest names is
# hashed again. It fails closed: a manifest of another shape, an attestation that does not verify,
# a file missing, a digest or size that differs, a file the manifest does not name, or a gate the
# manifest says is incomplete exits non-zero, and the report says which.
set -euo pipefail

usage="usage: scripts/verify-evidence.sh <directory> <repository> <tag>"
directory="${1:?${usage}}"
repository="${2:?${usage}}"
tag="${3:?${usage}}"
manifest="${directory}/evidence-manifest.json"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

[ -s "${manifest}" ] || {
    echo "FAIL: no evidence manifest in ${directory}" >&2
    exit 1
}
# The whole shape before anything is read from it: a list read below that is not a list would
# otherwise read as empty, and an empty list of problems as a pass.
jq -e --arg tag "${tag}" '
    .schema == "permguard.evidence-manifest.v1"
    and .tag == $tag
    and (.commit | type == "string" and length > 0)
    and (.complete | type == "boolean")
    and (.incomplete | type == "array" and all(.[]; type == "string"))
    and (.artifacts | type == "array" and length > 0)
    and all(.artifacts[];
        (.name | type == "string" and test("^[^/]+$") and (startswith(".") | not))
        and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.bytes | type == "number" and . >= 0))
    and (.complete == (.incomplete | length == 0))
' "${manifest}" >/dev/null || {
    echo "FAIL: ${manifest} is not a permguard.evidence-manifest.v1 of ${tag}" >&2
    exit 1
}

# Signed by the release pipeline itself, the one workflow that writes the manifest, for this tag:
# an attestation another workflow, or another release, made does not vouch for it.
gh attestation verify "${manifest}" --repo "${repository}" \
    --signer-workflow "${repository}/.github/workflows/release-pipeline.yml" \
    --source-ref "refs/tags/${tag}" \
    --deny-self-hosted-runners >/dev/null || {
    echo "FAIL: the manifest's attestation does not verify for ${repository} at ${tag}" >&2
    exit 1
}

problems=()
while IFS=$'\t' read -r name expected bytes; do
    path="${directory}/${name}"
    if [ ! -f "${path}" ]; then
        problems+=("${name}: missing")
    elif [ "$(sha256 "${path}")" != "${expected}" ]; then
        problems+=("${name}: its digest changed")
    elif [ "$(wc -c <"${path}" | tr -d ' ')" != "${bytes}" ]; then
        problems+=("${name}: its size changed")
    fi
done < <(jq -r '.artifacts[] | [.name, .sha256, (.bytes | tostring)] | @tsv' "${manifest}")

# Nothing beside the manifest that it does not name: an artifact added after the fact is not
# evidence the manifest vouches for.
while IFS= read -r path; do
    name="$(basename "${path}")"
    jq -e --arg name "${name}" 'any(.artifacts[]; .name == $name)' "${manifest}" >/dev/null ||
        problems+=("${name}: not named by the manifest")
done < <(find "${directory}" -maxdepth 1 -type f ! -name evidence-manifest.json -print)

while IFS= read -r reason; do
    problems+=("the gate is incomplete: ${reason}")
done < <(jq -r '.incomplete[]' "${manifest}")

jq -n --slurpfile manifest "${manifest}" \
    --argjson problems "$(printf '%s\n' "${problems[@]+"${problems[@]}"}" | jq -R 'select(length > 0)' | jq -s .)" \
    '{tag: $manifest[0].tag, commit: $manifest[0].commit, artifacts: ($manifest[0].artifacts | length),
      verified: ($problems | length == 0), problems: $problems}'

if [ "${#problems[@]}" -gt 0 ]; then
    echo "FAIL: the evidence of $(jq -r .tag "${manifest}") does not verify (${#problems[@]} problems)" >&2
    exit 1
fi
echo "ok: the evidence of $(jq -r .tag "${manifest}") ($(jq -r .commit "${manifest}")) verifies" >&2
