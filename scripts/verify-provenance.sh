#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies the SLSA provenance of a release's artifacts, and fails on the first that does not name
# the approved builder and the expected source.
#
#   scripts/verify-provenance.sh files  <dist-directory>
#   scripts/verify-provenance.sh images <dist-directory>
#
# `files` verifies every file in <dist>/checksums.txt, before anything is published. `images`
# verifies every image in <dist>/digests.txt, which exists only once the images are in their
# registries. Every artifact must carry a GitHub artifact attestation whose provenance names:
#
#   source   this repository, the tag being released, and the commit it points at;
#   builder  `.github/workflows/release-build.yml` of this repository — the reusable workflow that
#            builds, packages and attests in isolation from the workflow that calls it, which is
#            what makes it a SLSA Build L3 builder — on a GitHub-hosted runner.
#
# The raw verification results go to <dist>/provenance-<phase>.json and a line per artifact naming
# its builder and source to <dist>/provenance-<phase>.txt; both are published with the release as
# its provenance evidence. Run by the release workflow, with `GITHUB_REPOSITORY`, `GITHUB_REF_NAME`,
# `GITHUB_SHA` and `GH_TOKEN` set.
#
# What this proves is that the release's configuration is right: that every artifact was attested,
# by the approved builder, for this tag and commit. It runs inside that builder, so it is not a
# defence against someone who controls it; a user's own `gh attestation verify` is.
set -euo pipefail

usage='usage: scripts/verify-provenance.sh files|images <dist-directory>'
phase="${1:?${usage}}"
dist="${2:?${usage}}"
repository="${GITHUB_REPOSITORY:?}"
tag="${GITHUB_REF_NAME:?}"
commit="${GITHUB_SHA:?}"
builder_workflow="${repository}/.github/workflows/release-build.yml"

case "${phase}" in
    files)
        listing=checksums.txt
        # Four binaries on six platforms, at the least.
        minimum=24
        ;;
    images)
        listing=digests.txt
        # Four images (cli, all-in-one, control plane, data plane) in each of two registries.
        minimum=8
        ;;
    *)
        printf '%s\n' "${usage}" >&2
        exit 2
        ;;
esac

if [ ! -s "${dist}/${listing}" ]; then
    printf 'error: %s/%s is missing or empty: there is nothing to verify\n' "${dist}" "${listing}" >&2
    exit 1
fi

json="${dist}/provenance-${phase}.json"
summary="${dist}/provenance-${phase}.txt"
printf '[' > "${json}"
printf 'provenance policy: source %s@refs/tags/%s (%s), builder %s on a GitHub-hosted runner\n' \
    "${repository}" "${tag}" "${commit}" "${builder_workflow}" > "${summary}"
first=1

# An attestation is written a moment before it is verified, and the API that serves it may not
# have it yet: three attempts, a little apart, before a missing one counts as a failure.
attempts="${VERIFY_ATTEMPTS:-3}"
pause="${VERIFY_PAUSE:-5}"

verify() {
    local subject="$1" result builder source attempt=1
    until result="$(gh attestation verify "${subject}" \
        --repo "${repository}" \
        --signer-workflow "${builder_workflow}" \
        --source-ref "refs/tags/${tag}" \
        --source-digest "${commit}" \
        --deny-self-hosted-runners \
        --format json)"; do
        if [ "${attempt}" -ge "${attempts}" ]; then
            printf 'error: the provenance of %s did not verify after %s attempts\n' "${subject}" "${attempts}" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep "${pause}"
    done
    builder="$(jq -r '[.[].verificationResult.signature.certificate.buildSignerURI] | unique | join(", ")' <<<"${result}")"
    source="$(jq -r '[.[].verificationResult.signature.certificate | "\(.sourceRepositoryURI)@\(.sourceRepositoryRef) (\(.sourceRepositoryDigest))"] | unique | join(", ")' <<<"${result}")"
    # The policy flags above already enforce both; naming them is what makes the evidence readable.
    if [ -z "${builder}" ] || [ "${builder}" = "null" ] || [[ "${source}" == *null* ]]; then
        printf 'error: the attestation of %s does not name its builder and source\n' "${subject}" >&2
        exit 1
    fi
    [ "${first}" -eq 1 ] || printf ',' >> "${json}"
    first=0
    printf '%s' "${result}" >> "${json}"
    printf '%s\n  builder: %s\n  source:  %s\n' "${subject}" "${builder}" "${source}" >> "${summary}"
}

# One line of a checksums file: `<sha256>  <name>`, the digest optionally written `sha256:<hex>`.
# Anything else is refused rather than guessed at: a line read wrongly is an artifact not verified.
line_pattern='^(sha256:)?([0-9a-f]{64})[[:space:]]+\*?([^[:space:]]+)$'

verified=0
# Several tags of one image share a digest; it is one artifact, verified once. A newline-separated
# list rather than an associative array, so the script runs on the bash 3.2 macOS ships.
seen=$'\n'
while IFS= read -r line || [ -n "${line}" ]; do
    [ -n "${line}" ] || continue
    if ! [[ "${line}" =~ ${line_pattern} ]]; then
        # shellcheck disable=SC2016 # the backticks are literal, in the message
        printf 'error: %s holds a line that is not `<sha256>  <name>`: %s\n' "${listing}" "${line}" >&2
        exit 1
    fi
    if [ "${phase}" = files ]; then
        subject="${dist}/${BASH_REMATCH[3]}"
    else
        image="${BASH_REMATCH[3]}"
        # The tag is what follows the last `:` of the last path segment; a registry port is not one.
        last="${image##*/}"
        if [[ "${last}" == *:* ]]; then
            image="${image%:*}"
        fi
        subject="oci://${image}@sha256:${BASH_REMATCH[2]}"
    fi
    case "${seen}" in
        *$'\n'"${subject}"$'\n'*) continue ;;
    esac
    seen="${seen}${subject}"$'\n'
    verify "${subject}"
    verified=$((verified + 1))
done < "${dist}/${listing}"

printf ']\n' >> "${json}"

if [ "${verified}" -lt "${minimum}" ]; then
    printf 'error: verified %s %s; the release produces at least %s\n' "${verified}" "${phase}" "${minimum}" >&2
    exit 1
fi

printf 'ok: the provenance of %s %s names builder %s and source %s@%s\n' \
    "${verified}" "${phase}" "${builder_workflow}" "${repository}" "${tag}"
