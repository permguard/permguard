#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Writes the digest of every image tag a release pushed, as `<digest>  <image>:<tag>`: the
# `sha256sum` form, hex only, which is the one `actions/attest` reads from `subject-checksums`.
# A `sha256:` prefix on a line is an invalid digest to it, and failed a release at its last step.
#
#   scripts/image-digests.sh <version> <digests-file> [goreleaser-config]
#
# GoReleaser writes `dist/digests.txt` for the images it pushes, and the release attests and
# verifies every line of it. From GoReleaser 2.19 the file comes out empty for `dockers_v2`, so the
# attestation had no subject. This reads the same list GoReleaser built from, every image and tag
# of `dockers_v2` in the configuration, asks the registry for the digest each tag now names, and
# writes the file only when GoReleaser left it empty. A tag the registry does not hold fails it:
# an image that was not pushed is never attested by omission. `scripts/verify-provenance.sh` reads
# the same file, and accepts the digest with or without the prefix.
set -euo pipefail

version="${1:?usage: scripts/image-digests.sh <version> <digests-file> [goreleaser-config]}"
out="${2:?usage: scripts/image-digests.sh <version> <digests-file> [goreleaser-config]}"
config="${3:-.goreleaser.yaml}"
version="${version#v}"
major_minor="$(printf '%s' "${version}" | cut -d. -f1-2)"

if [ -s "${out}" ]; then
    echo "${out} already lists $(wc -l <"${out}" | tr -d ' ') image tags: kept as GoReleaser wrote it"
    exit 0
fi

# The `$image` is yq's own variable, not the shell's.
# shellcheck disable=SC2016
refs="$(yq -r '.dockers_v2[] | .images[] as $image | .tags[] | $image + ":" + .' "${config}" |
    sed -e "s/{{ \.Version }}/${version}/g" -e "s/{{ \.Major }}\.{{ \.Minor }}/${major_minor}/g")"
[ -n "${refs}" ] || {
    echo "FAIL: ${config} names no image under dockers_v2" >&2
    exit 1
}
if printf '%s\n' "${refs}" | grep -q '{{'; then
    echo "FAIL: a tag template this script does not render:" >&2
    printf '%s\n' "${refs}" | grep '{{' >&2
    exit 1
fi

listing=""
while IFS= read -r ref; do
    digest="$(docker buildx imagetools inspect "${ref}" --format '{{json .Manifest}}' | jq -r '.digest')"
    case "${digest}" in
        sha256:*) listing+="${digest#sha256:}  ${ref}"$'\n' ;;
        *)
            echo "FAIL: the registry names no digest for ${ref}" >&2
            exit 1
            ;;
    esac
done <<<"${refs}"
printf '%s' "${listing}" >"${out}"
echo "ok: $(wc -l <"${out}" | tr -d ' ') image tags written to ${out}"
