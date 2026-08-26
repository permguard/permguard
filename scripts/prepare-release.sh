#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Moves the repository to a version, so that tagging it is safe.
#
# The version of a release is its tag, and nothing else. GoReleaser passes the tag into every build
# as `PERMGUARD_BUILD_VERSION`, `permguard-core`'s `build::VERSION` reads it, and every binary
# reports it — so the workspace version in Cargo.toml never moves, no release churns the lockfile,
# and there is no number to keep in sync with the tag because there is only the tag.
#
# One file still has to name the release, and it is not a Rust one:
#
#   Chart.yaml       version and appVersion, the second being the image tag the chart deploys
#
# A chart left behind deploys images this release does not publish, and Helm reads a file rather
# than an environment variable, so this number is committed before the tag exists.
#
# CHANGELOG.md is promoted when there is something to promote: the `## [Unreleased]` bullets become
# this version's section. Empty is allowed — the release notes GoReleaser builds from the commits
# are the floor, and a human sentence is the thing worth writing, not the thing worth blocking on.
#
#   scripts/prepare-release.sh 0.1.1

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

version="${1:-}"

if [ -z "${version}" ]; then
    echo "usage: $0 <major>.<minor>.<patch>" >&2
    echo "the version without the leading v — the tag v<version> is what gets created from it" >&2
    exit 2
fi

# Tolerated rather than documented: `v0.1.1` is what half the muscle memory types.
version="${version#v}"

if ! printf '%s' "${version}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.-]+)?$'; then
    echo "not a version: ${version}" >&2
    echo "expected <major>.<minor>.<patch>, without the leading v" >&2
    exit 1
fi

tag="v${version}"
current="$(sed -n 's/^version: \(.*\)$/\1/p' charts/permguard/Chart.yaml | head -1)"

# Read before anything is written, compared after: the workspace version is not the release
# version, and a release that quietly moved it would be a release nobody meant to cut.
workspace_version() {
    awk -F'"' '/^\[/ { in_section = ($0 ~ /^\[(workspace\.)?package\]/) }
               in_section && /^version = "/ { print $2; exit }' Cargo.toml
}
declared_before="$(workspace_version)"

if [ -z "${current}" ]; then
    echo "cannot read the chart version from charts/permguard/Chart.yaml" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "the tag ${tag} already exists locally — delete it first if it was never released:" >&2
    echo "  git tag -d ${tag} && git push origin :refs/tags/${tag}" >&2
    exit 1
fi

if [ "${current}" != "${version}" ]; then
    printf 'releasing %s -> %s\n' "${current}" "${version}"

    # `version` is the chart's own, `appVersion` is what it deploys — which is the image tag, so a
    # chart left behind deploys images that this release does not publish.
    sed -i.bak -E \
        -e "s/^version: ${current}\$/version: ${version}/" \
        -e "s/^appVersion: \"${current}\"\$/appVersion: \"${version}\"/" \
        charts/permguard/Chart.yaml
    rm -f charts/permguard/Chart.yaml.bak

    # The Unreleased section becomes this version, and a fresh empty one takes its place. The
    # bullets are moved, not generated: they were written by whoever made the change. Nothing to
    # move is a normal outcome, and the section is left alone when that is the case.
    unreleased_bullets="$(
        awk '
            /^## \[Unreleased\]/ { inside = 1; next }
            inside && /^## / { exit }
            inside { print }
        ' CHANGELOG.md | grep -cE '^\s*[-*]' || true
    )"

    if [ "${unreleased_bullets}" -gt 0 ]; then
        today="$(date -u +%Y-%m-%d)"
        awk -v version="${version}" -v today="${today}" '
            /^## \[Unreleased\]/ && !done {
                print "## [Unreleased]"
                print ""
                print "Nothing yet."
                print ""
                print "## [" version "] - " today
                done = 1
                inside = 1
                next
            }
            inside && /^## / { inside = 0; print; next }
            # The placeholder does not follow the bullets it stood in for.
            inside && $0 == "Nothing yet." { next }
            { print }
        ' CHANGELOG.md > CHANGELOG.md.new
        mv CHANGELOG.md.new CHANGELOG.md
        printf 'CHANGELOG.md: Unreleased promoted to %s - %s (%s bullet(s))\n' \
            "${version}" "${today}" "${unreleased_bullets}"
    else
        printf 'CHANGELOG.md: nothing under Unreleased to promote, left as it is\n'
    fi
else
    # This is a valid retry state: the chart commit may have reached main while pushing the tag
    # failed. Do not force somebody to manufacture another version just to finish that release.
    printf 'chart already prepared at %s; creating its missing tag\n' "${version}"
fi

# Retrying an already-prepared release takes this path too, so validate instead of assuming the
# earlier run completed every write.
if ! grep -qx "version: ${version}" charts/permguard/Chart.yaml ||
    ! grep -qx "appVersion: \"${version}\"" charts/permguard/Chart.yaml; then
    echo "Chart.yaml does not carry version and appVersion ${version}" >&2
    exit 1
fi
printf 'Chart.yaml: version and appVersion at %s\n' "${version}"

declared_after="$(workspace_version)"
if [ "${declared_after}" != "${declared_before}" ]; then
    echo "the workspace version moved ${declared_before} -> ${declared_after}" >&2
    echo "the release version comes from the tag; Cargo.toml is not part of a release" >&2
    exit 1
fi
printf 'Cargo.toml: left at %s — the binaries take %s from the tag\n' "${declared_after}" "${version}"

echo
printf 'ready for %s. Review the diff, then commit and tag:\n' "${tag}"
printf '  git add charts/permguard/Chart.yaml CHANGELOG.md\n'
printf '  git commit -m "chore(release): %s"\n' "${version}"
printf '  git tag -a %s -m "%s" && git push origin main %s\n' "${tag}" "${tag}" "${tag}"
