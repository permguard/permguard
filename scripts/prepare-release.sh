#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Moves the repository to a version, so that tagging it is safe.
#
# The release pipeline refuses a tag whose version is not already in Cargo.toml, and it is right to:
# GoReleaser builds the commit the tag points at, so a version injected during the build would
# describe a binary that no commit in this repository produces. The number has to be committed
# first. That is a rule nobody remembers at the moment it matters — the moment a tag is already
# public and the pipeline has just failed — so this does the remembering.
#
# Four places carry the version and all four have to move together:
#
#   Cargo.toml       the workspace version, and the path dependencies pinned beside it
#   Cargo.lock       regenerated, because the pipeline builds with --locked and a stale lock fails
#   Chart.yaml       version and appVersion, the second being the image tag the chart deploys
#   CHANGELOG.md     the `## [Unreleased]` section, promoted to this version
#
# The changelog is promoted, never written: what changed for somebody *running* Permguard is a
# sentence only a person can write, and `check-changelog.sh` exists to insist on it. Write the
# bullets under `## [Unreleased]` while the change is fresh; this gives them their number.
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
current="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"

if [ -z "${current}" ]; then
    echo "cannot read the workspace version from Cargo.toml" >&2
    exit 1
fi

if [ "${current}" = "${version}" ]; then
    echo "the workspace is already at ${version}" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "the tag ${tag} already exists locally — delete it first if it was never released:" >&2
    echo "  git tag -d ${tag} && git push origin :refs/tags/${tag}" >&2
    exit 1
fi

# An entry that is only a heading is an entry nobody wrote, and the release check will say so later.
# Better here, before anything has been edited.
unreleased_bullets="$(
    awk '
        /^## \[Unreleased\]/ { inside = 1; next }
        inside && /^## / { exit }
        inside { print }
    ' CHANGELOG.md | grep -cE '^\s*[-*]' || true
)"

if [ "${unreleased_bullets}" -eq 0 ]; then
    echo "the '## [Unreleased]' section of CHANGELOG.md lists nothing" >&2
    echo "write what changed for whoever runs this, as bullets, then run this again" >&2
    exit 1
fi

printf 'releasing %s -> %s\n' "${current}" "${version}"

# The workspace version, and the path dependencies that pin it beside themselves. Anchored rather
# than a blanket substitution: a third-party dependency that happens to sit at the same version is
# not ours to move.
sed -i.bak -E \
    -e "s/^version = \"${current}\"\$/version = \"${version}\"/" \
    -e "s/^(permguard-[a-z-]+ = \{[^}]*version = )\"${current}\"/\1\"${version}\"/" \
    Cargo.toml
rm -f Cargo.toml.bak

moved="$(grep -c "\"${version}\"" Cargo.toml || true)"
printf 'Cargo.toml: %s version(s) moved\n' "${moved}"

if grep -q "^version = \"${current}\"\$" Cargo.toml; then
    echo "the workspace version in Cargo.toml did not move" >&2
    exit 1
fi

# The pipeline builds with --locked, so a lock that still names the old version fails the build.
# -w touches the workspace members and leaves the dependency graph alone.
cargo update --workspace --quiet
printf 'Cargo.lock: regenerated\n'

# `version` is the chart's own, `appVersion` is what it deploys — which is the image tag, so a
# chart left behind deploys images that this release does not publish.
sed -i.bak -E \
    -e "s/^version: ${current}\$/version: ${version}/" \
    -e "s/^appVersion: \"${current}\"\$/appVersion: \"${version}\"/" \
    charts/permguard/Chart.yaml
rm -f charts/permguard/Chart.yaml.bak
printf 'Chart.yaml: version and appVersion at %s\n' "${version}"

# The Unreleased section becomes this version, and a fresh empty one takes its place. The bullets
# are moved, not generated: they were written by whoever made the change.
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
printf 'CHANGELOG.md: Unreleased promoted to %s - %s\n' "${version}" "${today}"

# What the release pipeline checks first, checked here while the tag is still hypothetical.
./scripts/check-changelog.sh "${tag}"

echo
printf 'ready for %s. Review the diff, then commit and tag:\n' "${tag}"
printf '  git add Cargo.toml Cargo.lock charts/permguard/Chart.yaml CHANGELOG.md\n'
printf '  git commit -m "chore(release): %s"\n' "${version}"
printf '  git tag -a %s -m "%s" && git push origin main %s\n' "${tag}" "${tag}" "${tag}"
