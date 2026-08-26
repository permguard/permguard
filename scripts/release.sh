#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# Cuts a release: reads the latest `v<major>.<minor>.<patch>` tag, bumps the patch, and — after a
# `y` at the prompt — creates the annotated tag and pushes it to origin. The GitHub release,
# archives, packages, SBOMs, signatures, and container images are published by GoReleaser in CI.
#
#   scripts/release.sh          # v0.3.0 -> v0.3.1
#   scripts/release.sh 0.4.0    # tag exactly this version — how a minor or major release is cut
#   DRAFT=1 scripts/release.sh  # publish the release as a draft, to edit and release by hand
#   YES=1 scripts/release.sh    # no summary, no question: one line, then the release happens
#
# The tag is `v<version>` and its message is `<product> v<version>`, where the product is the
# repository's name. "Latest" is decided after fetching the remote's tags, so a stale checkout
# cannot re-issue a bump somebody else already pushed. The prompt shows what is about to happen —
# the commits going into the release, and any version bump — and anything other than `y` aborts
# with nothing created.
#
# The prompt shows commit subjects since the previous tag, so work committed straight to main is
# visible before the tag is pushed. GoReleaser builds the final release notes in CI.
#
# The version of a release is its tag: GoReleaser passes it into every build as
# `PERMGUARD_BUILD_VERSION` and the binaries report it, so Cargo.toml never moves and no release
# churns the lockfile. What still has to be committed before the tag is the chart — its `appVersion`
# is the image tag it deploys, and Helm reads a file. `prepare-release.sh` owns that write, so the
# local and the Actions entry points stay on one implementation.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

product="$(basename "$(pwd)")"

# What the chart currently deploys. This is the one number in the tree that a release moves, and
# the one the preparation below is checked against.
chart_version() {
  [[ -f charts/permguard/Chart.yaml ]] || return 0
  sed -n 's/^version: \(.*\)$/\1/p' charts/permguard/Chart.yaml | head -1
}

if [[ -n "$(git status --porcelain)" ]]; then
  echo "the working tree is not clean: commit or stash before releasing" >&2
  exit 1
fi

# The remote decides what "latest" means.
git fetch --tags --quiet origin

latest="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -1)"
chart="$(chart_version)"

if [[ $# -ge 1 && -n "$1" ]]; then
  version="${1#v}"
elif [[ -n "${latest}" ]]; then
  IFS=. read -r major minor patch <<<"${latest#v}"
  version="${major}.${minor}.$((patch + 1))"
else
  # Nothing to bump from, and the workspace version is no longer a release number to fall back on.
  echo "no tag to bump: name the first version, e.g. $0 0.1.0" >&2
  exit 1
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "\`${version}\` is not a <major>.<minor>.<patch> version" >&2
  exit 1
fi

tag="v${version}"

if git rev-parse --quiet --verify "refs/tags/${tag}" >/dev/null; then
  echo "the tag ${tag} already exists" >&2
  exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD)"

# What the release will say: every commit since the previous tag, newest first.
range="${latest:+${latest}..}HEAD"

if [[ -n "${YES:-}" ]]; then
  echo "releasing ${tag} — ${product} v${version}, from $(git rev-parse --short HEAD) on ${branch}"
else
  echo "release:"
  echo "  latest tag    ${latest:-none}"
  echo "  new tag       ${tag}"
  echo "  message       ${product} v${version}"
  echo "  commit        $(git rev-parse --short HEAD) on ${branch}"
  echo "  changes since ${latest:-the beginning}:"
  git log --format='    - %s (%h)' "${range}"
fi

# The warnings appear in both modes: YES silences the question, never the risks.
if [[ -n "${chart}" && "${chart}" != "${version}" ]]; then
  echo "  chart         Chart.yaml ${chart} -> ${version}, committed and pushed before tagging"
fi
if [[ "${branch}" != "main" ]]; then
  echo "  NOTE: this is not main"
fi
if [[ -n "${DRAFT:-}" ]]; then
  echo "  NOTE: DRAFT is ignored here; the GoReleaser workflow owns GitHub release publishing"
fi

if [[ -z "${YES:-}" ]]; then
  read -r -p "create ${tag}, push it and publish the release? [y/N] " answer
  case "${answer}" in
    y | Y | yes | YES) ;;
    *)
      echo "aborted: nothing was created"
      exit 1
      ;;
  esac
fi

# The binaries take their version from the tag, so nothing here has to be in the commit for them.
# The chart does: it names the image tag it deploys, in a file. That write is its own pushed commit
# and the tag lands on it. Run the preparation even when the chart already has the requested
# number — it validates the whole version surface, which a retried release needs.
if [[ -n "${chart}" ]]; then
  ./scripts/prepare-release.sh "${version}"
  prepared="$(chart_version)"
  if [[ "${prepared}" != "${version}" ]]; then
    echo "moving Chart.yaml did not take: it now says \`${prepared}\`, not ${version}" >&2
    exit 1
  fi
  git add charts/permguard/Chart.yaml CHANGELOG.md
  if ! git diff --cached --quiet; then
    git commit --quiet --message "${product} v${version}"
    git push --quiet origin HEAD
    echo "moved the chart to ${version}"
  fi
fi

git tag --annotate "${tag}" --message "${product} v${version}"
git push origin "${tag}"

echo "pushed ${tag}; the GoReleaser workflow will publish the release artifacts and images"
