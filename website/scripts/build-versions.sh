#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Builds the whole versioned documentation site into one directory.
#
# GitHub Pages replaces the entire site on every deploy, so every deploy rebuilds every version:
#
#   latest         from the checked-out `main`, at the site root
#   MAJOR.MINOR    from the newest `vMAJOR.MINOR.PATCH` tag of that line, at `<root>/MAJOR.MINOR/`
#
# A patch tag therefore replaces its line (`v0.1.2` supersedes `v0.1.1` under `0.1/`). Tags that are
# not exactly `vMAJOR.MINOR.PATCH`, the `0.0` line, and tags from before the site existed are left
# out. Every version is built with the same list of versions, so every version's menu offers them all.
#
# Usage: build-versions.sh <output-dir> <root-base-path> <root-url>
#   root-base-path  the path Pages serves the site under, such as `/permguard` (empty at a domain root)
#   root-url        the absolute URL of that root, such as `https://docs.permguard.com/permguard`

set -euo pipefail

out="$(mkdir -p "$1" && cd "$1" && pwd)"
root_base="${2%/}"
root_url="${3%/}"

repo="$(git rev-parse --show-toplevel)"
cd "${repo}"

# The newest tag of every published MAJOR.MINOR line. `sort -V` orders patch releases, so the last
# tag seen for a line wins.
declare -A newest=()
while IFS= read -r tag; do
    [[ "${tag}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || continue
    line="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    [[ "${line}" == "0.0" ]] && continue
    git cat-file -e "${tag}:website/package.json" 2>/dev/null || continue
    newest["${line}"]="${tag}"
done < <(git tag --list 'v*' | sort -V)

lines=()
if ((${#newest[@]})); then
    mapfile -t lines < <(printf '%s\n' "${!newest[@]}" | sort -rV)
fi
versions_json="$(printf '%s\n' "${lines[@]}" | jq -R . | jq -cs 'map(select(length > 0))')"
echo "published versions: ${versions_json}"

build() {
    local site_dir="$1" version="$2" base_path="$3" target="$4"
    (
        cd "${site_dir}"
        npm ci --no-audit --no-fund
        DOCS_VERSION="${version}" \
            DOCS_VERSIONS="${versions_json}" \
            DOCS_ROOT_URL="${root_url}" \
            VITEPRESS_BASE="${base_path}" \
            npm run docs:build
    )
    mkdir -p "${target}"
    cp -R "${site_dir}/.vitepress/dist/." "${target}/"
}

build "${repo}/website" latest "${root_base}/" "${out}"

worktrees="$(mktemp -d)"
trap 'git -C "${repo}" worktree prune; rm -rf "${worktrees}"' EXIT
for line in "${lines[@]}"; do
    tag="${newest[${line}]}"
    echo "building ${line} from ${tag}"
    git worktree add --detach "${worktrees}/${line}" "${tag}" >/dev/null
    build "${worktrees}/${line}/website" "${line}" "${root_base}/${line}/" "${out}/${line}"
    git worktree remove --force "${worktrees}/${line}"
done

printf '%s\n' "${versions_json}" > "${out}/versions.json"
