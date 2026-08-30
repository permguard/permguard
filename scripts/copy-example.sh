#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Copies one of the workspaces under `examples/` into a directory of your choosing, so that a
# playground can be started from a known-good set of policies instead of from an empty folder.
#
# Two paths, resolved differently on purpose: the **source** is relative to this repository, because
# that is where the examples live; the **destination** is wherever the caller was standing, because
# that is where the playground is. The Taskfile passes `USER_WORKING_DIR` and the Makefile passes
# `CURDIR`, which is the same idea in each tool's own words.
#
# What is not copied is `.permguard/`: it is the workspace's own state — which remote it tracks, which
# commit it is at — and carrying it over would give the new directory another workspace's history.

set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

example="${1:-}"
destination="${2:-}"

if [ -z "${example}" ] || [ -z "${destination}" ]; then
    printf 'usage: %s <example> <destination>\n' "$(basename "$0")" >&2
    exit 64
fi

source_dir="${repository}/examples/${example}"

if [ ! -d "${source_dir}" ]; then
    printf 'error: no example named `%s`. There is:\n' "${example}" >&2
    for found in "${repository}"/examples/*/; do
        printf '  %s\n' "$(basename "${found}")" >&2
    done
    exit 64
fi

mkdir -p "${destination}"
destination="$(cd "${destination}" && pwd)"

# Copying an example over itself would be a slow no-op at best, and at worst would look like it did
# something. It is a mistake worth naming rather than performing.
if [ "${destination}" = "${source_dir}" ]; then
    printf 'error: that is the example itself — pick a directory to copy it *into*\n' >&2
    exit 64
fi

copied=0
while IFS= read -r relative; do
    mkdir -p "${destination}/$(dirname "${relative}")"
    cp "${source_dir}/${relative}" "${destination}/${relative}"
    copied=$((copied + 1))
done < <(cd "${source_dir}" && find . -type f -not -path './.permguard/*' | sed 's|^\./||' | sort)

printf '%s file(s) copied from examples/%s into %s\n\n' "${copied}" "${example}" "${destination}"

# The languages the example's own manifest names, so the `init` printed below is the one that will
# actually work. Read from the manifest rather than guessed from the example's name: a workspace
# initialised for the wrong languages refuses the sources it was just handed.
languages="$(
    sed -n 's/.*language:[[:space:]]*{[[:space:]]*name:[[:space:]]*\([a-z][a-z0-9_-]*\).*/\1/p' \
        "${source_dir}/manifest.yml" | sort -u | paste -sd, -
)"
languages="${languages:-cedar,rego}"

printf 'Next:\n'
printf '  task cli -- -w %s init %s --language %s\n' "${destination}" "${example}" "${languages}"
printf '  task cli -- -w %s remote add origin http://127.0.0.1:6443\n' "${destination}"
printf '  task cli -- -w %s validate\n' "${destination}"

if [ "${example}" = "dogwood-session-access" ]; then
    printf '\nThis one needs a plane with the temporal interface on:\n'
    printf '  task run:experimental        # both planes in one process, event path enabled\n'
fi
