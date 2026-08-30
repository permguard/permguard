#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Fails when a file that can carry a licence header does not.
#
# CONTRIBUTING.md asks every source file for one, which makes it a rule; this makes it a fact. The
# form is the short one — a copyright line and an SPDX identifier — because that is what tooling
# reads and what a reviewer can check at a glance.
#
# Formats without comments are skipped, because there is nowhere to put it: plain JSON, Markdown
# (which uses an HTML comment instead, and is checked), lock files, and generated output.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

EXPECTED_COPYRIGHT='Copyright (c) 2022 Nitro Agility S.r.l.'
EXPECTED_SPDX='SPDX-License-Identifier: Apache-2.0'

missing=""
wrong=""

while IFS= read -r file; do
    case "${file}" in
        # Nowhere to put a comment, or not ours to annotate.
        Cargo.lock | LICENSE | *.json) continue ;;
        # Third-party or generated.
        .gitignore | */node_modules/* | target/*) continue ;;
    esac

    # Tracked but not on disk: a rename or deletion that has not been committed yet. The header
    # check is about the files that exist; the file's fate is git's business.
    if [ ! -f "${file}" ]; then
        continue
    fi

    # Only the first 20 lines: a header further down is not a header.
    head="$(head -20 "${file}")"

    # Do not pipe `printf` into `grep -q` while `pipefail` is active. `grep -q` may stop reading as
    # soon as it finds the text; the writer can then receive SIGPIPE and make a successful match look
    # like a failed pipeline. Match the already-bounded shell value directly instead.
    if [[ "${head}" != *"${EXPECTED_SPDX}"* ]]; then
        missing="${missing}  ${file}"$'\n'
        continue
    fi

    if [[ "${head}" != *"${EXPECTED_COPYRIGHT}"* ]]; then
        wrong="${wrong}  ${file}"$'\n'
    fi
done < <(
    git ls-files \
        '*.rs' '*.sh' '*.toml' '*.yml' '*.yaml' '*.md' '*.jsonc' '*.tpl' '*.txt' '*.js' \
        'Makefile' 'Dockerfile' '*.Dockerfile' \
    | sort
)

status=0

if [ -n "${missing}" ]; then
    printf 'these files carry no licence header:\n%s' "${missing}" >&2
    status=1
fi

if [ -n "${wrong}" ]; then
    printf 'these files carry an SPDX identifier but not the expected copyright line:\n%s' "${wrong}" >&2
    printf 'expected: %s\n' "${EXPECTED_COPYRIGHT}" >&2
    status=1
fi

if [ "${status}" -ne 0 ]; then
    printf 'error: every source file carries the short-form header, as CONTRIBUTING.md asks\n' >&2
    exit 1
fi

printf 'ok: every tracked source file carries the licence header\n'
