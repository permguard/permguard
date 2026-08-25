#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Fails when the Makefile and the Taskfile stop offering the same things.
#
# The repository keeps both because a contributor has one or the other, and neither is generated from
# the other — so they drift, silently, and the first person to notice is somebody following the README
# with the wrong tool. The two spell names differently (`run:all` against `run-all`), so the
# comparison is on the name with separators removed.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Documented Make targets: the ones carrying a `## ` description, which is what `make help` lists.
make_targets="$(
    awk -F':' '/^[a-zA-Z0-9_.-]+:.*## /{ print $1 }' Makefile | tr -d ':-' | sort -u
)"

# Task names, which are the top-level keys under `tasks:`.
task_targets="$(
    awk '
        /^tasks:/ { inside = 1; next }
        inside && /^[a-zA-Z]/ { inside = 0 }
        inside && /^  [a-zA-Z0-9_.:-]+:/ { name = $1; sub(/:$/, "", name); print name }
    ' Taskfile.yml | tr -d ':-' | sort -u
)"

# `help` is Make's own listing; Task has `--list` built in, so there is nothing to compare it to.
make_targets="$(echo "${make_targets}" | grep -v '^help$' || true)"

only_make="$(comm -23 <(echo "${make_targets}") <(echo "${task_targets}"))"
only_task="$(comm -13 <(echo "${make_targets}") <(echo "${task_targets}"))"

if [ -n "${only_make}" ] || [ -n "${only_task}" ]; then
    if [ -n "${only_make}" ]; then
        printf 'in the Makefile and not the Taskfile:\n%s\n' "${only_make}" >&2
    fi
    if [ -n "${only_task}" ]; then
        printf 'in the Taskfile and not the Makefile:\n%s\n' "${only_task}" >&2
    fi
    printf 'error: the two build systems must offer the same commands\n' >&2
    exit 1
fi

printf 'ok: the Makefile and the Taskfile offer the same %s commands\n' "$(echo "${make_targets}" | wc -w | tr -d ' ')"
