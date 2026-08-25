#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

#
# The coverage floor: every crate keeps at least 60% of its lines under test.
#
# Per crate, not per workspace, on purpose: a workspace average lets a large
# well-tested crate hide an untested one. The floor is a floor — the numbers
# above it are quality, the number below it is a failure.
#
#   scripts/check-coverage.sh            # measure and gate
#   scripts/check-coverage.sh --report   # gate an existing measurement (fast, CI second step)
#
# Needs `cargo llvm-cov` (cargo install cargo-llvm-cov).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

FLOOR=60

if [ "${1:-}" = "--report" ]; then
  report="$(cargo llvm-cov report 2>/dev/null)"
else
  report="$(cargo llvm-cov --workspace 2>/dev/null)"
fi

gate="$(echo "$report" | awk -v floor="$FLOOR" '
  $1 ~ /^permguard-[a-z-]+\// {
    split($1, parts, "/")
    lines[parts[1]] += $8
    missed[parts[1]] += $9
  }
  END {
    failed = 0
    for (name in lines) {
      covered = 100 * (lines[name] - missed[name]) / lines[name]
      mark = covered < floor ? "FAIL" : "ok  "
      if (covered < floor) failed = 1
      printf "%s %-32s %6.1f%%  (floor %d%%)\n", mark, name, covered, floor
    }
  }
')"

echo "$gate" | sort -k2

if echo "$gate" | grep -q '^FAIL'; then
  echo "coverage: at least one crate is under the ${FLOOR}% line floor" >&2
  exit 1
fi
echo "coverage: every crate is at or above the ${FLOOR}% line floor"
