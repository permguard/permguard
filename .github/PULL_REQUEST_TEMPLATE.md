<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

## What this changes

<!-- One or two sentences. What is different afterwards, not what you did. -->

## Why

<!-- The problem. If it is a bug, what it did before. -->

## Contributor License Agreement

By opening this pull request you confirm that you have read and accept the
[Permguard Contributor License Agreement](https://github.com/permguard/.github/blob/main/CLA.md).
You keep ownership of what you contribute; the CLA grants Nitro Agility S.r.l.
the rights it needs to distribute it as part of Permguard, now and under future
licensing terms.

- [ ] I have read and accept the Permguard Contributor License Agreement

## Checklist

- [ ] `task check` passes locally (lint, structural checks, tests)
- [ ] Tests cover the behaviour, not just the code path
- [ ] `CHANGELOG.md` updated under *Unreleased*, if this changes anything an operator can see
- [ ] Any new configuration key, flag, metric, exit status or `reason` code is documented
- [ ] `docs/compatibility.md` still describes reality, if this touches one of the listed interfaces

## Interfaces touched

<!-- Delete what does not apply. These are the things somebody automates against. -->

- [ ] Configuration file keys or environment variables
- [ ] CLI commands, flags, output fields or exit statuses
- [ ] HTTP routes or gRPC services
- [ ] Metric names or labels
- [ ] Container images, chart values, or anything in a release artifact
- [ ] None of the above
