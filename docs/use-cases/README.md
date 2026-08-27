<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Use cases

What Permguard is for, one domain at a time. Each page describes a domain, the
people and systems in it, the controls that domain needs, and why those controls
are hard to get right without an external decision point.

These pages assume no Permguard knowledge and no Cedar or Rego. Rules are written
as pseudocode — what is allowed, and the condition — so that the argument can be
read by whoever owns the process, not only by whoever implements it.

| Use case | Domain | The controls it turns on |
| --- | --- | --- |
| **[Release and deployment operations](release-pipeline.md)** | software delivery | team ownership, verified machine identities, separation of duties on approvals, production rollback restricted to an open incident |

Every use case has a runnable counterpart under
**[examples/](../../examples)**: the same controls as real policies, with requests
to send and decisions to read back. The prose says what the control is for; the
example proves it does what the prose claims.
