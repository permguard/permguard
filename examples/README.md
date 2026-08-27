<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Examples

Policy workspaces you can apply to a running Permguard and ask questions of. Each
one is a real workspace — a manifest, policies in Cedar and Rego, and decision
requests — not a snippet.

| Example | Domain | What it is for |
| --- | --- | --- |
| **[basics](basics)** | users, groups, documents | the platform end to end, on a domain small enough to stay out of the way: apply, mirror, decide, read the decisions back, verify them, and two workspaces pushing at each other |
| **[release-pipeline](release-pipeline)** | software delivery | a realistic set of controls — team ownership, machine identities, separation of duties, incident-only rollback — and the audit evidence they leave |

Start with **basics** to see how a workspace reaches a decision, and read
**release-pipeline** to see what a set of controls looks like when the domain is
one somebody is actually audited on.

The reasoning behind the release pipeline example, written for a reader who has
never used Permguard, is in
**[docs/use-cases/release-pipeline.md](../docs/use-cases/release-pipeline.md)**.

## Not to be confused with `lab/`

`lab/` at the repository root is something else: the configuration of the local
observability stack — Prometheus, Grafana, Loki, Tempo — that `task lab:up` starts.
These examples are policy workspaces; that is the environment they can be watched
in.
