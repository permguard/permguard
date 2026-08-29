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
| **[dogwood-session-access](dogwood-session-access)** | session access | the *temporal* interface: a policy that decides on what has already happened, and the durable history it reads |

All three show the same thing about a request: `subject`, `action`, `resource` and `context` reach
every partition of a profile, and `partition_inputs` reaches **one**, by the partition's own name. What
each partition accepts is the ledger's decision, declared in `manifest.yml`; a request states the
type too, and the two are compared. `release-pipeline` covers every way that can go wrong, each
with a case asserting it.

Start with **basics** to see how a workspace reaches a decision, and read
**release-pipeline** to see what a set of controls looks like when the domain is
one somebody is actually audited on.

**dogwood-session-access** is the odd one out, and deliberately: the first two
answer a question the request contains, and it answers one the request cannot.
"Has this user logged in within the hour" is not in a `Read` request — it is in the
history — so that example is about a different interface, a durable event journal,
and what a decision must carry for somebody to reproduce it later.

The reasoning behind the release pipeline example, written for a reader who has
never used Permguard, is in
**[docs/use-cases/release-pipeline.md](../docs/use-cases/release-pipeline.md)**.

## Check what an example decides

Both carry cases — what the workspace claims its own policies decide — and
`permguard test` checks them offline, with the same engines a data plane uses:

```bash
permguard -w examples/release-pipeline test
permguard -w examples/basics test
```

Exit `0` when every case passes, `2` when one does not. It is the step between
`validate` (is this well formed?) and `plan` (push it): *does it decide what I
meant?*

## Copy one into a playground

To try things without editing the example itself, make a directory and fill it:

```bash
mkdir -p playground/rspipe && cd playground/rspipe
task cp-rspipe          # or: task cp-basics
```

The source is resolved against this repository, the destination against wherever
you are standing, and `.permguard/` is left behind — a playground gets the
policies, not another workspace's history. `playground/` is git-ignored, so what
happens there stays there.

`make cp-rspipe` does the same for whoever uses the Makefile.

## Not to be confused with `lab/`

`lab/` at the repository root is something else: the configuration of the local
observability stack — Prometheus, Grafana, Loki, Tempo — that `task lab:up` starts.
These examples are policy workspaces; that is the environment they can be watched
in.
