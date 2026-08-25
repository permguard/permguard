<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Answering decisions

How a data plane turns a mirrored ledger into an authorization decision, in
microseconds, without ever trusting anything it cannot verify.
Status: **implemented** — `permguard-data-plane`'s `authz` module (the serving
side), `permguard-languages` (the engines), `permguard check` (the client).
The contract itself is specified in
[Profiles & Manifest](profiles-manifest.md); this is the machine behind it.

## The path of one request

```text
POST /access/v1/evaluation           {zone, ledger, subject, action, resource, context}
        │
        ▼  resolve      required fields, defaults, boxcarring          400 if not a request
        ▼  locate       which mirror this zone/ledger names            404 if not served here
        ▼  head         refs/main → commit → manifest → LOAD GATE      503 if it may not be served
        ▼  block?       a commit this engine already refused           503, without reading a policy
        ▼  partitions   from memory, or compiled from the volume and kept
        ▼  evaluate     every partition of the profile
        ▼  answer       200 {decision, context{id, reason_admin, reason_user, policies}}
```

Both surfaces — HTTP and gRPC — land on the same code, so a deployment picks a
transport and never a set of semantics.

## What makes it fast

A decision is answered from a **compiled** program: every policy parsed, the
engine's own representation built, the schema checked. That work happens once —
and it happens off the request path whenever it can, because the
synchronization loop does it the moment a ledger arrives.

| | |
| --- | --- |
| Cache key | `(zone-id, ledger-id, commit, partition)` |
| Populated by | the sync loop after a mirror advances, or the first request that misses |
| Bounds | `authz.cache.partitions` (entries) and `authz.cache.bytes` (weight) |
| Eviction | least recently used, until both bounds hold — never to nothing |

The **commit is part of the key**, and that is what makes the cache correct
rather than merely fast: a synchronization that advances a ledger asks for a
key that does not exist yet, compiles it, and the old entries fall out as the
least recently used. Nothing serves a commit that has been replaced, and
nothing has to remember to invalidate anything.

What is *not* cached is the head: `refs/main` is read per request — one small
file, from the page cache — so a ledger synchronized a second ago answers from
its new commit now, without waiting for anything to notice.

## What makes it trustworthy

| Gate | When | On failure |
| --- | --- | --- |
| The whole closure was verified before the checkpoint moved | at sync | nothing is served that was not proven |
| Objects are digest-verified on read | every read | a corrupt object cannot be evaluated, only reported |
| **Load gate**: language *and* engine ranges | every head read | `503 ledger_incompatible` — never best-effort |
| **Schema**: every policy type-checks against it | at compile | the load is refused, and the ledger is blocked |
| Fail-closed evaluation | every request | an error is a deny carrying its reason |

An engine outside a manifest's declared range interpreting the same policies
differently is a silent authorization bypass. So it is not permitted to try:
the answer is `unavailable`, which is a different sentence from `deny` and
calls for different behaviour on the PEP's side.

### The block file

A ledger this engine may not serve will stay that way until the ledger
*changes*. Rediscovering that every round — reading every object, compiling
every policy, to reach the same refusal — would be expensive and would train an
operator to ignore the log. So the refusal is written down beside the mirror:

```text
<mirror>/BLOCKED   { "commit": "sha256:…", "reason": "…", "at": … }
```

The rule is one line: **if the block names the commit that is now the head,
skip; otherwise try again.** A synchronization that brings a new commit
therefore retries by itself — exactly when something might have changed — and a
ledger that stays put stays blocked for the cost of one small file read. There
is nothing to configure and no timer to tune. A plane that restarts does not
forget what it learned, and an operator can see the reason on the volume.

A blocked ledger is **refused, not downgraded**: the head is whatever the
checkpoint names now, so the plane answers `503 ledger_incompatible` rather
than answering from the last commit it could compile — which may still be in
the cache. The same holds for a head that cannot be read at all. See
[Keeping a data plane current](data-plane-mirrors.md#after-a-mirror-advances-ready-or-blocked)
for why that is the safe reading and not merely the strict one.

## What a mirror looks like on the volume

```text
<volume>/data/mirrors/<zone-id>/<ledger-id>/
├── FORMAT            the layout version
├── objects/          zlib at rest, content-addressed
├── refs/main         {head, counter} — what was verified
├── LEDGER            {zone_id, zone_name, ledger_id, ledger_name, server}
└── BLOCKED           only when this engine may not serve it
```

Directories are **identities**, so a rename upstream never moves one and two
zones cannot collide over a reused name. `LEDGER` is what lets a request that
names things — `zone: "acme"` — find the directory; the sync loop rewrites it
every round, so a rename reaches this plane with the next sync.

## The languages

Both built-in languages answer the same profile. A caller cannot tell which
one decided.

| | Cedar | Rego |
| --- | --- | --- |
| Engine | `cedar-policy` (official) | `regorus` (Microsoft) |
| Decision | `permit` / `forbid`, Cedar's own resolution | `allow` and `deny` rules, **deny overrides**, absent means no |
| The request becomes | principal `type::"id"`, action `Action::"name"`, resource `type::"id"`, a context record | the `input` document: `subject`, `resource`, `action`, `context` |
| Attributes | `subject.properties`/`resource.properties` are synthesized as entity attrs unless `entities` already states that uid | read from `input.*.properties` |
| Entity graph | `entities.items`, verbatim, in Cedar's JSON shape | `data.entities` — Rego traverses data |
| Schema | enforced at load, strict mode | none: a `schema: true` Rego partition is refused |
| Policies cited | the store's policy identity, so a decision and its audit record name the same thing | the same |

For Rego the convention is written down because Rego has none of its own:
`allow` permits, `deny` refuses whatever else allowed, and `default allow :=
false` is what makes a module's answer well-defined.

## What an operator sees

**Logs.** `authz.partition_compiled` (with the language, the policy count and
the bytes), `authz.ledger_blocked`, `authz.ledger_not_served`,
`authz.ledger_warm`, `sync.ledger_ready`.

**The audit trail.** Every decision, permit and deny alike, as
`authz.decision`: the subject (the `principal` extension when the caller sent
one, so *who asked* is on the record), and a target naming the ledger, the
action, the resource, the counter it was decided at and the decision's own
`context.id`. A trail that carried only denies could not answer "who read
this, and when" — the question auditors actually ask.

**Metrics**, on the telemetry port, and both Grafana dashboards read them:

| Metric | Answers |
| --- | --- |
| `permguard_authz_decisions_total{zone,ledger,outcome}` | permits and denies, per ledger |
| `permguard_authz_evaluations_total{…}` | the same, counting a batch as what it is |
| `permguard_authz_refusals_total{reason}` | requests that never reached a decision, by why |
| `permguard_authz_request_seconds` | the latency a caller feels |
| `permguard_authz_evaluation_seconds{partition}` | where the time goes inside a decision |
| `permguard_authz_compilations_total` · `_compile_seconds` | the expensive path — should be flat between syncs |
| `permguard_authz_cache_lookups_total{result}` | hit rate: a falling one means the bounds are too small |
| `permguard_authz_cache_entries` · `_bytes` | what is held, against the configured bounds |
| `permguard_authz_cache_evictions_total` | climbing steadily: raise the bounds |
| `permguard_authz_blocked_ledgers{zone,ledger}` | anything above zero is an upgrade waiting to happen |
| `permguard_authz_audit_records_total{outcome}` | decision audit queue outcomes: `queued`, `written`, `dropped`, `failed` |
| `permguard_authz_audit_queue_depth` | audit records waiting behind the worker |

## Configuration

Under `dataPlane.authz`, beside `sync` — the decision path is the data plane's
own business, and a control plane answers no decisions.

```yaml
dataPlane:
  authz:
    cache:
      partitions: "64"       # compiled partitions held at once
      bytes: "256M"          # what they may weigh
    max_evaluations: "256"   # the most evaluations one boxcarred request may carry
```

Every value is a flat setting, so an environment variable
(`PERMGUARD_AUTHZ_CACHE_BYTES`, …) still wins over the file, which wins over
the default. Every shipped configuration carries the block, filled in for its
environment.

## Asking from the command line

```bash
# A document — what a test suite keeps in version control.
permguard check -f request.json

# From a pipe.
cat request.json | permguard check -f -

# The question a person asks at a terminal.
permguard check --subject user:alice --action read --resource document:budget

# Machine-readable, like every other command.
permguard check -f request.json -o json
```

Which store the question is about follows one rule, shared by every command
that needs it: **flags win, then the workspace, then the document's own
`zone`/`ledger`**. Standing in a checked-out ledger, `check` asks about *that*
ledger — the point of standing there — and `--ignore-workspace` sends the
document exactly as written. The endpoint follows the ordinary layered
pipeline: `--data-endpoint` > `PERMGUARD_DATA_PLANE_ENDPOINT` > the
configuration file > `http://127.0.0.1:7656`.

A **deny exits 0**: it is an answer. A script branches on `decision`, not on
the exit code, because an exit code that conflated a deny with a PDP that is
down would be a trap. Only a request that could not be evaluated is a failure,
with the documented class, code and exit status.

## What is deliberately not here yet

Authentication and authorization **of the API itself**: today a caller reaches
this endpoint over TLS (mutual TLS where a deployment asks for it), and when
tokens arrive they arrive for every consumer at once, designed once for the CLI
and the planes together. The Search APIs of the standard are not served, and
their absence from the metadata document is the declaration. Signed decision
responses are the `permguard.trust-anchor.v1` profile, later: the data plane's
ring at `keys/data` already exists for it.
