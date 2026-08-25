<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Decision logs

Every decision a data plane answers, recorded where it can be kept, proven and
consumed.
Status: **implemented** — `permguard-decisions` (the record, the chain, the
signed envelope, the spool), `permguard-data-plane`'s `decisions` module (the
journal and the shipper), `permguard-control-plane`'s `decisions` module
(ingestion, the store, the views, retention) and `permguard decisions` on the
command line. Where this document says a thing is not built yet, it says so in
place.

Where it says **normative**, two independent implementations must agree byte
for byte, or the chain they produce cannot be verified by the same code.

## The shape

```text
data plane                                 control plane                    consumers
──────────                                 ─────────────                    ─────────
decide  ─►  spool (append-only, on disk)
                │  shipper: batched, signed, at-least-once
                ▼
                                     ingest ─► segments (append-only,
                                                hash-chained, sealed)
                                                        │
                                                        ▼  read from an offset
                                                                        SIEM, data lake,
                                                                        an application, the CLI
```

Four properties hold this together, and each closes a failure that is common in
systems like this:

| Property | What it prevents |
| --- | --- |
| The decision path **never** waits on the log | a logging outage becoming an authorization outage |
| The record is durable **before** it is shipped | losing decisions to a restart, or to the control plane being down |
| **One writer, many readers** — consumers pull from an offset | a slow consumer back-pressuring the PDP, or the control plane growing a queue |
| The record is **signed and chained** | a log that cannot be told apart from one somebody edited |

## What this proves, and what it assumes

A cryptographic log is worth exactly what its trust model says, so the boundary
is drawn before anything else.

| | |
| --- | --- |
| **Proved** | that every record committed to a stream is intact, in order, unaltered and attributable to the key that signed its batch — and that no record committed to a stream has been silently removed, reordered or rewritten afterwards, by the control plane or by anyone downstream |
| **Assumed** | that the producer writes a record for every decision it answers |

The second is not provable by any log, and the specification does not pretend
otherwise: a compromised or buggy PDP that never creates a record leaves
nothing to detect. What narrows that assumption is elsewhere — the binary is
signed and its provenance attested, the plane declares its identity and build
in a signed marker (below), and the decision counters it exports
(`permguard_authz_decisions_total`) can be reconciled against the records
shipped. Reconciliation is *evidence of divergence*, not proof of completeness,
and it is worth having for exactly that.

Everything below concerns the first guarantee.

## Streams and sequence — normative

A **stream** is one producer's ordered, unbroken history. It is identified by
two values together:

```text
stream_id = (pdp.id, pdp.instance)
```

| | |
| --- | --- |
| `pdp.id` | the deployment's name for this plane — stable, reused across restarts, shared by replicas of the same deployment only if they also differ in `instance` |
| `pdp.instance` | a UUIDv7 identifying **one continuous incarnation**: minted when a spool is created, and again whenever continuity is broken — a lost volume, or an unrecoverable local loss (see Discontinuity) |

`seq` is a `u64` starting at `1`, incremented by one for **every record written
to the spool**, and never reused inside a stream.

The two rules that make this hold under failure:

- **The instance lives with the spool.** A process that restarts and finds its
  spool finds its instance and its last `seq`, and continues the same stream. A
  volume that is lost, wiped or replaced yields a **new instance**, therefore a
  new stream, therefore `seq` restarting at 1 with no ambiguity: `(stream_id,
  seq)` is still unique.
- **A stream is never resumed across a hole.** If records that were written and
  chained can no longer be shipped, the stream **ends**; a new incarnation
  begins. Why that has to be so is the Discontinuity section — it is the one
  place where an earlier draft of this design was mathematically wrong.
- **One writer per spool.** Two processes sharing a spool directory would share
  a sequence; the spool is opened exclusively, and a second opener refuses to
  start rather than interleave.

Consumers order by `seq` **within** a stream. Across streams there is no total
order and none is claimed — the control plane's own arrival order is what a
reader traverses, and each record carries its stream so per-producer order is
always recoverable.

## Configuration

The destination is described exactly like a mirror source — an exact URL and
its own trust material — because it is the same kind of relationship: a server
this plane must authenticate before it speaks to it. The client certificate is
deliberately its own: *may ship decision logs* and *may read policy* are two
different authorizations, and a deployment should be able to grant one without
the other.

```yaml
dataPlane:
  mirrors:
    servers:
      - url: "grpcs://control.acme.com:7557"
        tls: { ca_file: tls/control-plane-ca.pem }

  decisions:
    cache: { partitions: "64", bytes: "256M" }
    max_evaluations: "256"

    log:
      enabled: "true"

      # Where the record goes. Absent, and this plane mirrors exactly one
      # server: it ships there. Ambiguous (several mirror servers) is refused
      # at startup rather than guessed.
      server:
        url: "grpcs://control.acme.com:7557"
        tls:
          ca_file: tls/control-plane-ca.pem
          cert: tls/decision-log-client.pem     # its own identity, not the mirror's
          key: tls/decision-log-client.key
          server_name: control-plane

      # Durability before the network. Bounded both ways: a spool that grows
      # without limit turns a control-plane outage into a full disk.
      spool:
        directory: "decisions/spool"  # under the volume; holds the instance id too
        bytes: "512M"               # decision records only; the terminal record is reserved apart
        age: "24h"

      # Latency against efficiency: whichever comes first.
      batch: { bytes: "256k", interval: "1s" }

      # What to do when the spool is full — the one decision only a deployment
      # can make. `open`: keep answering; the stream ends with a signed
      # discontinuity and a new one begins (see Discontinuity). `closed`:
      # refuse to decide rather than decide unrecorded.
      on_full: "open"

      # What is written. Denies and errors are never sampled, whatever this says.
      sample: { permits: "1.0" }

      # The secret input commitments are taken under. Required when the log is on, and a
      # different key from the pseudonymisation one: rotating one to crypto-shred pseudonyms
      # must not invalidate every commitment with it.
      commitment: { key_ref: decision-commitment, key_version: "v1" }

      # Caller-supplied attributes may carry personal data, so they are off by
      # default and named explicitly when wanted. Their keyed commitments are
      # always recorded — see Replay below.
      include:
        subject_properties: []      # e.g. ["department"] — an allow-list, never "all"
        resource_properties: []
        context: []                 # e.g. ["ip", "time"]
```

> Today the block above is called `dataPlane.authz`. It becomes
> `dataPlane.decisions` when the log lands, so the record and the bounds of the
> decision path live in one place.

### On the volume

Both halves live under `data/`, because `data/` is what a restore has to bring
back and `operations/` is how a server runs itself:

```text
<volume>/data/
  zones/<zone>/<ledger>/           the ledgers                     (control plane)
  mirrors/<zone>/<ledger>/         verified copies of them         (data plane)
  decisions/
    spool/                         written, not yet shipped        (data plane)
    store/                         the log, kept                   (control plane)
```

The spool belongs there and not in scratch space: until a record is
acknowledged, that is its **only** copy, so a plane whose spool sits on an
`emptyDir` loses decisions on its first restart.

## The record

One JSON object per record. Minimal on purpose: everything here is either
needed to answer *"why was this allowed"*, to prove the record is genuine, or
to prove what it was decided from.

```json
{
  "v": 1,
  "kind": "decision",
  "stream": { "id": "data-plane-7f3a", "instance": "01931f2c-…" },
  "seq": 4711,
  "prev": "sha256:7c19…",

  "id": "0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d",
  "at": "2026-08-24T10:00:00.123Z",
  "pdp": { "version": "0.1.0" },

  "store": {
    "zone": "acme",
    "ledger": "main-ledger",
    "commit": "sha256:ec1773bf…",
    "counter": 3,
    "profile": "default"
  },

  "subject":  { "type": "User", "id": "pseudo:v1:9f2c…" },
  "resource": { "type": "Document", "id": "budget-2026" },
  "action":   { "name": "read" },
  "principal": { "type": "Workload", "id": "pseudo:v1:41ab…" },

  "inputs": {
    "context": "hmac-sha256:v1:1f0a…",
    "entities": "hmac-sha256:v1:b74d…",
    "external": []
  },

  "decision": true,
  "policies": ["af4c4260-ba94-8f5f-8ae1-942ea8644f4e"],
  "reason":   { "code": "200" },

  "trace": { "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7" },
  "request_id": "lab-1",
  "latency_us": 143
}
```

| Field | Why it is there |
| --- | --- |
| `stream` + `seq` + `prev` | identity, order and integrity — the **producer** dimension |
| `store.zone` + `store.ledger` | ownership and access — the **tenancy** dimension, and what a scoped reader is bound to |
| `kind` | `decision`, `marker` (an epoch: identity, build, sampling) or `discontinuity` (the last record of a stream). A reader must switch on it |
| `id` | joins the record to the response the caller received (`context.id`) |
| `store.commit` + `counter` | **the forensic core**: the exact policy set that produced this answer |
| `inputs` commitments | keyed, not bare digests — see Replay |
| `policies` | which policies decided — identities that survive renames |
| `reason.code` | the class, not the sentence: prose changes, codes are an interface |
| `trace` | W3C Trace Context, when the caller sent one: the decision joins the request that caused it |
| `latency_us` | the number that tells a slow PDP from a slow policy set |

**One record per evaluation.** A boxcarred request carries several questions
about several subjects, resources and actions, and each is a decision: folding
them into one record would attribute all of them to the first and lose the rest
of the trail. The request's own verdict — the conjunction — is not recorded,
because it is not a decision: it is an answer *about* decisions, and a reader
computes it from them.

**What is deliberately absent:** policy text (it is in the ledger, addressed by
the commit), the entity graph itself, and any caller attribute not named in
`include`. A decision log is not a request archive.

### Trace correlation

`trace` carries `trace_id` and `span_id` exactly as
[W3C Trace Context](https://www.w3.org/TR/trace-context/) defines them, taken
from the `traceparent` of the incoming request. That is all: **the record is
not an OpenTelemetry event**, and does not become subordinate to a telemetry
model — it has cryptographic and stream properties that a span does not. But a
decision that cannot be joined to the request that caused it is half an
investigation, and the join is one standard field.

## Replay, and what it actually promises

`store.commit` identifies the policy set exactly, so *the policies* are always
recoverable. That is not the same as replaying the decision, because an answer
may also depend on inputs that are not in the ledger:

| Input | Where it comes from | How it is recorded |
| --- | --- | --- |
| The policies | the ledger, at `store.commit` | by reference — exact and immutable |
| `context` (time, ip, …) | the caller | **keyed commitment**, plus whatever `include` names |
| `entities` (the graph) | the caller | **keyed commitment** |
| Anything fetched at decision time (a PIP, a risk score) — *not implemented today* | outside | reference + keyed commitment in `inputs.external` |

So the honest claim is: **a decision is replayable when its recorded inputs are
supplied again.** The commitments are what make that verifiable — a caller
replaying with the same context and entities can prove they are the same ones,
and an auditor can prove two decisions saw the same input without either party
storing the input itself.

**They are keyed, and that is not a detail.** A bare `SHA-256` of a
low-entropy value is not confidential: `department=HR` has a few thousand
plausible preimages and a dictionary attack recovers it in milliseconds. The
same is true of booleans, roles, small enums and most identifiers. So an input
commitment is

```text
commitment(value) = HMAC-SHA256( commitment_key , "permguard.input.v1\n" || JCS(value) )
```

with the key held like the pseudonym key — resolved from the secret store at
startup, at least 32 bytes, its version declared in the stream's marker — and
**required when the log is on**: a plane that names no commitment key refuses to
start rather than commit under something a reader could guess. Equality within a deployment still works — which is
what the commitment is *for* — while a reader of the log cannot enumerate its
way to the value. The trade is stated: commitments are not comparable across
deployments, and rotating the key changes them, which is the same
crypto-shredding property the pseudonyms have.

**The commit must still exist to be replayed against, and that is a
cross-subsystem invariant.** A decision log retained for years references
commits that the control plane's garbage collector could otherwise reclaim: a
superseded commit is not named by any ref. It survives because reachability
follows `predecessors`, so every ancestor of a ledger's head stays reachable and
a sweep never reclaims it. That is true of the collector as implemented, and
this document depends on it: **any future optimisation that shortens
reachability — a shallow sweep, a horizon, a squashed history — silently
invalidates every decision record older than the horizon.** Whoever proposes one
has to answer this first.

`inputs.external` is empty today and exists because the moment a PDP consults
anything at decision time, a log without it stops being sufficient. Designing
the field now costs nothing; discovering it later costs a schema version. When
it is filled, the minimum each entry has to carry is fixed by what a
reconstruction needs and nothing more: **who** was asked (a source identity),
**when** the value was observed (its own timestamp, not the decision's), **what
came back** (a keyed commitment, or a reference if the source keeps its own
addressable history), and **how long it was considered valid** (the freshness
the PDP relied on). Anything less and a replay cannot tell a stale answer from a
current one; anything more and the decision log starts archiving somebody
else's data.

## Integrity — normative

Two chains, with different jobs. The **producer chain** proves a stream came
from a PDP and was not altered; the **store chain** proves the control plane's
copy was not edited afterwards. They are independent, and a reader can check
either alone.

### The record digest

```text
digest(record) = SHA-256( "permguard.decision.v1\n" || JCS(record) )
```

- **JCS** is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON,
  the same canonicalisation the JWS payload uses. A verifier re-serialising a
  parsed record computes the same bytes.
- The hashed input **includes `prev`** — that is what binds each record to its
  predecessor — and includes every other field of the record as it is shipped.
  Nothing is excluded, so there is no "which fields count" question to get
  wrong.
- The digest itself is **not** a field of the record: it is computed, never
  transmitted. A transmitted digest is a field somebody can make agree with a
  lie.
- The domain-separation prefix keeps these digests from being confusable with
  object digests or seal digests elsewhere in the product.

### The chain

- `prev` of the first record of a stream is the **genesis**:
  `sha256:0000…0000` (sixty-four zeroes) — the same genesis the audit trail
  uses, so one verifier shape serves both.
- `prev` of every later record is `digest(previous record of the same stream)`,
  where "previous" means `seq - 1`. The chain therefore spans **the whole
  stream**, not a batch and not a segment: batches and segments are transport
  and storage boundaries, and integrity must not depend on where they happen to
  fall.
- The producer persists the last digest beside the spool, so a restart
  continues the chain rather than starting a second one. If it is missing —
  a wiped volume — the producer must start a **new stream**, never a new
  genesis inside the old one.

### The signed head

Every batch carries an envelope signed by the data plane's ring (`keys/data`,
published at `/data-plane/keys`):

```json
{
  "stream": { "id": "data-plane-7f3a", "instance": "01931f2c-…" },
  "first_seq": 4700,
  "last_seq": 4799,
  "count": 100,
  "previous_head": "sha256:31c8…",
  "head": "sha256:9ab2…",
  "sampling": { "permits": "1.0" },
  "at": "2026-08-24T10:00:01Z"
}
```

`head` is `digest(record with seq = last_seq)`; `previous_head` is the head of
the previous batch of this stream, so a verifier can check **continuity between
batches**, not merely the integrity of the one in hand. `count` against
`last_seq - first_seq + 1` catches a batch that omits records inside its own
range.

The signature is **JWS** ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)),
JSON serialisation, `alg: EdDSA`, `kid` naming the key in the published JWKS,
over the JCS of that envelope together with the digest of the payload. Not a
JWT: this is not a bearer token and has no claims semantics.

**Not per record.** A signature per decision would cost an asymmetric operation
on a path measured in microseconds, for no additional guarantee: the chain
already binds every record to the signed head. This is the trade Certificate
Transparency makes with signed tree heads, Rekor with checkpoints, and
CloudTrail with hourly digest files — sign the head, chain the entries.

### On the control plane

Records are stored **verbatim**, so the producer chain stays verifiable end to
end by anyone, forever. On top of that the store keeps its own append-only
segments, each sealed on rotation with a signed statement
(`{segment, records, head, at}`) by the control plane's ring — the same seal the
audit trail already writes daily. Two chains, two questions: *did this come
from that PDP* and *has this store been edited since*.

## Sequence, sampling and loss — normative

`seq` counts **records written to the spool**, not decisions taken. This is the
resolution of an otherwise real conflict: a gap in `seq` must mean *something
was lost*, and a sampled-out permit was never a record, so it must not produce
one.

That makes sampling a property of the *stream*, and it is declared where a
reader will see it: `sampling` in every batch envelope, signed with it. A
consumer therefore knows exactly what the log claims to be complete about —
**denies and errors always, permits at the declared rate** — instead of
inferring it from gaps that do not exist.

### Discontinuity — when local loss ends a stream

An earlier draft of this document said that `on_full: open` could drop the
oldest records and declare the loss later with a `gap` record inside the same
stream. **That does not work, and the reason is arithmetic**, not taste.

The chain is `prev(N) = digest(N − 1)`. If records 1000–1523 were written and
chained but removed before they were ever shipped, record 1524 still carries
`prev = digest(1523)` — a digest of something the control plane will never
hold. Nothing later can repair that: a `gap` record at 5200 declares *that*
something was lost, but it cannot make the link at 1524 verifiable. The stream
would be permanently unverifiable from 1524 onward while claiming to be a
chain.

So an unrecoverable local loss **ends the stream**:

1. The producer writes a final `kind: "discontinuity"` record — the last record
   of the old stream, chained and shipped like any other, so it is covered by a
   signed head. In the example below `acked` was 999, which is why the terminal
   sits at `seq` 1000 and its `prev` is `digest(999)`:

```json
{
  "v": 1,
  "kind": "discontinuity",
  "stream": { "id": "data-plane-7f3a", "instance": "01931f2c-…" },
  "seq": 1000,
  "prev": "sha256:44be…",
  "at": "2026-08-24T11:00:00Z",
  "reason": "spool_full",
  "lost": { "from_seq": 1000, "count_estimate": 524 },
  "successor": "01931f7e-…"
}
```

2. It mints a **new incarnation** and starts a new stream at `seq` 1, whose
   first record is a `kind: "marker"` naming its predecessor.

Two properties come out of this that the gap model did not have. **Every stream
is internally complete**: verification never has to cross a hole, so "the chain
holds" means what it says. And **the discontinuity is evidence**: a stream that
ends without one, or a successor that names a predecessor which never ended, is
a detectable inconsistency rather than an absence somebody has to notice.

The producer can only write the discontinuity *before* discarding — it is the
first thing it does when it decides the spool cannot hold more — which is why
`lost` carries `from_seq` and an estimate rather than an exact range: at that
moment it knows where the hole starts, not where it will end.

**Where the terminal record sits — normative.** The discontinuity is not
written at the current head. It is written at **`acked + 1`**, and its `prev` is
`digest(acked)` — the last record the control plane confirmed durable.

This is forced, not chosen. Suppose the producer is at `seq` 5200 with `acked`
= 999, and writes the terminal at 5200 chained to `digest(5199)`. The control
plane holds 1–999 and then a record whose `prev` names something it will never
have: the terminal record itself is unverifiable, and the model is back to the
arithmetic the gap record failed on. Only a terminal at `acked + 1` lands on a
chain the receiver can close.

Two consequences follow, and both are requirements on the implementation:

- The producer persists **the digest at the acknowledgement point**, not only
  the digest of the last record it wrote. It needs `digest(acked)` to chain the
  terminal, and by definition it no longer holds the records after it.
- `seq` values above `acked` that were written and then discarded are **never
  observed by anyone** — the terminal takes `acked + 1`, and the successor
  starts a new stream. "Never reused inside a stream" holds where it is
  checkable: no two records the control plane can hold ever share a `(stream,
  seq)`.

`lost` then reads exactly: `from_seq` is `acked + 1` and `count_estimate` is
how many written records are being discarded.

**The successor is minted before the terminal is written — normative.** Its
instance id is a field of the discontinuity record, so a crash between the two
steps is recoverable and cannot mint two successors: a producer that restarts
and finds a terminal record as the last entry of its spool adopts the successor
named *in that record* rather than generating a fresh one. Restart recovery is
therefore idempotent at every boundary — before the terminal is durable
(nothing happened, retry), after it is durable (the successor is already
decided), after the successor's marker is durable (ordinary operation).

**The reserve — normative.** The producer cannot write its terminal record with
the last byte, and this is the ordering that must not be discovered at runtime:

```text
spool physically full  →  needs a discontinuity  →  cannot append it durably
                       →  cannot legally discard  →  cannot continue at all
```

So `spool.bytes` is a bound on **decision records only**. The spool reserves,
outside that bound and for the life of the spool, enough space for one terminal
`discontinuity` record and the successor's own metadata (its instance, its
first `seq`, its chain digest). The reserve is claimed when the spool is
created, not when it is needed — a reservation made under pressure is a
reservation that fails under pressure. A spool that cannot claim it refuses to
start, the same way a plane that cannot open its spool exclusively refuses to
start: a producer that cannot end its stream cleanly must not begin one.

The same reserve is what makes `age`-based expiry safe, since it discards for
the same reason and reaches the same wall.

**`on_full: closed` never produces one**, because it never discards: it refuses
to decide instead. That is the whole difference between the two modes, and it
is now visible in the log itself.

### Markers: identity, build and sampling epochs

Some facts are properties of a *range* of records, not of each one. Repeating
them per record would be waste; leaving them implicit would make completeness
claims ambiguous. They are chained records of their own:

```json
{
  "v": 1,
  "kind": "marker",
  "stream": { "id": "data-plane-7f3a", "instance": "01931f7e-…" },
  "seq": 1,
  "prev": "sha256:0000…0000",
  "at": "2026-08-24T11:00:01Z",
  "predecessor": { "instance": "01931f2c-…", "last_seq": 1000 },
  "pdp": {
    "version": "0.1.0",
    "build": "sha256:9c4e…",
    "engines": { "cedar": "4.12.0", "rego": "1.0.0" }
  },
  "sampling": { "permits": "1.0" },
  "commitments": { "alg": "HMAC-SHA256", "key_version": "v1" }
}
```

A marker is written at the start of every stream and **whenever any of these
changes** — a configuration reload that moves the sampling rate, a binary
upgrade that changes an engine version. So for any record, exactly one marker
governs it: the most recent one at or before its `seq`.

That is what makes a completeness claim unambiguous. "Permits sampled at 0.5"
is true of a *range*, and the range has a beginning and an end that are both in
the chain. A rate declared only in a batch envelope would leave the records
that straddle a configuration change describing themselves two ways.

The build and engine versions are here rather than in every record for the same
reason — and they answer the question `pdp.version` alone cannot: *which
evaluation semantics produced this answer*. A ledger's manifest constrains the
engine range; the marker records the build that was actually inside it.

## Tenancy: two dimensions that must not be confused

A record carries both, and they answer different questions:

```text
integrity and order   :  pdp.id + pdp.instance  →  seq  →  hash chain
ownership and access  :  zone  →  ledger  →  decisions
```

**Why they must stay separate.** One PDP serves many ledgers, often for many
zones. Making the producer stream `zone + ledger + seq` would mean one spool,
one sequence, one chain and one signing path *per ledger* on every plane —
N writers where the machine has one, for no integrity gain: the chain proves a
producer's history, and the producer is the plane, not the tenant.

**Why tenancy cannot be left implicit either.** The physical stream is global
to a PDP, so a reader placed on it sees every tenant. `zone → ledger` is
already this product's isolation boundary for policy; a decision log that did
not honour it would be the one place where a tenant's data leaks — and the
worst kind, because it leaks *who accessed what*.

### How the control plane reconciles them

On ingest, records are stored **verbatim** (the producer chain must stay
verifiable exactly as it was signed) and are **indexed into per-`(zone,
ledger)` views**. `store.zone` and `store.ledger` are inside the record, so
they are covered by its digest and by the batch signature: the demultiplexing
cannot be steered by anything a caller can change.

A view is a physical partition, not a filter. That matters:

| | Filtering a global stream | Per-tenant views |
| --- | --- | --- |
| A bug in the predicate | leaks another tenant's records | cannot: they are not in the partition |
| Offsets | global — a reader learns other tenants' rates and gaps | scoped, and meaningless elsewhere |
| Retention, export, lifecycle | one policy for everyone | per zone, which is how they are actually bought and audited |

### Stream-level records belong in every view

`marker` and `discontinuity` records carry no `store.zone` and no
`store.ledger` — they are properties of the producer, not of a tenant. A view
partitioned strictly on those fields would therefore contain none of them, and
that breaks two claims this document makes elsewhere:

```text
a scoped reader would not see  →  the sampling rate governing its records
                               →  the build and engines that decided them
                               →  that its stream ended and where it continues
```

A tenant would hold records whose completeness claim is stated in a record it
cannot read. So: **stream-level records are copied verbatim into every view of
that stream.** They contain nothing belonging to any tenant by construction, so
replicating them discloses nothing, and it is what makes a scoped view a
self-describing stream rather than a bag of rows. A reader resolves the marker
governing a record exactly as a global reader does — the most recent one at or
before its `seq`.

### The reading API, scoped

```text
GET  /zones/{zone}/ledgers/{ledger}/decisions/v1/records?from=<offset>&limit=<n>
GET  /zones/{zone}/ledgers/{ledger}/decisions/v1/stream?from=<offset>
gRPC permguard.control.v1.DecisionLog/Read   { zone, ledger, from }
```

The offset stays opaque and consumer-owned — the property worth keeping — but
it is **bound to the scope that issued it**, and an offset presented under a
different `(zone, ledger)` is refused rather than reinterpreted. A stateless
server and a tenant boundary are not in tension: the boundary is in the
address, the position is in the consumer.

A deployment-wide scope stays available for an operator who is authorized for
it (`/decisions/v1/records`), because somebody has to be able to verify a whole
PDP stream. That is the one place where the two dimensions meet, and it is an
explicitly privileged one.

### Verification inside a scope

A tenant-scoped reader sees a subsequence of a producer's stream, so the chain
alone does not verify for them: the records between theirs are another tenant's
and they must not have them. So each batch envelope carries, beside its head, a
**Merkle root over the digests of the records it contains**, and a scoped
reader can be given the inclusion path for each of its records.

**What the proof discloses, stated.** An inclusion path's depth reveals how
many records the batch held, and the envelope it is checked against carries
`first_seq`, `last_seq` and `count` in the clear — it must, because those fields
are signed and redacting them would destroy the signature. So a scoped reader
learns the producer's **decision volume** in the windows containing its own
records. It learns nothing about the content, the tenants or the outcomes; it
does learn rate. That is an accepted disclosure of the design, not an
oversight: a deployment where inter-tenant volume is itself sensitive should
give those tenants separate producers, which is the only thing that actually
removes the channel.

**This is not optional in practice, and finding out why is worth writing down.**
A tenant page is a subsequence, so running a chain check across it reports a
failure of *arithmetic* as a failure of *integrity*: the records in between are
another tenant's, and their absence is the design working. A verifier that did
that would cry wolf on every healthy multi-tenant page. So the proof a reader
runs is chosen by the scope, not by preference — chain for a producer stream,
inclusion for a tenant view — and `permguard decisions --verify` reports which
of the two it ran.

The tree is rebuilt from the **producer stream** to compute a path, never from
the tenant's page: the other leaves are exactly the records the tenant must not
see, and a path computed without them would reach a different root.

That gives a tenant the guarantee that actually matters to them — *this record
was in a batch signed by that PDP, and has not been altered* — without handing
them anything belonging to anybody else. The chain remains what it always was:
the proof of the producer's whole history, checkable by whoever is authorized
for the whole stream. Two proofs, two audiences; neither weakens the other.

## Ingestion API

Both transports, the same contract, as everywhere else in this product.

```text
POST /decisions/v1/batches          gRPC  permguard.control.v1.DecisionLog/Ship
```

Both are served, and both carry the record as **its JSON bytes**. That is the
one design decision in the gRPC contract worth defending: a record's digest is
taken over its canonical JSON, and the chain is taken over those digests, so
re-encoding a record as protobuf and back would change the bytes and break
every digest after it. The wire carries what was signed, and the contract
carries the wire — which is what lets the two transports deliver the *same*
record rather than two renderings of one.

The body is the signed batch. The server verifies the signature against the
published key set, verifies the chain inside the batch, and appends.

**The acknowledgement is the highest *contiguous durable* sequence** for that
stream — not the highest accepted. That single choice is what makes recovery
unambiguous: the shipper truncates its spool by it, and truncating by a number
that had a hole behind it is exactly how a gap becomes permanent.

**"Durable" is defined, not implied.** A sequence may be acknowledged only once
its records and the index entries that make them findable are written **and
flushed** to the segment store, such that a process restart or a host restart
finds them. Not "accepted", not "queued", not "in the page cache with a write
scheduled": the producer is about to delete its only other copy on the strength
of this number.

**Continuity is checked, not assumed.** The chain spans a whole stream, so the
one link a per-batch check cannot see is the one that crosses the boundary — and
that is exactly where a producer's history could be replaced by a different,
internally perfect one. The sequence numbers would run on and the digests would
not. So a batch that advances the stream must satisfy both: its envelope's
`previous_head` is the head this store recorded, and its first record's `prev` is
that same digest. Both are covered by the signature, so a producer cannot attest
one history and ship another.

A batch that *overlaps* what is held — a replay after a lost acknowledgement —
is checked record by record against what is stored instead: its own `prev`
belongs to a position this store has moved past.

| The batch begins at | The server holds through | Answer |
| --- | --- | --- |
| `≤ acked` entirely | | `ok`, `acked` unchanged — a replay, deduplicated by `(stream_id, seq)` |
| `acked + 1` | | `ok`, `acked` moves to the batch's `last_seq` |
| `> acked + 1` | | **`out_of_order`**, with `expected_seq = acked + 1`; nothing is stored, and the shipper resends from there. Deliberately not called `gap`: nothing has been lost, the shipper simply ran ahead |
| a `seq` already stored, with a **different digest** | | **integrity error** — the stream is **closed permanently**, and an alarm is raised. This is not a retry |

Refusals otherwise follow the server's taxonomy: `401` unauthenticated (the
client certificate today, tokens later), `422` a signature that does not verify
or a chain that does not hold, `503` the store cannot accept right now — which
the shipper treats as *retry*, never as *drop*.

**A cryptographic conflict closes a stream for good.** Two different records
claiming one `(stream, seq)` means either a bug or an attack, and in both cases
the stream's history can no longer be reasoned about as a single sequence.
Nothing is repaired, nothing is overwritten, and there is no "unquarantine":
what is already stored stays exactly as it is, as evidence, and the producer
must open a **new incarnation** to keep logging. Repairing history would be
indistinguishable, to a later auditor, from an attacker doing the same.

**And it is the one legitimate stream that ends without a terminal record.**
The producer cannot ship a discontinuity into a stream the server has closed,
so the rule that "a successor naming a predecessor which never ended is a
detectable inconsistency" would fire on a case that is not an inconsistency at
all. The successor's marker therefore carries the reason it exists — `closed_by_server` beside the ordinary `spool_full` — and a verifier treats a predecessor
with no terminal record as **explained** exactly when the successor says so and
the server's own closure record agrees. Two independent statements about the
same event, which is what makes the exception safe to have.

### Whose key verifies a batch

A batch is signed by the **data plane that decided**, never by the control
plane that receives it, so a control plane cannot verify one against its own
ring. It needs each producer's published key set — and it does **not** dial
back to fetch it: a control plane that reached out to every PDP would make
ingestion depend on the reachability of the very planes shipping to it, which
is the coupling this whole design exists to avoid.

So the sets are named in the file, and read once at startup:

```yaml
controlPlane:
  decisions:
    enabled: "true"
    producer_keys:
      - keys/data-plane-eu-1.jwks     # each producer's published set, as a file
```

A plane that hosts both roles — the all-in-one — needs none of this: the
producer's ring is in the same process, and is used directly. A control plane
that knows no producer's keys **serves no decision routes at all** rather than
accepting what nobody checked, and says so at startup.

The rotation question is answered twice over. A producer's published set
contains its published, active and retired keys at once, so a batch signed just
before a rotation still verifies against a set captured just after it. And when
a key really is new to this plane — the file was updated after startup — the
sets are **re-read from disk on the one refusal that warrants it**: a batch that
cannot be attributed. Rotating is therefore updating a file, not restarting a
plane, and a deployment whose producers are stable never reads those files
again after startup.

A forged batch cannot turn that into a denial of service: an unattributable
batch is refused either way, and the re-read is a handful of small local files.
What is still not solved is *distribution* — getting the new key into the file
in the first place — which is a deployment's own business until the APIs grow
authentication of their own.

### Keys, and evidence that outlives them

A batch signed in 2026 must still verify in 2031, after the key that signed it
has been rotated a dozen times and possibly revoked. So the control plane
**archives the verification keys** — every JWKS it accepted, by `kid`, with the
window each key was seen in — beside the segments they attest to.

Rotation and revocation are then two different things, and the distinction is
the whole point: rotation retires a key for **new** signatures and changes
nothing about old evidence; **revocation** is a statement that a key was
compromised, and it is recorded with a *time* — everything that key signed
after that time becomes suspect, everything before it stays exactly as
trustworthy as it was. Deleting a public key because it is no longer in use
would destroy the ability to verify the past, which is the one thing an audit
store exists for.

## Reading: offsets, not subscriptions

```text
GET  /decisions/v1/records?from=<offset>&limit=<n>     one page, and the next offset
GET  /decisions/v1/stream?from=<offset>                the same, held open
gRPC permguard.control.v1.DecisionLog/Read             server-streaming, same semantics
```

The **offset is opaque and belongs to the consumer** — `(segment, position)`,
Kafka-like in behaviour without Kafka in the deployment. The control plane
keeps no per-consumer state, so any number of independent readers coexist: a
SIEM streaming in near-real-time, a nightly batch into a data lake, an
application answering "why was I denied", each with its own position and none
able to affect the others.

For volumes where an API is the wrong transport, sealed segments roll to object
storage and consumers read the files directly, with the API serving only the
index. Nobody should stream terabytes through request/response.

**Retention is the bound on how far behind a reader may fall**, and falling off
it is answered explicitly rather than silently: an offset older than what the
scope still holds is refused with `offset_expired`, carrying the **oldest
offset now available** and where the archive for the older range lives. A
consumer that returns from a long outage therefore learns three things at once —
that it lost records, exactly which range, and where to go for it — instead of
resuming from the wrong place and reporting a clean run.

## On the command line

```sh
permguard decisions tail --follow                    # the stream, as it happens
permguard decisions list --since 2026-08-24T00:00:00Z --zone acme
permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d             # one decision, and its commit
permguard decisions export --from <offset> -o json   # bulk, resumable
```

`terminal`, `json` and `yaml`, like every other command; the terminal rendering
speaks the same dialect (`+` permit, `-` deny, identifiers in their own colour,
one bold summary line). `--verify` re-computes the chain and checks the batch
signatures and seals against the published key set — so an operator can confirm
a log is intact **without trusting the server that served it**, which is the
only kind of confirmation worth having.

## Privacy

**Pseudonymisation at the source.** Subject and principal identifiers pass
through the pseudonymizer this server already has — HMAC with a named key and
version (`operations.audit.pseudonym`) — *before* the record leaves the data
plane. The control plane never holds raw identifiers, and neither does any
consumer.

**Re-identification is a controlled path.** Whoever holds the pseudonym key can
map a token back; nobody else can. The key lives in the secret store, and its
use is auditable.

**Data minimisation is the default.** Caller-supplied `properties` and
`context` may contain anything — an address, a device id, a whole profile — so
they are **not logged unless named** in `include`. An allow-list, never a
deny-list: a field added to a request tomorrow must not start being recorded by
itself. What is always kept is their **keyed commitment** (see Replay): it
proves what the decision saw and lets two decisions be compared, and — because
it is an HMAC under a held key rather than a bare digest — a reader of the log
cannot enumerate a low-entropy value back out of it. That is a much stronger
statement than the bare digest an earlier draft kept here, and it is still not
"discloses nothing": whoever holds the commitment key can confirm a guess, and
the *presence* of a commitment for a named field discloses that the field was
part of the decision.

**Erasure, stated precisely.** An append-only log cannot honour a deletion
request by deleting a line: that would break every chain and every seal, and
the value of the log is precisely that it cannot be edited. Rotating the
pseudonym key destroys the ability to resolve those tokens **through that
key** — which is the accepted mechanism for immutable audit stores, and the
reason pseudonymisation must happen at the source.

It is **not**, by itself, anonymisation. A record still carries a resource, an
action, a timestamp and whatever `include` named, and those can re-identify a
person by correlation. What actually bounds the residual risk is the
combination of: minimisation (the allow-list above), **retention** — records
leave on a schedule — and, where the risk is material, coarsening what is kept
(an hour rather than a millisecond, a subnet rather than an address). A
deployment subject to a data-protection assessment should treat the residual
risk of correlation as a question its own assessment answers, not as one this
design has closed.

**Retention per zone**, enforced by the segment lifecycle, with the object-store
tier carrying its own (longer) policy where an audit obligation demands it.

## Failure modes, and what happens

| | What happens |
| --- | --- |
| Control plane unreachable | the shipper backs off and retries; the spool absorbs; decisions are unaffected |
| Spool full, `on_full: open` | the stream **ends** with a signed `discontinuity` at `acked + 1`, a new incarnation begins, records are counted (`permguard_decisions_dropped_total`), alarm |
| Spool full, `on_full: closed` | the PDP refuses to decide (`503`) — chosen deliberately, never a surprise |
| Journal write error (disk fault, not a full spool), `on_full: closed` | the same refusal (`503 decision_unrecordable`): "refuse rather than decide unrecorded" is about being unrecorded, whatever made it so |
| Journal write error, `on_full: open` | the incident is reported (`authz.journal_failed`) and the plane keeps answering; nothing was appended, so the chain has no hole and the next decision retries the same sequence |
| Batch rejected (bad signature or broken chain) | the shipper stops and alarms: this is not a retry, it is an incident |
| Duplicate batch after a timeout | deduplicated by `(stream_id, seq)`; the acknowledgement does not move |
| Batch beyond the acknowledged sequence | refused `out_of_order` with `expected_seq`; the shipper resends from there — a gap is never skipped past |
| Same `seq`, different digest | the stream is **closed permanently**; what is stored stays as evidence and the producer opens a new incarnation |
| PDP restarts | the spool holds the instance, the last `seq`, the last digest and `digest(acked)`: the same stream continues |
| Crash between the terminal record and the successor | the successor's instance is named *inside* the terminal record: recovery adopts it, and cannot mint a second one |
| PDP volume lost | a new instance, therefore a new stream from `seq` 1 — no ambiguity, and the discontinuity is visible |
| Clock skew | `at` is informational; ordering is by `seq` within a stream and by arrival across streams |
| A consumer falls behind retention | `offset_expired`, naming the oldest offset available and where the archive is |
| A signing key is rotated | old batches keep verifying: the verification keys are archived by `kid` beside what they attest |
| A signing key is **revoked** as compromised | the revocation carries a time: signatures after it are suspect, signatures before it are not |

## What I would not build

**Not a queue inside the control plane.** No per-consumer cursors on the
server, no fan-out to N sinks. Readers keep their own offsets; exporters
(OTLP, object storage, Kafka, a webhook) are *readers*, configured, never a
branch in the write path.

**Not a mandatory broker.** Kafka is excellent and it is somebody's operational
burden; a deployment that has one attaches it as a reader.

**Not NOTP.** That protocol moves immutable content-addressed objects between
stores. A decision log is an ordered stream. Reusing it would bend both.

**Not an OpenTelemetry envelope.** The record borrows trace correlation and
nothing else: a log with cryptographic and stream semantics should not become a
subordinate of a telemetry model whose guarantees are weaker.

**Not synchronous remote logging on the decision path**, in any mode. Even
`on_full: closed` waits for local durability only, never for the network or the
control plane.

**Not one `fsync` per decision.** Durability is settled by **group commit**:
appends land immediately, one flush covers every record appended before it,
and each request still waits for the flush that covers its own — the same
durable-before-the-answer contract, paid once per group instead of once per
record. A flush that fails is an error handed to every request it stranded,
before any of their answers leave. This is the trade every write-ahead log
makes, and it is why the guarantee and a PDP's latency can coexist.

**Not duplicated into the operational audit trail.** When the decision log is
on, it *is* the decision trail — every decision, chained, signed, shipped. An
`authz.decision` event beside it would restate the same fact with weaker
guarantees and contend for the same disk, so the operational trail keeps what
only it records: lifecycle and administration. A plane with the log **off**
still audits decisions through the bounded audit worker.

## Open questions

1. **Sampling of permits at high volume.** Head-based per-request sampling is
   simple and loses the ability to say "this specific request was allowed";
   tail-based is more useful and much more machinery. Start head-based,
   defaulting to `1.0`, with the rate declared in every batch envelope so the
   log always says what it claims to be complete about.
2. **Multi-destination shipping.** Deliberately excluded: it needs
   per-destination acknowledgement inside the spool, and a slow destination
   would hold everyone's disk. If it is ever needed, the config shape (`server`
   → `servers`) grows into it.
3. **Where the object-store tier is written from** — the control plane rolling
   its own segments, or a reader doing it like any other consumer. The second
   is more honest to the design; the first is one less thing to deploy.
4. **What `pdp.id` is by default.** A configured name is clearest; falling back
   to the hostname is convenient and wrong the first time somebody runs two
   replicas on one host. Leaning towards: required when the log is enabled.
5. ~~Whether a scoped reader should get inclusion paths by default.~~
   **Settled: on request.** `?proof=true` (or `proof` on the gRPC request)
   returns the signed envelopes and one inclusion path per record; without it
   a page is just records. `permguard decisions --verify` asks for them, which
   is the case that needs them. Always sending them would cost bytes on every
   page for a guarantee most consumers never check.
6. **How the deployment-wide scope is authorized** once tokens exist. Reading
   every tenant's decisions is the most powerful read in the system, and it
   should not be reachable by the same grant that reads one zone.
