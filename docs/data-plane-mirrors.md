<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Keeping a data plane current

How a plane that answers decisions gets the policies it answers from.
Status: **implemented** — `permguard-control-client` (the client),
`permguard-data-plane`'s `sync` module (the loop). Companion of the
[git-like storage specification](gitlike-object-model.md).

## The shape

```text
config: servers (exact URLs) → zones (patterns) → ledgers (patterns)
              │
              ▼  every `interval`
        list zones → keep matches → list ledgers → keep matches
              │
              ▼  up to `parallelism` at once, `timeout` each
   <volume>/data/mirrors/<zone-id>/<ledger-id>/{FORMAT, objects/, refs/main}
              │
              ▼
        remove mirrors no answering server wants any more
```

Identities name the directories, not names: a zone renamed on the server
keeps its mirror, and two zones cannot collide because somebody reused a
name. The layout is the control plane's own, so an operator who has seen one
volume has seen both — and it sits **beside** the control plane's, under
`data/`, for the same reason:

```text
<volume>/data/zones/<zone-id>/<ledger-id>/     the ledger, where it is authored
<volume>/data/mirrors/<zone-id>/<ledger-id>/   the verified copy, where it is served
```

`data/` is what a restore has to bring back; `operations/` is how the server
runs itself. An all-in-one holds both of those directories at once, and the
symmetry is the point.

## The consistency model, stated

**Policy replication is asynchronous and eventually consistent, deliberately.**
A data plane serves the last policy state it verified, and goes on serving it
while the control plane is unreachable. That is an availability decision *and*
a security decision, so it is written down rather than left to be discovered:

> A data plane may serve a previously verified policy state while disconnected
> from the control plane, for as long as it is disconnected.

Three properties are involved, and they are not the same thing:

| Property | What answers it | Where it stands |
| --- | --- | --- |
| **Authenticity** — was this signed by the authority I expect? | the signed head statement against the published ring | enforced before a checkpoint moves |
| **Consistency** — does it belong to the history I already know? | the `(counter, digest)` table: no rollback, no equivocation | enforced before a checkpoint moves |
| **Freshness** — how long may I keep trusting this version? | `mirrors.stale_after` and `mirrors.expire_after`, against the `SYNCED` marker | bounded when the deployment sets a bound; unbounded by default |

The third is the one to be honest about: `(counter, digest)` stops
`counter 42 → 41`. It does not stop `counter 42, forever`. A control plane that
is offline — or an attacker who can keep it unreachable — leaves this plane
serving an authentic, unrolled-back, **stale** policy set. For a revocation
that matters, indefinitely is the wrong number — and the right number is a
risk decision nobody can make centrally, so it is a per-deployment bound with
three states:

| State | When | What happens |
| --- | --- | --- |
| `fresh` | age below `stale_after` (or no bound set) | served |
| `stale` | age at or past `stale_after` | **served, and alarmed**: `sync.mirror_stale` per round, and `permguard_sync_mirror_age_seconds` carries the real age |
| `expired` | age at or past `expire_after` | **refused**: `503 ledger_expired`, because deciding on a state that may have revoked somebody since is the one thing this bound exists to prevent |

Age is time since the last **verified confirmation**, not since the last
change: every synchronization round that ends in a verified answer — advanced,
unchanged, or legitimately empty — touches a `SYNCED` marker in the mirror,
and a failed round does not. A ledger that never changes is perfectly fresh as
long as somebody keeps asking. A mirror with no marker — a volume fed by other
means, where no synchronization loop runs — is not bounded here: its freshness
belongs to whoever feeds it. The default for both bounds is "no bound", which
stays right for many deployments; what no longer exists is *no way to set one*.

## The configuration

Declared **inside `dataPlane`**, because mirroring is the data plane's own
business: it is the plane that answers decisions that needs the policies, and a
control plane has nothing to mirror. A process hosting both planes — the
all-in-one — states it in the same place, under its own `dataPlane` section, and
a `sync` block at the top level is refused at startup naming where it moved.

```yaml
dataPlane:
  public:
    http: { enabled: true, addr: 0.0.0.0:7656 }
  mirrors:
    enabled: "true"
    interval: "30s"        # how often a round STARTS
    timeout: "2m"          # per ledger
    parallelism: "4"       # ledgers mirrored at once
    jitter: "0.1"          # spread, so replicas do not wake together
    servers:
      - url: "http://control-plane:7556"  # the URL alone: everything it lists
      - url: "https://control.acme.com"   # exact: this is who you trust
        zones: ["acme-.*"]                # absent means every zone listed
        ledgers: ["main-ledger"]          # absent means every ledger of a match
        tls:
          ca_file: tls/control-plane-ca.pem  # absent: the platform trust store
      - url: "grpcs://control.internal:7557"
        zones: ["eu", "us"]               # several patterns are alternatives
        tls:
          ca_file: tls/control-plane-ca.pem
          cert: tls/control-plane-client.pem  # mutual TLS, where the server asks
          key: tls/control-plane-client.key
          server_name: control-plane          # when the address is not the name
```

Every shipped configuration carries this block, filled in for its own
environment — the local pair, the compose network, the lab, and the TLS and
mutual-TLS variants of each — and a test loads all of them the way the binaries
do, so a configuration that stops being true stops being green.

| Rule | Why |
| --- | --- |
| The **server URL is exact** | It is an identity: whose certificate you check, whose ring signs what you accept. A pattern there would mean trusting something you cannot name in advance |
| **Zones and ledgers are patterns** | They come and go while the deployment runs; a plane that needed a config change per ledger would always be behind |
| Patterns are **anchored** | `main` follows the ledger `main`, never `main-staging` — a configuration an operator cannot predict eventually follows something nobody asked for |
| A broken pattern **fails at startup** | Loudly, while somebody is watching, instead of becoming a mirror that follows nothing |
| Naming **neither** zones nor ledgers means everything | The URL alone reads as "mirror this server": the common case needs no patterns, and there is no `*` to spell |
| Trust material is **per server** | Two control planes in one file may sit behind two different authorities. There is no "skip verification": a plane that accepts any certificate takes its policies from whoever answers the port, and nobody is watching this one |
| `jitter` is **± half of it** | each round waits `interval ± (interval × jitter)/2`, drawn again every round — `0.1` is ±5%. Per round rather than per process, so a fleet that aligns on its first tick does not stay aligned |
| The scalars ride the layered pipeline | Flag → environment → file → default, like every other setting; the **server list comes from the file only**, because an array of servers has no sensible single-variable form |

## What the loop guarantees, and what it does not

- **Rounds never overlap.** A tick that finds the previous round still working
  is *skipped* and counted (`outcome="skipped"`), never queued: a slow control
  plane produces a slower cadence, not a growing backlog.
- **The timeout is per ledger.** One unreachable ledger must not consume the
  budget of every other. Honestly: a blocking thread cannot be killed in Rust,
  so what the deadline guarantees is that the *round* abandons that mirror and
  moves on; the work itself ends when its socket times out. Objects already
  fetched stay — they are immutable and the next round reuses them.
- **An unreachable server never causes a deletion, and neither does a partial
  one.** Absence is evidence of deletion only when the observation was
  complete, and only for the server that was asked. So: a server whose listing
  fails at any point contributes **nothing** (the whole discovery for it fails,
  never half of it); and reaping considers only mirrors **attributable to a
  server that answered this round** — the `LEDGER` file beside each mirror
  records which server put it there. A mirror whose server is silent stays; a
  mirror that names no server is left in place and reported, because a plane
  that cannot attribute a directory cannot know whether anybody still wants
  it.
- **Removal is guarded three ways.** The path must resolve inside the mirrors
  root, be a directory and not a link, and either look like a mirror (it
  carries `FORMAT` or `objects`) or hold no files at all. Anything else is
  left in place and reported.
- **A ledger with no history is not a failure.** It is a ledger nobody has
  applied to; the mirror waits, and fills on the round after the first commit.
- **Nothing is accepted that cannot be proven.** Every mirror advances through
  the same verification the CLI uses: the signed head statement against the
  published ring, the `(counter, digest)` table that refuses a rollback or an
  equivocation, and the whole closure present before the checkpoint moves. A
  compromised server can make this plane **stale**; it cannot make it serve
  policy nobody signed.

Authentication and authorization are deliberately **not** part of this yet:
today a plane presents TLS material (mutual TLS where a deployment asks for it,
declared per server under `mirrors.servers[].tls`), and when tokens arrive they
arrive for every consumer at once.

## After a mirror advances: ready, or blocked

A synchronization does not stop at the bytes. The moment a mirror advances, the
same round reads the ledger for **serving**: the load gate (language and engine
ranges), then the compile of every partition it declares, into the memory the
decision path answers from.

| Outcome | Meaning |
| --- | --- |
| `ready` | compiled and held — the **first** request after a sync is as fast as the thousandth |
| `empty` | a ledger nobody has applied to yet |
| `blocked` | this engine may not serve it; the refusal is written to `<mirror>/BLOCKED` and the ledger answers `503` until it changes |
| `damaged` | the mirror is present and unreadable — a missing or corrupt object; the ledger answers `503` until the mirror is repaired or moves on |

**A request sees one commit, never a mixture.** The head is resolved once per
request, and every partition of the profile is then taken at *that* commit —
the commit is part of the cache key, so a synchronization landing mid-request
cannot produce `app` at commit 43 beside `gateway` at 42. Requests already in
flight finish against the state they started with; the next one sees the new
state. The swap is atomic because there is nothing to swap: a new commit is a
new key.

**There is no last-known-good fallback, for either refusal.** The commit a
request is answered at is the one the ledger's checkpoint names *now*, resolved
from disk per request. So once the checkpoint moves to a commit this engine
cannot serve, that ledger answers `503` — it does **not** fall back to the
previous commit, even though that commit may still be compiled in memory:

```text
commit 42  ready, serving        commit 42  ready, serving
commit 43  verified → blocked    commit 43  damaged
  ⇒ 503 ledger_incompatible        ⇒ 503, the refusal names the object
```

`blocked` and `damaged` differ in *why* and in how they clear, not in what a
caller gets. This is a security decision before it is an availability one: a
newer commit exists because somebody applied it, and it may be the revocation
that matters. Continuing to answer from a state the operator has already
superseded would make this plane authoritative for a policy set nobody
currently intends — quietly, and exactly when it matters most. A plane that
cannot serve the current state must say so rather than answer from the old one.

Note that this is a different question from the one in
[What is not there yet](#what-is-not-there-yet): that gap is about a checkpoint
that **cannot advance** (an unreachable control plane), where this plane keeps
serving a state it verified. Here the checkpoint *has* advanced, and the
superseded state is deliberately no longer served.

**The `BLOCKED` marker is bound to a commit**, not to a ledger: it records the
commit it refused, and a marker naming any other commit is ignored. A copied
volume, a crash between write and rename, or a manual restore therefore cannot
leave a ledger refused for a version it no longer holds.

**`BLOCKED` is a cache, never a safety mechanism.** Nothing this plane refuses
depends on the file being present or being right: the load gate and the compile
run against the head on every request, and reach the same refusal on their own.
The marker only lets them skip the expensive way of finding out. That is why a
race between the synchronization loop writing it and a request clearing a stale
one costs a round of rediscovery and nothing else — and it is the property to
preserve if the marker is ever made to carry more: the moment a plane *serves*
because a file says it may, deleting a file becomes a way to change a decision.

A blocked ledger costs one small file read per round instead of a full
read-and-compile that would reach the same refusal, and it retries by itself
the moment a new commit arrives. See
[Answering decisions](authorization-check.md) for the mechanism and
`permguard_sync_warmed_total` for the metric.

## What it reports

Every round goes on the audit trail — including the quiet ones, because
"nothing changed at 03:00" is exactly what an auditor needs in order to say
the plane was current then.

| Metric | Answers |
| --- | --- |
| `permguard_sync_rounds_total{outcome}` | rounds `ok`, `partial`, `skipped` |
| `permguard_sync_round_seconds` | whether a round still fits inside its interval |
| `permguard_sync_mirrors_total{zone,ledger,outcome}` | per mirror: `ok`, `unchanged`, `empty`, `failed`, `timeout` |
| `permguard_sync_mirror_seconds` | the slow ledger, before its timeout starts firing |
| `permguard_sync_mirror_counter` | where each mirror stands — a gauge that stops while the server's climbs is the whole story |
| `permguard_sync_mirror_age_seconds` | freshness, as a number a page can be written against |
| `permguard_sync_mirrors` / `_zones` | how much this plane holds |
| `permguard_sync_zone_ledgers` / `_zone_bytes` | which zone carries the most, and occupies the most |
| `permguard_sync_fetched_objects_total` | the shape of policy actually changing |
| `permguard_sync_reaped_total{reason}` | mirrors removed |
| `permguard_sync_rounds_total{outcome="partial"}` | includes a round that found a ledger two servers claim |
| `permguard_sync_warmed_total{zone,ledger,outcome}` | whether a freshly mirrored ledger is `ready`, `empty`, `blocked` or `damaged` |

The lab ships the dashboard that reads them: **Permguard · Data plane**
(mirrors, freshness, round duration, ledgers and disk per zone, the mirror
table), beside **Permguard · Control plane** (the catalog, and every NOTP
transfer through it).

## What is not there yet

One gap remains of the four this document named, and three are closed. A
distribution protocol is judged by what it does when things go wrong, so both
halves stay written down: what is fixed, and what still is not.

**1. Maximum staleness — closed.** `mirrors.stale_after` and
`mirrors.expire_after` are the per-deployment bound the consistency-model
section describes: `fresh` serves, `stale` serves and alarms, `expired`
refuses with `503`. The scenario it exists for:

```text
10:00  the policy permits Alice to transfer
10:01  Alice is compromised; the policy is revoked on the control plane
10:02  the network towards the control plane is cut
18:00  with no bound set, this plane still permits her — with a correctly
       signed, correctly ordered, eight-hour-old policy set
       with expire_after: 1h, it has refused to answer from that mirror since 11:02
```

**2. The PDP does not verify the head in sidecar mode.** See the section below:
the trust anchor has to live outside the volume for that shape to be as strong
as the mirroring one.

**3. Two control planes offering the same ledger — no longer silent.** A mirror
is addressed by `(zone-id, ledger-id)` with no trust domain in the path, so two
servers listing the same identities are indistinguishable once the bytes are on
disk. Taking the first would mean this plane decided *whose policies it
answers from* by configuration order, which is not a decision but an accident.
So a ledger claimed by more than one **answering** server is now left exactly
as it is and reported (`sync.ledger_contested`, `outcome.contested`, and the
round is `partial`), and the same server named twice is refused at startup.

What is still open is the good case: two servers that are genuinely
*interchangeable mirrors* of one immutable history. The right answer is to
verify the equivalence — same head, same ring — and follow either; today they
are refused along with the real conflicts, which is safe and coarse.

**4. Abandoned work now keeps its slot.** The per-ledger deadline abandons a
mirror *logically* and a blocking task cannot be killed, so the permit is held
by the work rather than by the wait: a semaphore sized to `parallelism`, taken
inside the blocking task and released when it physically ends. One pool for the
life of the plane rather than one per round, because work abandoned by one
round is still outstanding during the next. A pathological endpoint therefore
slows the cadence instead of accumulating threads.

**And one small thing worth adding:** a `/status` on the plane that answers
*"which exact policy state am I deciding with right now"* — zone, ledger,
commit, counter, when it was mirrored, when it was compiled, its age, and which
server it came from. The metrics carry the numbers, but an incident asks the
question about one ledger, and it should be one call. It also closes the
forensic loop with the decision log, which records `store.commit` per decision:
the log says what a decision was made against, and this says what the plane is
deciding against now.

## The forensic join, and what it rests on

A decision record names `store.commit`; this plane serves at a commit; the two
meet on an immutable content-addressed identifier and nowhere else. That is the
right coupling — neither subsystem has to know the other exists, and the join
survives renames, replicas and rebuilds, because a digest is not a coordinate
into anything mutable.

It rests on one invariant that lives in a third place, and is worth naming here
because nothing in either subsystem states it: **the commit has to still be
there.** A commit superseded years ago is named by no ref, and the control
plane's collector reclaims what no ref reaches. It survives only because
reachability follows a commit's `predecessors`, so every ancestor of a ledger's
head stays reachable and is never swept. Verified against the collector as
implemented — and it is the reason a shallow or horizoned sweep would be a
breaking change for forensics rather than a storage optimisation.

## The other shape: a sidecar

A plane that mirrors itself needs egress and trust material. A deployment that
wants neither runs `permguard pull` beside it — an init container plus a
sidecar — and leaves `mirrors.enabled` off: the PDP then serves whatever the
volume holds, with no credentials of its own. Both shapes use the same client
and produce the same volume.

**The choice moves the trust boundary, and that has to be said plainly.** When
this plane mirrors for itself, it verifies the signed head against the
published ring before a checkpoint moves — so the volume is *derived* from
something it checked. In sidecar mode that verification happened in the
sidecar, and this plane trusts the volume: it re-verifies every object's digest
as it reads, which catches corruption and a swapped object, but **not** a whole
consistent history written by anyone with write access to the volume.

So the sidecar shape is only as strong as the volume's access control, and a
deployment choosing it should treat the volume as part of the plane rather than
as shared scratch space. Closing that gap properly means the PDP verifying the
signed head itself against a trust anchor configured **outside** the mutable
volume — which is worth doing, and is not done today.
