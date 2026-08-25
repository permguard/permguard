<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Git-like storage specification

Everything below is normative. Status: **implemented, both sides** (model: `permguard-objects`; server: the control plane's `engine` + `store` modules +
the control plane's NOTP surface; client: `permguard-workspace` + the CLI);
protocol freeze awaits the Conformance deliverable at the end.

| Implementation notes (where reality is ahead of or behind this text) | |
| --- | --- |
| Crates | `permguard-objects` (canonical CBOR, objects, policy id, manifest, statements — what the objects *are*, with **no knowledge of any language, protocol or store**) · `permguard-notp` (the wire messages of the protocol that moves them: the model recognises the policy media-type *family*, never the catalogue) · `permguard-languages` (the languages themselves, split by role: the base every side needs, the authoring half only the CLI needs, evaluation when the PDP arrives — plus the dispatch from media type to language) · the server half lives *inside* `permguard-control-plane` (`engine` + `store` modules) · the client half lives *inside* the CLI (`engine::transfer`) — each half is a module of its one consumer; only the model earns a crate |
| gRPC framing | Batches ride one message per request (`GitLikeStore` service) — not client/server streams; the batch limits advertised at negotiate bound every message |
| Key ring | Served as a **JWKS** document (RFC 7517, `OKP`/`Ed25519`) at each plane's `jwks_uri` — `/control-plane/keys`, `/data-plane/keys` — named by `/.well-known/server-configuration` — on a plane's public port the document describes **that plane only** (its own `jwks_uri`); the cross-plane registry lives on the telemetry surface, operator material on the operator's port, so exposing one plane never reveals another's address; also `GetKeyRing` on gRPC. Ring epoch: pending |
| Signing rings | One per plane, configured under `controlPlane.keys` / `dataPlane.keys`: the control plane's (`keys/control`, signs the NOTP head statements; enabled with `operations.keys`) and the data plane's (`keys/data`, will sign decision responses; enabled with `operations.keys` like the control's). Never the ring sealing the audit trail; lifecycle follows `operations.keys` |
| Language validation | Real parses at ingest: Cedar via `cedar-policy`, Rego via `regorus` (crate `permguard-languages`, compiled in). Snapshot-vs-schema validation joins with the evaluation endpoint |
| Quotas | Config section `notp:` — batch, push-delta, and ledger quotas; per-principal staging quota and orphan-TTL GC: pending |
| Force, GC | Not implemented — declared out of NOTP v1 / explicit later operation |

## What is git-like storage

Content-addressed, immutable, versioned storage — the model git proved:

- Every piece of content is an **object**, named by the hash of its own bytes.
  Same bytes → same name, everywhere, forever. Objects never change; changes
  create new objects.
- Objects link to each other **by digest** (commit → tree → blob), so one
  verified head guarantees the integrity of everything reachable from it.
- The only mutable thing is a **ref**: a name pointing at the current head
  commit. History, branching, deduplication, and cheap synchronization all
  fall out of this structure for free.

Permguard uses it to version governed content — policies today, other
domains tomorrow — inside each ledger. Two parts follow: the **object
model** (what is stored) and **NOTP** (how it moves between client and
server).

## Object model specification

### The stack at a glance

| Layer | Choice |
| --- | --- |
| Identity | OCI digest — `sha256:<64 hex>` of the object's canonical bytes |
| Serialization | Canonical CBOR, integer keys, maps sorted |
| Content typing | Media types — `application/vnd.permguard.*`, each with a registered validator |
| Signature | COSE_Sign1 (Ed25519, `kid`) over the context-bound head statement, stored apart from the objects |
| Trust keys | COSE Key Set with states: `signing`, `verify-only`, `revoked` |
| Mutable layer | `refs/<name>` → commit digest; everything else is immutable |

```text
refs/main ──► Commit ──► root Tree ──► TreeEntry ──► Blob | sub-Tree
 (mutable)     │                         (role: name, id)   (opaque bytes)
   signed ─────┴──► predecessors ──► ... ──► root commit
```

One rule decides where a fact lives: **true of the bytes → Blob; true of the
role of those bytes in a tree → TreeEntry.** The same blob may appear in many
trees under different names and ids.

Three structural kinds only — blob, tree, commit. Everything the *domain*
defines (manifests included) is a blob with a media type: the store walks the
graph, it never interprets content.

### Objects

Every object starts with `kind` (CBOR key `1`).

Canonical encoding is enforced **on ingest, not just on output**: the server
decodes strictly and accepts an object only if the received bytes are
byte-identical to its canonical re-serialization. Otherwise the same logical
object could exist under two digests (unsorted maps, long-form integers),
breaking deduplication, id convergence, and negotiation at once.

The canonical profile is normative — RFC 8949 Core Deterministic Encoding:

| Rule | Requirement |
| --- | --- |
| Lengths | Definite-length only |
| Integers | Shortest (preferred) encoding |
| Map keys | Bytewise-sorted encoded keys; **duplicates rejected before materialization** |
| Unknown integer keys | Rejected on structural objects |
| CBOR tags, floats, simple values | Rejected unless a schema explicitly lists them |
| Digest strings | Exactly `sha256:` + 64 lowercase hex `[a-f0-9]` |

A `+cbor` blob payload (e.g. the manifest) is a byte string inside an
already-canonical blob — its **inner** CBOR must satisfy this same profile,
enforced by that media type's validator, or one logical manifest could exist
under many digests.

#### Blob — `kind = 1`

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 1 | `kind` | u8 | `1` |
| 2 | `media_type` | string | What the bytes are — must be a registered media type |
| 3 | `data` | bytes | The authored content, verbatim. Opaque to the store |

#### TreeEntry (inside a Tree)

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 1 | `kind` | u8 | Kind of the referenced object (`1` blob, `2` tree) |
| 2 | `digest` | string | `sha256:<hex>` of the referenced object |
| 3 | `name` | string | Path segment — unique in the tree; grammar below |
| 4 | `annotations` | map string→string | Well-known keys (below). Deterministic: sorted, string values only |

Entry `name` grammar (normative — an entry name is one path segment, never a
path): charset `a-z 0-9 . - _`, 1–128 bytes, starts and ends alphanumeric,
never `.` or `..`, no `/`, no other byte (no NUL, no percent-escapes, no
non-ASCII).

#### Tree — `kind = 2`

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 1 | `kind` | u8 | `2` |
| 2 | `entries` | array of TreeEntry | Sorted by `name`, unique names |

A tree carries no location or partition field: where it sits is a fact about
its *role*, so it lives in the entry that points to it. Identical subtrees
share one digest wherever they appear.

#### Commit — `kind = 3`

| Key | Field | Type | Meaning |
| --- | --- | --- | --- |
| 1 | `kind` | u8 | `3` |
| 2 | `tree` | string | Digest of the root tree |
| 3 | `manifest` | string | Digest of the manifest blob (also reachable inside the root tree) |
| 4 | `predecessors` | array of digest | `[]` root · `[x]` linear · `[x,y]` merge |
| 5 | `author` | string | Who authored the change |
| 6 | `author_at` | i64 | Unix seconds, UTC |
| 7 | `message` | string | Human summary |

The commit contains **only client-determined fields** — the client builds it
locally and announces its digest before the server sees it, so the server can
never author a byte of it without changing the head. Server-side acceptance
facts (when it was accepted, by which authenticated principal) live **only in
the audit trail** — the authoritative record of acceptance — never in the
hashed object, and not in the head statement either (whose `signed_at` is a
signing time, free to change on re-sign, not an acceptance time).

### Limits

Enforced at push; an object over any limit is rejected, never truncated.

| Limit | Value |
| --- | --- |
| Object size | ≤ 5 MB |
| Entries per tree | ≤ 10 000 |
| Tree depth | ≤ 32 |
| Annotations per entry | ≤ 32 |
| Annotation key | ≤ 128 bytes, charset `a-z 0-9 . - _`, namespaced (`permguard.…`) |
| Annotation value | ≤ 1 KB, UTF-8 string |

### Media types

The store is generic; domains are registered here. A media type is a
contract: **name + version + validation rule**. At push, the domain validator
dispatches on the blob's `media_type`; an unregistered media type is
**rejected — fail-closed**, never stored as "unknown opaque bytes".
`+cbor` suffix = structured CBOR payload; no suffix = raw authored text.

| Media type | Payload | Validation at ingest (per blob) |
| --- | --- | --- |
| `application/vnd.permguard.policy.cedar` | Cedar policy source, verbatim bytes | Cedar parse — the source must compile |
| `application/vnd.permguard.schema.cedar` | Cedar schema, verbatim bytes | Cedar schema parse |
| `application/vnd.permguard.manifest.v1+cbor` | Ledger manifest (below) | Canonical CBOR decode + structural schema |
| `application/vnd.permguard.policy.rego` | Rego policy source, verbatim bytes | Rego parse (`regorus`) |

Validation runs at **two levels**, and both are required — and on **both
sides**: the client validates before sending (fail fast, good errors), the
server re-validates everything on receive because it trusts nobody. Nothing
that fails schema or validation is ever stored.

1. **Ingest, per blob** (table above): syntax, resource bounds — a blob is
   accepted in isolation.
2. **Commit, per snapshot**: the whole new tree is validated as a set —
   Cedar policies against the Cedar schema in the same snapshot, partitions
   against the manifest rules, ids against the identity rules. Parsing alone
   never makes a policy set valid.

Validators are **versioned and pinned**: the manifest declares the engine
profile (language + validator version) each partition is validated against,
so an immutable, already-accepted blob can never become invalid because a
node upgraded its parser. Changing the profile is a manifest change — a new
commit, visible in history.

Naming pattern for future families:
`application/vnd.permguard.<family>.<format>[+encoding]` — the family is the
content typology, the format names the language or schema version, the
encoding suffix tells transports how to decode without understanding.
Registering a new family = name + schema + validator; the store is untouched.

### Manifest

A blob (`…manifest.v1+cbor`), not a structural kind. Exactly one per commit,
pointed to by the commit and present as the well-known root entry `manifest`.
It is the authority on what the ledger is and how it may be consumed:

| Field | Type | Meaning |
| --- | --- | --- |
| `metadata` | map | `kind` (the ledger's type: `policy` today, `pip` later — **never mixed** in one ledger), name, description, author, license |
| `runtimes` | map string→runtime | Runtime key (e.g. `cedar`) → `language {name, constraint}` + `engine {name, constraint}` — two independent semver-range constraints |
| `partitions` | map string→rules | Partition name → its runtime, allowed media types, whether a schema is present. Names unique (a CBOR map under the canonical profile) and matched 1:1 with the root subtrees — declared-but-absent and present-but-undeclared both reject |
| `profiles` | map string→profile | Profile name → `type` (the **evaluation contract**, language-agnostic: `permguard.pdp.v1` now; `authzen.v1`, `permguard.trust-anchor.v1` later) + the partitions it is built from |

A **profile is a contract, not a language**: it fixes how a consumer asks for
and receives decisions (AuthZEN-style: subject/action/resource/context →
decision), whatever languages the partitions underneath speak.

**Runtime constraints are a fail-closed load gate, not decoration.** Version
constraints follow a closed semver-range grammar — `>=x.y.z`, `>=a <b`,
exact `x.y.z`; nothing else — and every consumer (the data plane before
evaluating, the control plane at commit validation, the CLI when building)
MUST refuse to operate on a ledger whose `language`/`engine` constraints its
own implementations do not satisfy. Re-checked on every load and sync: an
engine outside the declared range interpreting the same policies differently
is a silent authorization bypass, and the only safe answer is `unavailable`,
never a best-effort decision.

### Partitions

A partition is a **named subtree of the root tree** — pure structure, no
dedicated field. The manifest declares each partition and what it may
contain; push validation enforces it (a blob whose media type is not allowed
in its partition is rejected).

```text
root Tree
 ├── "manifest"  ──► Blob  vnd.permguard.manifest.v1+cbor
 ├── "cedar/"    ──► Tree  (partition: Cedar policies and schemas)
 └── "rego/"     ──► Tree  (partition: another language, its own rules)
```

A domain may store additional manifest blobs inside a partition as ordinary
entries; the commit-level manifest remains the single authority.

### Commit acceptance invariants

Checked by the server before any ref may point at a commit — all of them,
every time, fail-closed:

| Invariant |
| --- |
| Every object of the new region is present, canonical, and within limits |
| `TreeEntry.kind` equals the actual kind of the referenced object |
| `Commit.tree` references a Tree; `Commit.manifest` references a blob of the manifest media type |
| `Commit.manifest` equals the digest of the root entry `manifest` |
| `predecessors` has 0–2 entries, no duplicates, each referencing a **Commit**: `[]` only for a history root, `[x]` linear, `[x,y]` merge |
| Every blob's media type is allowed by the manifest rules of its partition |
| Identity rules hold (id cascade recomputed, uniqueness, no identity mutation) |
| Snapshot-level semantic validation passes under the pinned engine profile |

Domain validity is **contextual**: the same subtree digest can be valid under
one partition's rules and invalid under another's. Implementations must never
memoize `digest → domain-valid` alone — the cache key is
*(digest, partition rules, engine profile)*. Structural validity (canonical
bytes, hash, limits) is context-free and may be cached by digest.

### Refs

A ref is the only mutable object and appears in URLs and on disk, so its
grammar is normative, parsed per segment, never naively concatenated into
paths:

| Rule | Value |
| --- | --- |
| Charset | `a-z 0-9 - _`, segments separated by `/` |
| Segment | Starts with a letter, ends alphanumeric, 1–63 bytes |
| Total length | ≤ 255 bytes |
| Forbidden | Empty segments, `.`, `..`, leading/trailing `/`, any other byte (no `\`, NUL, percent-escapes, non-ASCII) |

### Annotations — well-known keys

Namespaced, string values, part of the hashed content. Domain validation at
push rejects a policy entry missing its required keys.

| Key | Required for | Meaning |
| --- | --- | --- |
| `permguard.policy.id` | `…policy.*` | Stable identity of the policy across revisions — always system-derived, never authored |
| `permguard.policy.alias` | optional | The `@alias` declared in the source: a human handle, unique per snapshot when present, and the carry-forward hook across renames |
| `permguard.policy.kind` | `…policy.*` | Kind of element (policy, template, …) |
| `permguard.policy.language-version` | optional | Language version it was authored against |

### Policy id

Never random, never minted per push, and **never authored**: the identity is
always the system's, a pure function of *(previous tree, content)* — the
client computes it and writes the annotations into the tree it builds; the
server recomputes the same function and rejects the push on any mismatch.
What the author may declare is an **alias** (`@alias("…")` in Cedar): an
optional human handle — present or absent, never the id — that carries the
identity across renames.

| Rule | Source | When |
| --- | --- | --- |
| 1 | Carried forward from the previous tree, matched by **logical path** | Edit of an existing entry |
| 2 | Carried forward matched by **`@alias`**, when no path matches | Rename/move of an entry that declares an alias |
| 3 | Derived from the exact authored bytes: `sha256("permguard.policy.id.v1" ‖ bytes)`, folded to a UUID as defined below | New entry |

Precisions, all normative:

- Rule 3 hashes the **verbatim authored bytes** with a domain-separation
  prefix (the prefix is the 22 ASCII bytes `permguard.policy.id.v1`, no
  separator) — no semantic canonicalization, no whitespace or comment
  stripping. "Same bytes ⇒ same id" is the whole contract, identically
  computable in any language.
- **UUID folding, exactly**: take bytes 0–15 of the SHA-256 digest in order;
  set byte 6 to `(byte6 & 0x0F) | 0x80` (UUID version 8) and byte 8 to
  `(byte8 & 0x3F) | 0x80` (RFC 9562 variant); render as lowercase hyphenated
  `8-4-4-4-12` hex. No other byte is altered, no endianness conversion.
- `@alias` is optional. When present it is recorded as
  `permguard.policy.alias`, MUST be **unique per snapshot**, and MUST be
  stable: an entry whose path matches a previous entry cannot change its
  alias and its id in the same push (one handle must survive to prove
  continuity). Removing or adding an alias on an existing path is fine — the
  path carries the identity through.
- Merge (two predecessors): rules 1–2 match against **both** parent trees.
  Same id in both → carried. Different ids for the same path or alias →
  explicit conflict, the push is rejected until the client resolves which
  identity survives.
- Cedar gives `@alias` no special language semantics — it is an annotation.
  Its binding to `permguard.policy.alias` is defined here and verified at
  push. Other families define their own alias marker, or none.

Consequences, by design:

- Two authors pushing identical new content from different machines derive
  the **same id** — merges converge, no duplicates.
- Once assigned, edits keep the id (rule 1). The id is frozen by history,
  not by the file.
- A rename without an alias is a new identity — git semantics. Declare
  `@alias` when continuity across renames matters: the alias, not the id,
  is the author's handle.
- The PDP assigns the annotation id to the policy set at load time, so
  authorization responses and audit records cite this id (reports may show
  `alias (id)` together — both live in the tree).

The blob digest identifies the **revision**; `permguard.policy.id` identifies
the **policy** across revisions. Both always exist; the alias exists when the
author wants a handle.

### Signatures

Objects are persisted **unsigned**. Integrity at rest is the hash chain.
Provenance is a COSE_Sign1 envelope over a **head statement**, stored apart
from the objects (never inside the hashed content), produced by the server
and delivered alongside the head when a ref is served.
The signature never enters the hashed content, so re-signing never rewrites
history. An implementation may produce it at ref update or lazily at first
serve and cache it — the model does not care.

The signed payload is never a bare digest — it binds the digest to its
context, so a genuine signature cannot be replayed on another zone, ledger,
or ref. The envelope is COSE_Sign1 with the statement **embedded** as the
payload (RFC 9052 terms — not detached: the statement travels inside the
envelope):

```text
COSE_Sign1 {
  protected:   { alg: EdDSA (-8), kid: bstr "2026-08-srv-1" (UTF-8) }
  payload:     bstr( HeadStatement, canonical CBOR ) {
    1  zone       zone GUID
    2  ledger     ledger GUID
    3  ref        ref name, e.g. "main"
    4  digest     sha256 of the head commit
    5  counter    u64, monotonic per ref — +1 on every ref update
    6  signed_at  Unix seconds, UTC
  }
  signature:   Ed25519                              (64 bytes)
}
```

The profile pins the algorithm fully: verifiers accept only `alg = EdDSA`
with a key of `kty = OKP`, `crv = Ed25519` — never any other EdDSA-capable
key. `kid` is a byte string (UTF-8 text inside), unique within the key set.

#### Rollback protection — what it gives, honestly

This is **stateful rollback protection after a trusted checkpoint**. The
client persists the last accepted `(counter, digest)` per (zone, ledger, ref)
and applies:

| Received | Verdict |
| --- | --- |
| `counter > last` | Accept, persist new checkpoint |
| `counter == last`, same digest | Accept (retry, or re-sign after rotation) |
| `counter == last`, different digest | **Equivocation — reject** |
| `counter < last` | **Rollback — reject** |

Re-signing after a key rotation keeps the same counter and digest — that is
why equal-counter-same-digest must verify.

What the counter alone does not protect: a client with **no checkpoint** —
first clone, lost or restored local state, a new machine. Such a client
accepts the first validly-signed head it sees (trust on first use) and is
protected from then on. The signing server is inside the trusted computing
base: two clients cannot detect the server signing them two different heads
(fork equivocation) with this mechanism — declared out of scope; a
transparency log would be the upgrade if that threat ever matters.

#### Verification (client, on pull)

```text
1. fetch ref ──► head statement + COSE signature
2. verify signature against the key ring (by kid)     ── provenance
3. check zone/ledger/ref match, then apply the
   (counter, digest) rollback/equivocation table above  ── freshness
4. walk the DAG from the head, recompute every digest,
   stopping at an already-verified local checkpoint     ── integrity
```

Step 4 need not re-verify history below a checkpoint the client has already
verified and persisted (the closure behind a `have`) — new objects are always
hash-verified, old verified ones are not re-walked on every pull.

Trust flows **downward from the head**: a commit reachable from an attested
head is valid regardless of any older signature's key state. Signatures gate
the *view*; hashes gate the *objects*.

#### Key ring and rotation

The server publishes a COSE Key Set. Each key: `kid` + state. The ring needs
its own trust model, or replaying an **old ring** would resurrect a revoked
key:

- **Trust anchor**: the ring is fetched over the transport trust already in
  place (TLS, optionally pinned in client configuration). Deployments that
  want independence from TLS pin the ring's root key in configuration.
- **Ring epoch**: the key set carries a monotonic `epoch`; clients persist it
  and reject any ring with a lower epoch — the same rule as the head counter,
  applied to the trust material itself.
- A `kid` is never reused for different key material.

| Event | Server does | Client does |
| --- | --- | --- |
| Routine rotation | New key signs; old key → `verify-only` | Nothing — old signatures stay valid |
| Compromise | Key → `revoked`; re-sign ref heads with new key | Re-fetch signatures (~100 B each). **Never** re-fetches objects |
| Corrupt local object (hash mismatch) | — | Re-fetch that one object — the digest guarantees which bytes are correct |

Hashes give corruption **detection, not recovery**: if the server's own copy
has rotted, re-fetching returns the same corrupt bytes and the client keeps
rejecting them. The server verifies the hash when reading an object it is
about to serve on suspicion (or on a failed client verification report) and
marks a mismatch corrupt/unavailable; recovery comes from replicas or
backups, never from the hash itself. Presence in negotiation ("file exists")
is likewise not proof of integrity.

Fail-closed: a head whose signature does not verify against the current ring,
or whose statement fails the context or counter check, is an unattested view —
the ref is not used until a fresh statement arrives.

### Worked example

One zone, ledger `main`, a Cedar partition with two policies. Digests
shortened to 8 hex for readability — real ones are 64.

**Blob** `sha256:9c41aa02`

| Field | Value |
| --- | --- |
| kind | 1 |
| media_type | `application/vnd.permguard.policy.cedar` |
| data | `permit(principal in Group::"billing", action == Action::"view", resource);` |

**Tree (partition `cedar/`)** `sha256:5b02e11f`

| name | kind | digest | annotations |
| --- | --- | --- | --- |
| `billing-view.cedar` | 1 | `sha256:9c41aa02` | `permguard.policy.id: 7f3a9c21-4b8e-8d5f-a1c2-9e0b3d6f8a41` · `permguard.policy.kind: policy` |
| `ops-admin.cedar` | 1 | `sha256:e3d70486` | `permguard.policy.id: 1b9e6f04-2a7c-8b3d-9e1f-4c5a6d7e8f90` · `permguard.policy.kind: policy` |

**Root Tree** `sha256:a94d20c7`

| name | kind | digest | annotations |
| --- | --- | --- | --- |
| `cedar` | 2 | `sha256:5b02e11f` | — |
| `manifest` | 1 | `sha256:77a1b3c5` | — |

**Manifest blob** `sha256:77a1b3c5` — `application/vnd.permguard.manifest.v1+cbor`

| Field | Value |
| --- | --- |
| metadata | `name: main` |
| partitions | `cedar → { media_types: [policy.cedar, schema.cedar] }` |
| profiles | `default → [cedar]` |

**Commit** `sha256:41f6c990`

| Field | Value |
| --- | --- |
| kind | 3 |
| tree | `sha256:a94d20c7` |
| manifest | `sha256:77a1b3c5` |
| predecessors | `[sha256:d08a44b1]` |
| author / author_at | `nicola.gallo@nitroagility.com` / `1787836800` |
| message | `Restrict billing view to the billing group` |

**Served to the client**

| Item | Value |
| --- | --- |
| `refs/main` | `sha256:41f6c990` |
| Head statement | `zone: 0198f2…` · `ledger: 0198f3…` · `ref: main` · `digest: 41f6c990…` · `counter: 42` · `signed_at: 1787836802` |
| COSE_Sign1 | `kid: 2026-08-srv-1` · payload = the statement · Ed25519 signature |

Edit `billing-view.cedar` and push: new blob digest, new partition tree, new
root tree, new commit with `predecessors: [sha256:41f6c990]` — but the entry
keeps `permguard.policy.id: 7f3a9c21-…` (rule 2). Audit history stays whole.

### Layout on disk

Inside `zones/<zone-guid>/ledgers/<ledger-guid>/`:

```text
FORMAT                    the layout version pin — `1`
objects/41/f6c990…        one file per object, digest-fanout, immutable, zlib
refs/main                 the head commit digest + monotonic counter
signatures/main.sig       COSE_Sign1 head statement, replaced on update
```

Object files are **zlib-compressed at rest** — the shelf git keeps loose
objects on. The digest always names the uncompressed canonical bytes;
compression is an encoding of the shelf, never of the identity, and every
read decompresses (bounded by the object size limit) and re-verifies the
hash. `FORMAT` pins the layout: a store whose pin does not match — or a
populated store without one — is refused with what was found, never
reinterpreted. The workspace's `.permguard` mirrors both rules (its pin is
the `version` field of its config).

The abstract property implementations must satisfy, however they deploy:

> `UpdateRef(expected, new)` MUST be linearizable and MUST update
> `(head, counter)` as one atomic, durable unit.

Single-node satisfies it with the ledger lock and this write sequence before
acknowledging: write temp → fsync temp → atomic rename → fsync the containing
directory. A distributed deployment must provide the same property by other
means (a linearizable store); "ledger lock" is the single-node implementation
of the property, not the property. Objects and signatures are written
tmp+rename; the signature file is a cache of the head statement — the server
verifies it matches the current `(head, counter)` before serving it, and
regenerates it if not.

The catalog's ledger record declares the ledger's **default ref** (e.g.
`main`) — a reference, never a copy: the head digest lives only in
`refs/<name>`, and any API that shows a ledger's head reads it through the
ref at response time. One source of truth; no second head to drift.

Garbage = objects unreachable from any ref. Collection is explicit — never
implicit — and only collects orphans older than the orphan TTL, serialized
with ref updates on the same lock. The TTL makes collecting a live upload
unlikely, not impossible (an upload can idle past the TTL before its commit):
correctness never depends on it, because commit re-checks the closure and
fails on missing objects — the client re-uploads and retries.

## Reclaiming what nothing references

A content-addressed store only ever adds. Objects are uploaded **before** the
commit that references them, so a push that never commits — a lost connection,
a conflict nobody retried — leaves objects nothing will ever reach; so does a
history that moved past a policy version. Nothing else in the protocol deletes
an object, so the disk of a long-lived deployment climbs in one direction until
something reclaims.

The rule is the same on both sides, and it is one line:

```text
keep  =  reachable from any ref  ∪  younger than the grace period
```

**Reachability** is computed from *every* ref, walking commits to their
predecessors, manifest and tree, and trees to their entries. **Age** is what
protects a transfer in flight: during a push the uploaded objects are
legitimately unreachable, so a sweep that ignored their age would delete the
work of every push in progress. A server refuses a grace period short enough to
make that possible (15 minutes is the floor; the default is a day).

| | Server (a ledger) | Client (a workspace mirror) |
| --- | --- | --- |
| Roots | every ref of the ledger | the tracked checkpoint, and the staged snapshot |
| Runs | on a cadence — `controlPlane.storage.gc` | when somebody runs `permguard objects prune` |
| Concurrency | the grace period | the workspace lock a mutating command already holds |
| A hole in the closure | that ledger is skipped, untouched | the prune is refused, pointing at `permguard verify` |
| Records | the audit trail, every sweep, plus metrics | the command's own report |

Two properties of the model are what make this safe rather than merely
convenient: objects are **immutable and content-addressed**, so anything
removed by mistake can be restored byte-identically by any party that holds it;
and ref updates are **atomic**, so a sweep sees a ref either before or after a
commit, never halfway.

## NOTP — Negotiated Object Transfer Protocol

How objects move between a client workspace and the server. Same shape as
git's smart protocol — advertise, negotiate, transfer — but deliberately
simpler: **synchronous request/response, stateless on the server, one
negotiation round**. No sessions, no packfiles, no delta compression: at our
scale (hundreds of small objects) set-difference on digests is the whole
optimization, and content-addressing makes every step idempotent and
retryable. Batches do ride compressed when both sides agree — see
[Compression](#compression) — but that is an encoding of the pipe, never a
protocol state.

Exposed on both surfaces from one core, like every other API:

| Operation | REST | gRPC |
| --- | --- | --- |
| Advertise | `GET  …/ledgers/{ledger}/refs/{ref}` | `GetRef` |
| Negotiate push | `POST …/ledgers/{ledger}/notp/push/negotiate` | `NegotiatePush` |
| Upload objects | `POST …/ledgers/{ledger}/notp/objects` | `UploadObjects` (client-stream) |
| Commit push | `POST …/ledgers/{ledger}/notp/push/commit` | `CommitPush` |
| Negotiate pull | `POST …/ledgers/{ledger}/notp/pull/negotiate` | `NegotiatePull` |
| Download objects | `POST …/ledgers/{ledger}/notp/objects/fetch` | `FetchObjects` (server-stream) |

REST bodies are `application/vnd.permguard.notp.v1+cbor` (CBOR, the one codec
of the whole stack); errors use the standard `{class, code, message}` wire
taxonomy. gRPC streams object batches; REST batches in one body — same
messages, two framings.

**Scope**: authentication and authorization are not part of NOTP. They belong
to the hosting API server — the transport layer (TLS, mTLS, peer
authorization) and whatever access control it enforces gate every operation
before NOTP sees the request. The read granularity is the **ledger**: a
principal allowed to read a ledger may fetch any object in it by digest,
orphans included. Finer-grained read control (per ref, partition, or
reachability) is not supported by this protocol.

### Transport-aware batching

Message size limits differ per transport (a gRPC message caps at a few MB; an
HTTP body does not, but should be bounded anyway). The transfer therefore
never assumes a size: **every negotiate response advertises the server's
batch limits for the transport it arrived on**, and the client chunks
accordingly.

| Advertised in every negotiate response | Meaning |
| --- | --- |
| `max_batch_bytes` | Upper bound of one upload/fetch batch on this transport |
| `max_batch_objects` | Upper bound of objects per batch |

The client splits uploads and fetch requests into as many batches as needed —
each batch is an independent, idempotent request, so a failed batch is
re-sent alone. On gRPC the stream carries one object per message, the batch
bounds the stream; on REST the batch is the body.

Objects are never chunked, so a normative deployment constraint follows: on
every transport, the configured maximum message size MUST exceed the maximum
object size (5 MB) plus framing overhead — the default gRPC 4 MB message cap
is **not** a legal configuration for NOTP.

### Compression

Negotiated, like the batch limits, in the same single round — metadata first,
bytes after:

```text
negotiate response      compression: "deflate"        the server speaks it
upload request          compression: "deflate"        this batch is encoded so
fetch request           accept_compression: "deflate" the client can undo it
fetch response          compression: "deflate"        this batch is encoded so
```

Rules, all fail-closed:

- The field is **optional everywhere; absent means raw**. A client that does
  not speak the advertised algorithm simply sends and asks for raw batches —
  every server accepts them. Nothing breaks across versions.
- `deflate` (zlib, RFC 1950) is the one algorithm of this version. A new
  algorithm is a new name — additive, never a reinterpretation.
- Each object in a batch is compressed **individually**, so per-object
  decompression is bounded by the object size limit — a batch cannot be a
  zip bomb — and digests, claims and quotas all speak uncompressed bytes.
- A batch naming an unknown algorithm is rejected (`batch_rejected`), as is
  one that does not decompress.

The server side is one switch: `notp.compression: deflate | none`
(default `deflate`), advertised both per negotiation and in the discovery
document's `notp` object.

### Quotas

Per-object limits (previous section) bound each object; these bound the
aggregate — otherwise an authorized-but-compromised client could fill the
volume with perfectly valid orphans:

| Quota | Enforced at |
| --- | --- |
| Max objects and total bytes per push delta | Negotiate (preflight, on declared `{digest, size}`) and **re-enforced at commit on actual state** |
| Per-ledger storage quota | Upload — checked atomically (two parallel uploads cannot both pass on the same remaining space); rejected with class `unavailable` |
| Per-principal staging quota / rate limit | Upload — bounds an authorized-but-compromised writer that never commits |
| Orphan TTL | Objects uploaded but never committed become collectable after it |

### Transfer lifecycle

One logical transaction, whatever the transport and however many batches:

```text
negotiate ONCE ──► full `missing` set + batch limits
      │
      ▼
transfer N independent, idempotent batches   (split by the client
      │                                       to fit the limits)
      ▼
verify completeness
      │
      ▼
finalize ONCE    push: CommitPush + remote CAS
                 pull: advance the local ref/checkpoint
```

- Negotiation happens **once per attempt**, never once per batch. Batching
  is purely a framing concern of the transport; it never changes the logical
  transaction.
- A failed batch is retried **alone**: completed batches are immutable
  objects already stored, never re-sent (uploading an already-present digest
  is a no-op anyway). A retry re-requests only what is still missing.
- The client MUST NOT call `CommitPush` before every required object of the
  new region is uploaded — and the server does not trust that: commit
  re-verifies completeness, invariants, and quotas on disk, and a premature
  commit fails with `not_found`, leaving the ref untouched. The ref changes
  **only** after the whole transfer validated.
- **Pull finalization is distinct from downloading.** Objects MAY be
  persisted incrementally as batches succeed — they are immutable and
  reusable — but a client MUST NOT advance its local ref or persist the new
  `(counter, digest)` checkpoint until the complete required closure of the
  target commit is present and verified. An interrupted pull leaves the
  local ref at the old head with the already-verified objects kept; there is
  never an observable state where the ref names a head whose closure is
  incomplete. The head is logically atomic: it moves only when everything it
  points at is available and valid.
- **`missing = []`** is explicit, not accidental: on push, the client
  proceeds straight to `CommitPush` (which still runs every validation
  before the CAS); on pull, with the closure already present and verified
  locally, the client proceeds straight to finalization after the head
  statement and freshness rules pass.

### Binding across the steps

Because the server is stateless, nothing binds negotiate → upload → commit:
declarations made at negotiate are **preflight only**, never security
enforcement. Every security-relevant check (quotas, limits, closure
completeness, all commit acceptance invariants) is re-executed at commit on
what is actually on disk — a client that negotiates X, uploads Y, and commits
Z gains nothing. All quotas configurable, defaults declared with the
implementation; fail-closed like everything else.

### Push

The client builds the new commit locally, then negotiates the **delta
closure**: the objects reachable from the new head that are *not* reachable
from `expected old head` — never the full history. The server already holds
the old head's immutable closure; re-declaring it on every push would make
negotiation grow with history until the per-push cap forbids all pushes.

```text
client                                          server
  │ 1. negotiate: ref, new head, expected old,    │
  │    delta closure as {digest, size} ──────────►│  set-difference
  │◄────────── missing: [digests], batch limits ──┤  against objects/
  │ 2. upload: only the missing objects ─────────►│  per object: recompute
  │◄──────────────────────── received / rejected ─┤  digest, limits, ingest
  │ 3. commit: ref, new head, expected old head ─►│  validation; commit runs
  │◄────────────── ok + new head, or `conflict` ──┤  ALL acceptance invariants
```

- **Step 1** costs one round trip and a `{digest, size}` list (a size is
  declared because a digest alone reveals nothing about bytes — the byte
  quota needs it; the server re-checks actual sizes at upload). The server
  answers from file existence alone — no graph walk, no state kept.
- **Step 2** sends only what the server lacks. Uploading an object the server
  already has is harmless (same digest, same bytes) — retries are free.
  Every object is verified before it touches `objects/`: digest must match
  the bytes, canonical profile and limits apply, fail-closed.
- **Step 3** updates the ref, with two normative rules:

  **Fast-forward only.** `expected old head` must be an **ancestor** of the
  new head, and the ancestry path must be verifiable through the new region —
  a push may therefore carry N new commits (`A → B → C → D` pushed onto `A`),
  exactly like git. A push that would orphan history is rejected. History
  rewrite is a separate **force** operation with its own permission and its
  own audit event — never a side effect of an ordinary push; force is
  **outside NOTP v1** (the surface stays six operations).

  **Idempotent compare-and-swap.** The ref update resolves as:

  | Current head | Result |
  | --- | --- |
  | `== new head` | Success — the previous attempt landed; counter NOT incremented again |
  | `== expected old head` | CAS: update `(head, counter)`, success |
  | anything else | Class `conflict` |

  The lost-response retry (`commit lands, ack lost, client re-sends`) is
  therefore a success, not a conflict — the response returns the current head
  statement either way. The server refuses to commit while any object of the
  new region is missing, so a crashed upload is simply re-run.

  **Push to a ref that does not exist.** The client sends
  `expected old head = absent`; the CAS rule extends naturally: `absent → new`
  succeeds only if the ref still does not exist (a concurrent creation is a
  `conflict`; a retry that finds `current == new head` is a success, as
  above). The new ref's counter starts at `1`, acceptance invariants run in
  full, and two distinct cases are legal:

  - **Branch**: the new head is a commit already stored and reachable from an
    existing ref of the same ledger — `feature` created at `main`'s `C`.
    Nothing is uploaded; this is how branching stays free.
  - **History root**: the new head is a new closure whose root commit has
    `predecessors = []` — the first history of the ledger (or a deliberate
    independent line).

  A push with `expected old head = absent` against an **existing** ref is
  rejected: recreating a ref is history rewrite, i.e. force.

Orphaned objects from an abandoned push are unreachable and cost only disk
until garbage collection (bounded by the quotas above) — correctness never
depends on cleanup.

### Pull

```text
client                                          server
  │ 1. negotiate: ref, at?, have: [local heads] ─►│  walk from head (or `at`),
  │◄── head, COSE signature, missing: [digests] ──┤  stop at anything `have`d
  │ 2. fetch: [digests] ─────────────────────────►│
  │◄─────────────────────── the objects, batched ─┤
```

A pull targets the ref's **current head by default**. The optional `at` pins
the pull to a specific commit digest, which MUST be reachable from the
requested ref (so read granularity stays honest); the walk then starts at
`at` instead of the head. A pinned pull is verified by hash alone — the
client is naming the digest it wants — while the head statement in the
response remains the only proof of *what latest is*, with the freshness rules
applying to it as usual. Pulls take no lock: refs are written atomically
(tmp+rename), so a lockless read always sees a consistent `(head, counter)`
snapshot; pushes serialize on the ledger lock, pulls never wait.

- **`have`** is typically one digest — the client's current head. Declaring
  `have: X` is a contract: *the client holds and has verified the entire
  transitive closure of X*, not merely the object X. The server walks its own
  DAG from the advertised head and stops at anything `have`d; a client that
  claims a checkpoint it has partially lost gets an incomplete `missing` list
  and only hurts itself (it can always re-negotiate with a smaller `have`).
  An empty `have` is a full clone.
- The response carries the **head signature**; the client verifies it against
  the key ring, then verifies every fetched object by recomputing its digest
  (the verification flow of the Signatures section). A digest mismatch
  rejects that object and fails the pull — fail-closed.
- Fetch is repeatable and resumable by construction: ask again for whatever
  is still missing; objects already stored locally are skipped by digest.

### Compound commands

`clone`, `checkout`, and friends are client-side compositions of the
primitives above — the protocol surface stays these six operations:

| Command | Composition |
| --- | --- |
| `clone` | pull with empty `have` |
| incremental sync | pull with `have: [local head]` |
| `push` | negotiate → upload missing → commit (CAS) |
| retry after failure | re-run the same step — every step is idempotent |

### Why it is cheap, by construction

| Resource | What bounds it |
| --- | --- |
| Bandwidth | Only the delta-closure set-difference travels; unchanged subtrees are shared by digest and never re-sent |
| Storage | One copy per digest, ever — deduplication is the naming scheme |
| Round trips | Advertise + negotiate + transfer + (push) commit — fixed, no multi-round haggling |
| Server memory | Stateless: each request is self-contained; existence checks are file stats |
| Concurrency | Object writes are tmp+rename and idempotent; the only contended step is the linearizable ref update |

### Conformance — required before protocol freeze

This document fixes the model and the protocol behavior; core implementation
may begin against it. Before the protocol is **frozen** — the point where
independent implementations must interoperate — one more deliverable is
required, produced in parallel with the first implementation:

- **CDDL schemas** for every wire payload: the four objects, the head
  statement, the key set, and every NOTP request/response (negotiate,
  upload, commit, fetch — including object descriptors, partial-error
  semantics, and bounds for every list; initial-push semantics are already
  fixed in the Push section, the CDDL only encodes them).
- **Golden vectors**: byte-for-byte canonical encodings with their digests
  and signatures, so every SDK proves the same bytes, the same hashes, the
  same verdicts.
