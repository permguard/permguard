<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Profiles & Manifest

What a ledger **is**, what it **holds** (the manifest), and the **contracts**
it can be consumed through (the profiles) — one document, because they are
two halves of one decision: the manifest declares, the profile serves.
Status: **implemented** — manifest, languages, load gate, and the
`permguard.pdp.v1` decision endpoint on the data plane, over HTTP and gRPC.
Companion of the [git-like storage specification](gitlike-object-model.md) and
of [Answering decisions](authorization-check.md), which documents the serving
side: the volume walk, the cache, and what an operator sees.

```text
manifest  = what the ledger declares    (content, languages, constraints)
profile   = how a consumer talks to it  (the evaluation contract)
```

## Structure

```text
manifest
├── metadata      who/what this ledger is — including its KIND
├── runtimes      the language + engine every consumer must satisfy
├── partitions    named subtrees: what may live where
└── profiles      the evaluation contracts offered on top
```

| Section | Field | Meaning |
| --- | --- | --- |
| `metadata` | `kind` | The ledger's type: `policy` today, `pip` later. **One kind per ledger, never mixed** |
| | `name`, `description`, `author`, `license` | Human identity |
| `runtimes.<key>` | `language {name, constraint}` | The policy language and the semver range it was authored against |
| | `engine {name, constraint}` | The evaluation engine and the semver range allowed to run it — an **independent** constraint |
| `partitions.<name>` | `runtime` | Which runtime the partition's content speaks |
| | `media_types` | The registered media types allowed inside |
| | `schema` | Whether the partition carries a language schema |
| `profiles.<name>` | `type` | The **evaluation contract** (language-agnostic — see Profiles) |
| | `partitions` | Which partitions the profile is built from |

Partition names are unique twice by construction: they are keys of a CBOR map
(duplicates rejected by the canonical profile) and entries of the root tree
(unique, sorted). Declared partitions and root subtrees must match **1:1** —
declared-but-absent and present-but-undeclared both reject the push.

## Example

```json
{
  "metadata": {
    "kind": "policy",
    "name": "playground-cedar",
    "description": "A Permguard project using the Cedar language.",
    "author": "Nitro Agility S.r.l.",
    "license": "Apache-2.0"
  },
  "runtimes": {
    "cedar": {
      "language": { "name": "cedar",     "constraint": ">=4.0.0" },
      "engine":   { "name": "permguard", "constraint": ">=0.1.0 <0.2.0" }
    },
    "rego": {
      "language": { "name": "rego",      "constraint": ">=1.0.0" },
      "engine":   { "name": "permguard", "constraint": ">=0.1.0 <0.2.0" }
    }
  },
  "partitions": {
    "app":     { "runtime": "cedar", "media_types": ["application/vnd.permguard.policy.cedar", "application/vnd.permguard.schema.cedar"], "schema": true },
    "gateway": { "runtime": "rego",  "media_types": ["application/vnd.permguard.policy.rego"], "schema": false }
  },
  "profiles": {
    "default": { "type": "permguard.pdp.v1", "partitions": ["app", "gateway"] }
  }
}
```

(JSON above for readability; the wire form is canonical CBOR, like every
object of the store.)

## Languages

Each language is a registered media-type family with its own runtime entry.
Two are defined today, one is planned:

| Language | Media types | Schema | Status |
| --- | --- | --- | --- |
| Cedar | `application/vnd.permguard.policy.cedar` · `application/vnd.permguard.schema.cedar` | Cedar schema, its own media type | first |
| Rego | `application/vnd.permguard.policy.rego` | none — `schema: true` on a Rego partition **rejects** | **built in** (`regorus`) |
| JSON + CEL | data + expressions, two media types in one family | per family | planned |

### Cedar — example policy

The `@alias` annotation is the optional human handle: it carries the
identity across renames. The id itself is always system-derived; decisions
and audit records cite the id, reports may show both.

```cedar
@alias("budget-readers")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource == Document::"budget-2026"
);
```

### Rego — example policy

Identity comes from the cascade like any other language (an alias marker if
the family defines one; otherwise carried by path, or derived from the
bytes). Fail-closed by construction: `default allow := false`.

```rego
package documents

import rego.v1

default allow := false

allow if {
    input.subject.type == "user"
    input.action.name == "read"
    input.subject.id in data.documents.readers[input.resource.id]
}
```

Same ledger rules for both: the partition declares which family it accepts,
the runtime pins language and engine ranges, and the profile on top stays
identical — a `permguard.pdp.v1` consumer cannot tell which language answered.

### Plugins are built in, never loaded

Normative, and a supply-chain decision: language plugins (validator + engine
per family) are **compiled into the binaries** — a Rust trait implemented at
build time — never loaded at runtime as shared libraries or external
processes.

| Loaded at runtime would mean | Built in means |
| --- | --- |
| a writable path on the volume is executable code — anyone who can drop a file can inject an engine | the engine set is fixed at build: what evaluates policy is exactly what was reviewed, signed and shipped |
| the engine version the manifest gate checks can be swapped underneath it | the version the gate checks **is** the binary's, attested by the release (image digest, cosign) |
| a plugin ABI to keep stable and sandbox | one compiler, one audit surface, one release pipeline |

Adding a language is therefore a **build**, not a deployment action: a new
trait implementation, a new registered media-type family, a new release —
through the same review, signing and provenance every release gets.

## Version semantics

Constraints follow **semver ranges**, with a deliberately closed grammar —
exactly these three forms, nothing else (`^`, `~`, `*` mean different things
in different ecosystems and are refused):

| Constraint | Meaning | Matches | Does not match |
| --- | --- | --- | --- |
| `>=0.0.0` | any version | `0.1.0`, `1.0.0`, `2.3.1` | — |
| `>=1.0.0` | 1.0.0 upward | `1.0.0`, `1.5.2`, `2.0.0` | `0.9.9` |
| `>=1.0.0 <2.0.0` | the 1.x range | `1.0.0`, `1.9.9` | `0.9.9`, `2.0.0` |
| `1.2.3` | exactly 1.2.3 | `1.2.3` | `1.2.4`, `1.3.0` |

### Three versions, three different things

| Version of… | Constrains… | Declared in… |
| --- | --- | --- |
| **Language** (e.g. Cedar 4.x) | what the policy *sources mean* — syntax and semantics they were authored against | `runtimes.<key>.language` |
| **Engine / plugin** (e.g. permguard-cedar 0.1.x) | what may *evaluate* them — the implementation, with its own bugs and behaviours | `runtimes.<key>.engine` |
| **Server** (Permguard 0.1.0) | nothing here — the server hosts plugins; its version is discovery/ops material (`/version`), never a manifest constraint | — |

Language and engine are **independent** constraints on purpose: a new engine
build can fix a bug without the language moving, and a language revision can
land while the engine range stays put.

### The load gate — fail-closed, security-relevant

```text
consumer starts / syncs a ledger
        │
        ▼
read manifest ──► for each runtime:
        │           my language plugin  satisfies language.constraint ?
        │           my engine version   satisfies engine.constraint ?
        ▼
   both yes ──► load, serve, evaluate
   any no  ──► REFUSE: the ledger is `unavailable`
               (never evaluate best-effort)
```

Every consumer runs it: the **data plane** before evaluating, the **control
plane** at commit validation, the **CLI** when building. Re-checked on every
load and sync — a ledger that raises its constraint must make an old engine
*stop serving it*, not keep answering with the last semantics it understood.
An engine outside the declared range interpreting the same policies
differently is a silent authorization bypass; the only safe answer is
`unavailable`.

## Profiles — a contract, not a language

A profile fixes **how a consumer asks for and receives decisions**, whatever
languages the partitions underneath speak: subject / action / resource /
context in, a decision out.

| Profile type | Contract | Status |
| --- | --- | --- |
| `permguard.pdp.v1` | **Implements and extends OpenID AuthZEN 1.0** — the standard evaluation API, plus Permguard capabilities (below) | first |
| `permguard.trust-anchor.v1` | the same contract with signed, non-repudiable decisions (the data plane's ring at `keys/data` signs them) | later |

The profile id is **ours** — our namespace, our versioning cadence. What it
serves is the standard: a plain AuthZEN PEP talks to it without knowing what
Permguard is; a Permguard-aware PEP gets the extensions.

## The `permguard.pdp.v1` contract

**Lineage, stated plainly: we start from the OpenID AuthZEN Authorization
API 1.0 and build a custom Permguard profile on top of it.** The base is the
standard, implemented per ledger; the profile adds Permguard capabilities
and deliberately does **not** implement the Search APIs (§8 of the standard)
— per the standard's own rules, their absence from the metadata document is
the declaration.

Extension is what the standard itself provides for — extra parameters are ignored by
receivers that do not know them, and declared via the `capabilities` array of
the PDP metadata document.

**Scoping is the payload, not the URL.** One address answers for every ledger
the plane holds, and `zone` and `ledger` are **required fields of the
request**:

```text
/.well-known/authzen-configuration   PDP metadata
/access/v1/evaluation                one check
/access/v1/evaluations               boxcarred checks
```

The reason is operational. A PEP that enforces across several ledgers keeps
**one** endpoint, one connection pool and one piece of configuration; the
ledger becomes data, which is what makes a request loggable, auditable and
replayable as one record. It also means a caller can move a check from one
ledger to another without redeploying a URL.

The trade is stated plainly: this is the one place where the profile departs
from the standard's assumption that the store is the address. So the
divergence is declared where a PEP looks — the metadata document carries
`urn:permguard:authzen:store-in-payload` in its `capabilities` — and a payload
that names **neither** is refused with `400`, never answered against a
default. Deciding against the wrong policy store is the one failure mode
nobody can debug afterwards.

Both `zone` and `ledger` accept the **name** or the **identity**: a PEP
configured with either works, and a rename on the control plane does not
break a deployment that used identities.

Search endpoints are not served; per the standard, their absence from the
metadata document is how a PEP learns that.

### Permguard extensions (declared capabilities)

| Extension | Where | Meaning |
| --- | --- | --- |
| `entities` | request body | `{schema, items[]}` — the entity graph the evaluation runs against, in the runtime's schema |
| `principal` | request body | who is *asking* (`type`, `id`, `source?`, tokens) — may differ from the subject |
| structured reasons | response `context` | `id` + `reason_admin`/`reason_user` — correlation with the audit trail and the disclosure split the whole server speaks |

Request (standard shape; the store, and the extensions, in place):

```json
{
  "zone":     "acme",
  "ledger":   "main-ledger",
  "profile":  "default",
  "subject":  { "type": "user", "id": "alice@acme.com" },
  "resource": { "type": "document", "id": "budget-2026" },
  "action":   { "name": "read" },
  "context":  { "time": "2026-08-23T10:00:00Z" },
  "principal": { "type": "user", "id": "alice@acme.com" },
  "entities":  { "schema": "cedar", "items": [ ] },
  "evaluations": [
    { "action": { "name": "read" } },
    { "action": { "name": "delete" } }
  ]
}
```

Response:

```json
{
  "decision": false,
  "context": {
    "id": "83628…",
    "reason_admin": { "code": "403", "message": "Request failed policy 7f3a9c21-…" },
    "reason_user":  { "code": "403", "message": "Insufficient privileges" }
  },
  "evaluations": [
    { "decision": true },
    { "decision": false, "context": { } }
  ]
}
```

### Request fields

| Field | Required | Meaning |
| --- | --- | --- |
| `zone` | ✔ | which zone, by name or identity. No default |
| `ledger` | ✔ | which ledger of it, by name or identity. No default |
| `profile` | — | which of the ledger's profiles to evaluate. `default` when absent |
| `subject` | ✔* | `{type, id, properties?}` — whom the decision is about |
| `resource` | ✔* | `{type, id, properties?}` — what it targets |
| `action` | ✔* | `{name, properties?}` — the operation |
| `context` | — | environmental attributes (time, ip, …) |
| `evaluations[]` | — | boxcarred checks; each may override `subject`/`resource`/`action`/`context` |
| `principal` *(extension)* | — | who is asking — may differ from the subject |
| `entities` *(extension)* | — | the entity graph, in the runtime's schema |

\* required at the top level **or** in every evaluation — top-level values
are the defaults each evaluation inherits (see Contract semantics).

### Response fields

| Field | Meaning |
| --- | --- |
| `decision` | The boolean verdict — `false` also covers every error (fail-closed) |
| `request_id` | Echoed from the request, per evaluation and top-level |
| `context.id` | The decision's own identifier, for correlation with the audit trail |
| `context.reason_admin` | `{code, message}` — the full explanation, operator material |
| `context.reason_user` | `{code, message}` — the safe explanation, caller material |
| `evaluations[]` | One `{decision, request_id?, context?}` per boxcarred check, same order |

The rules the contract keeps, whatever the language underneath:

| Rule | Meaning |
| --- | --- |
| Decisions are boolean | `true` permit, `false` deny — deny is a `200` with `decision: false`, never a transport error |
| Fail-closed | any evaluation error is a deny, with the error in that evaluation's context |
| Two audiences | `reason_admin` (full) vs `reason_user` (safe) — the disclosure split the whole server already speaks |
| Policies are cited by id | reasons name `permguard.policy.id`, the identity that survives renames — audit stays whole |
| Boxcarring | top-level fields are defaults; each evaluation overrides what it declares |

### Contract semantics

Normative, self-contained — everything an implementer needs is here.

**Decisions and errors**

| Rule | Semantics |
| --- | --- |
| A decision is a boolean | `true` permit, `false` deny — nothing in between |
| Deny is an answer, not an error | HTTP `200` with `decision: false`. Transport errors (`400` bad request, `401`/`403` authentication, `500` fault) mean the request could not be evaluated — they are never a decision |
| Fail-closed | any evaluation error yields `decision: false`, with the error inside that evaluation's `context` |
| Required fields missing | `400` — `zone` and `ledger` always; `subject`, `resource`, `action` at the top level or in every evaluation |
| The ledger is not served here | `404` — this plane does not mirror it. Not a deny: a PEP has to tell "no" from "ask somebody else" |
| The ledger cannot be evaluated | `503` — no history yet, an engine outside the manifest's range, or a damaged mirror |
| More evaluations than the plane accepts | `400` — `authz.max_evaluations` bounds a batch, so a hostile payload cannot stall a worker |

**Boxcarring (multiple evaluations in one request)**

| Rule | Semantics |
| --- | --- |
| Defaults | top-level `subject`, `resource`, `action`, `context` are the defaults every entry of `evaluations[]` inherits; each entry overrides what it declares |
| Order | responses come back in the same order as the requests |
| Independence | evaluations are independent; the server may run them sequentially or in parallel |

`options.evaluations_semantic` selects how the batch resolves:

| Value | Behaviour |
| --- | --- |
| `execute_all` *(default)* | run every evaluation, return every result |
| `deny_on_first_deny` | stop at the first `false` (or error) — the `&&` of evaluations |
| `permit_on_first_permit` | stop at the first `true` — the `||` of evaluations |

**Transport**

| Rule | Semantics |
| --- | --- |
| `X-Request-ID` | when the caller sends it, the response echoes it verbatim; per-evaluation `request_id` echoes in its evaluation's response |
| Unknown fields | receivers ignore them — forward compatibility is the reader's duty, never the writer's |
| Payloads | UTF-8 JSON; numbers within IEEE 754 double precision; `null`-valued fields omitted rather than sent |

**Identity in answers**

| Rule | Semantics |
| --- | --- |
| Policies are cited by id | reasons name `permguard.policy.id` — the identity that survives renames, so audit stays whole (reports may show `alias (id)`) |
| Two audiences | `reason_admin` carries the full explanation, `reason_user` the safe one — the disclosure split the whole server speaks |
| Correlation | `context.id` is the decision's own identifier, matching the audit trail record |

**How partitions combine.** A profile may name several partitions, in
different languages. Across them: an **explicit** deny (a Cedar `forbid` that
matched, a Rego `deny` rule that held) wins; otherwise a permit permits;
otherwise the answer is no, because absent means no. An evaluation error is a
deny carrying its reason — never a permit, and never a transport fault.

Search/discovery APIs are out of scope for this profile.

## Where things are enforced

| Check | Enforced by | When |
| --- | --- | --- |
| Manifest structure, canonical CBOR | media-type validator | ingest of the blob |
| `kind` vs media-type families, partitions 1:1, media types per partition | commit acceptance invariants | push commit |
| Runtime constraints (language + engine) | every consumer's load gate | every load and sync |
| Schema satisfaction (every policy type-checks) | the language's compiler, at load | when a partition declares `schema: true` |
| — the same check at **authoring** and at **commit** | one implementation, three places: `permguard validate` runs it on the sources, the control plane runs it at commit acceptance (`schema_unsatisfied`), and the data plane's load gate runs it last | a policy that does not satisfy its partition's schema fails `validate` first, is refused at push second, and can no longer turn into a `503` at every plane serving the ledger. A partition that declares `schema: true` and carries no schema is refused the same way (`schema_missing`) |
| Profile contract | the data plane surface serving it | every request |
