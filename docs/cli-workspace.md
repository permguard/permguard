<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The CLI workspace

How policies are authored locally and exchanged with a remote ledger.
Status: **implemented** — the CLI's `engine` module (sync + authoring), and the
commands over it, and the [pdp-lab](../pdp-lab/README.md) walkthrough.
Companion of the [git-like storage specification](gitlike-object-model.md)
and [Profiles & Manifest](profiles-manifest.md).

## Principles

| Principle | Consequence |
| --- | --- |
| **Policies are versioned, not files** | The unit of content is one policy. Ten policies in one file or in ten files produce the **same objects** — files are the author's presentation, policies are the content |
| **One engine of truth** | Sync (Remote contract, local mirror, signed-head verification, the pull cycle) and authoring (sources, manifest, plan/apply, materialization) both live in the CLI's `engine` module — the CLI is the one synchronizer, because it is the thing that holds remotes, credentials and TLS. A crate exists only where a second consumer does |
| **The data plane never syncs itself** | A sidecar runs `permguard pull` onto a volume; the PDP serves from that volume with **no egress and no credentials** — it re-verifies hashes with `permguard-objects` and needs nothing else. Freshness is the sidecar's interval; provenance was proven at pull time and is re-provable offline |
| **Storage is a trait** | Both crates work against one storage trait: the CLI passes the filesystem implementation rooted at a workspace, the data plane one rooted at its volume, a browser one backed by its own storage. No `std::fs` outside the implementation |
| **Local names never clash with remote ones** | The local working copy is a **workspace**. "Ledger" always means the remote container — one word, one meaning |
| **Simple over clever** | Learned from the Go CLI: no state machines where a function does, no duplicated staging trees, no second copy of anything the object store already holds |

```text
        permguard-objects         what the objects are
             │                │
   CLI (engine module:    data plane          control plane
   sync + authoring)      reads the volume    (engine + store
        │ writes               │ serves        modules: the
        └──── shared volume ───┘               server half)
             (sidecar pattern)
```

## Engines, built in

| Language | Engine crate | Pinned |
| --- | --- | --- |
| Cedar | `cedar-policy` (official) | `4.12.x` |
| Rego | `regorus` (Microsoft) | `0.11.x` |

Compiled in, never loaded — see
[Plugins are built in, never loaded](profiles-manifest.md). Adding a language
is a build, not a deployment action.

## Referencing a server

```bash
permguard remote add origin https://permguard.acme.com        # scheme decides transport+TLS
permguard remote add origin grpcs://pdp.internal:7556         # https|http|grpcs|grpc
permguard clone https://permguard.acme.com/acme/main-ledger # last two segments: zone/ledger
```

References are `<remote>/<zone>/<ledger>[@<ref>]`; zone and ledger accept
**name or GUID** (the Selector rule of every surface); `@ref` defaults to the
ledger's default ref. On `remote add`, the CLI verifies the URL before
remembering it — over HTTP by reading `/.well-known/server-configuration`,
over gRPC by calling `GetServerConfiguration` (the same document). **The
scheme is the transport**: `http`/`https` ride the HTTP surface, `grpc`/`grpcs`
ride tonic — same server, same facade, one URL says which door. A server that
exposes only gRPC is a first-class citizen: every command, workspace and
admin alike, works against it. The discovery document says what a plane
exposes (`"transports":{"http":…,"grpc":…}`).

## The workspace on disk

```text
my-policies/
├── manifest.yml            # the manifest — MANDATORY, one per workspace
│                           #   (permguard.yml stays reserved for future
│                           #    workspace-level Permguard configuration)
├── app/                    #   ┐ directories = partitions,
│   ├── billing.cedar       #   │ exactly as the manifest declares them
│   └── schema.cedarschema  #   │
├── gateway/                #   │
│   └── routes.rego         #   ┘
├── .permguardignore        # what refresh never reads
└── .permguard/             # the workspace's own state — never edited by hand
    ├── config              # TOML: remotes, the tracked ledger, format version
    ├── HEAD                # the current ref, e.g. refs/main
    ├── lock                # present only while a mutating command runs
    ├── refs/               # per ref: remote head digest + counter — the
    │   └── main            #   rollback/equivocation checkpoint, persisted
    ├── objects/            # local object store — same format (zlib at rest,
    │   └── ab/cdef…        #   digest-fanout), same crate as the server's
    └── staging/
        └── tree            # the last built snapshot (digest), plan's input
```

Two guards keep concurrent and cross-version use boring:

- **One mutating command at a time.** Mutating commands take `.permguard/lock`
  (git's `index.lock` discipline: exclusive create, removed on exit). A second
  terminal is refused, told who holds it, and told exactly what to remove if
  the holder crashed. Read-only commands (`history`, `objects`, `verify`)
  never take it. On the server the same story needs no file: pushes serialize
  on the ref's compare-and-swap, pulls never wait.
- **The layout is version-gated.** `version` in `.permguard/config` pins the
  layout (v2: objects zlib-compressed at rest). A workspace written by a
  different layout is refused with both versions and the way out — use a
  matching CLI, or re-clone — never half-read.

What changed from the Go `.permguard`, and why:

| Go | Here | Why |
| --- | --- | --- |
| `code/@workspace` + `code/objs` staging copies | gone — `objects/` is the only store, staging is one digest | the object store *is* content-addressed; a second tree of copies is drift waiting to happen |
| `logs/` directory | gone — `history` walks commits | the DAG already is the log |
| remote = server + 2 ports + scheme | remote = **one URL** | HTTP and gRPC share the port; TLS is the scheme |
| zone id `int64` | zone name-or-GUID | the Rust identity model |
| refs without counters | refs persist `(digest, counter)` | the signed-head checkpoint: rollback and equivocation are detected locally |
| manifest optional-ish | `manifest.yml` **mandatory** | no manifest → `validate`, `plan`, `apply` all refuse; `init` always writes one |

### `.permguard/config`

```toml
version = 2

[remotes.origin]
url = "https://permguard.acme.com"
# tls-ca-file = "corp-ca.pem"          # per-remote trust, like docker registries

[ledger]
remote = "origin"
zone   = "acme"                       # name or GUID, as given
ledger = "main-ledger"
```

### `.permguard/refs/main`

```json
{"head":"sha256:41f6c990…","counter":42}
```

The client-side checkpoint of the specification: pulls verify the signed head
statement against the key ring, then apply the `(counter, digest)` table —
rollback and equivocation reject **locally**, and the checkpoint only
advances when the full closure is present and verified.

## The manifest is mandatory

`manifest.yml` **or** `manifest.yaml` at the workspace root — the same
manifest of [Profiles & Manifest](profiles-manifest.md), authored as YAML,
stored as the canonical CBOR blob at the root entry `manifest` on push.

| File rule | Behaviour |
| --- | --- |
| `init` creates | `manifest.yml` (the default) |
| Either extension | accepted — `.yml` or `.yaml`, the content is what matters |
| **Both present** | error, everywhere (`validate`, `plan`, `apply`, `pull`): two manifests is ambiguity, nobody guesses which one rules |
| Pull would materialize the other extension | both files end up on disk and the workspace errors — resolved by hand, deleting one; the CLI never picks silently |
| Push without a manifest | error — **every** push verifies it, every time |

```yaml
metadata:
  kind: policy
  name: acme-authz
runtimes:
  cedar:
    language: { name: cedar,     constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
  rego:
    language: { name: rego,      constraint: ">=1.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
partitions:
  app:     { runtime: cedar, schema: true }
  gateway: { runtime: rego,  schema: false }
profiles:
  default: { type: permguard.pdp.v1, partitions: [app, gateway] }
```

| Rule | Enforced by |
| --- | --- |
| No manifest → error | `validate`, `plan`, `apply` refuse; `init` always creates one; **and the server refuses the commit independently** |
| **One** manifest per snapshot | it is the root entry `manifest`, and `Commit.manifest` must equal it — a second one anywhere is just a blob nobody points at; partitions cannot carry one of their own kind |
| Directories ⟷ partitions 1:1 | `validate` — a directory not declared, or a declared partition without a directory, rejects |
| Runtime constraints | the load gate — the CLI refuses to build with engines outside the declared ranges |

## Policies, not files

`refresh` reads the partition directories, parses every source with the
partition's engine, and extracts **each policy as its own object**:

```text
app/billing.cedar          tree entries (what is versioned)
┌──────────────────────┐   ┌────────────────────────────────────┐
│ @alias("billing-ro") │──►│ billing-ro        id: 7f3a9c21-…   │
│ permit ( … );        │   │                                    │
│                      │   │                                    │
│ permit ( … );        │──►│ 9c41aa02-…        id: 9c41aa02-…   │
└──────────────────────┘   └────────────────────────────────────┘
     one file                    two policies, two blobs
```

- **Entry name** = the alias when declared, the derived id otherwise. The
  local file name is *yours*; the canonical name is the policy's.
- Identity follows the cascade of the specification: carried by path, then
  by alias, else derived from the bytes — computed by the crate, verified by
  the server.
- **Alias markers per language**:

```cedar
@alias("billing-ro")
permit (principal in Group::"finance", action == Action::"read", resource);
```

```rego
# METADATA
# custom:
#   alias: gateway-routes
package gateway.routes
import rego.v1
default allow := false
```

(Rego has no bespoke syntax; the standard OPA `# METADATA` annotation block
carries it under `custom.alias`. A language with no marker simply never
declares aliases.)

- **Pull materializes only what is missing**: a policy already present in
  *some* local file (matched by id) is left exactly where the author keeps
  it; every policy the workspace lacks becomes **one new file** named after
  its alias (or id) inside its partition directory. Your file organization
  survives every pull.
- **Folders nest, and they round-trip.** A partition is the directory named
  after it — always, no custom mapping: convention, not configuration.
  Inside it, subdirectories become subtrees (a Rego package tree keeps its
  shape), directory names obey the entry-name grammar, and a clone rebuilds
  the exact folder structure — same folders, same root digest.
- **Schemas: one per partition, at most.** `schema: true` requires the
  partition's language to *have* a schema (Cedar does — `.cedarschema`;
  Rego does not, and `schema: true` on a Rego partition rejects). Two schema
  files in one partition is the same ambiguity as two manifests: refused,
  naming every file — and the server re-checks both rules at commit.
- **Duplicates are ambiguity, and ambiguity rejects**: the same alias
  declared twice — in one file or across files — and the same policy (same
  id) present in two local files both fail `validate`, naming every path
  involved. One policy, one place.

## Commands

| Command | What it does | Touches network |
| --- | --- | --- |
| `init` | create `manifest.yml` + `.permguard/`; `--language cedar,rego` (default `cedar`, override in config) — unsupported language = error | no |
| `remote add/list/remove` | manage named server URLs (verified via discovery) | verify only |
| `clone <url>` | fetch a ledger into a fresh workspace: full pull + checkout | yes |
| `checkout <remote>/<zone>/<ledger>[@ref]` | bind this workspace to a ledger and materialize it | yes |
| `pull` | fetch the delta, verify statement + closure, advance the checkpoint, materialize missing policies | yes |
| `refresh` | parse sources → build the local snapshot (objects + staging tree) | no |
| `validate` | refresh + every local check: manifest, partitions, identities, per-blob validation, and the set-level semantic check — every policy against its partition's schema, the same check the server runs at commit acceptance and the data plane at load | no |
| `plan` | validate + diff staging tree against the remote head: create/update/delete per policy | fetch head |
| `apply` | plan + NOTP push (negotiate → upload missing → commit CAS) | yes |
| `history` | walk the commit DAG of the current ref | no |
| `status` | the workspace at a glance: tracked ledger, ref and checkpoint, pending change counts — `.permguard` read for you | no |
| `objects` | inspect the local store: `list [--tracked\|--staged]` situates every object; `cat` has four views — content (blob default), `--raw`, `--inspect` (typed, tri-format), `--human` | no |

**Validation is double, always.** Everything the workspace checks —
manifest well-formed against its grammar, canonical encoding, commit / tree /
tree-entry / blob structure, identities, partitions — the **server re-checks
on receive**, independently, fail-closed: nothing that fails schema or
validation is ever stored. The client validates to fail fast with good
errors; the server validates because it trusts nobody.

Each command is the previous plus one step — `apply` ⊃ `plan` ⊃ `validate` ⊃
`refresh` — so there is exactly one code path, exercised at four depths.

## Flows

### Author, from zero to applied (Cedar + Rego)

```bash
permguard init --language cedar,rego
#   creates manifest.yml (two runtimes), app/ gateway/, .permguard/

vi app/billing.cedar gateway/routes.rego

permguard remote add origin https://permguard.acme.com
permguard checkout origin/acme/main-ledger

permguard plan
#   + billing-ro       (app,     cedar)  7f3a9c21-…
#   + gateway-routes   (gateway, rego)   1b9e6f04-…
#   Plan: 2 to create, 0 to update, 0 to delete (0 unchanged).

permguard apply
#   pushed refs/main: counter 1 → 2, head sha256:41f6c990…
```

### Somebody else pushed — converge

```bash
permguard pull
#   verified head statement (kid 2026-08-srv-1), counter 42 → 43
#   1 new policy: rate-limit (gateway) → gateway/rate-limit.rego
#   your files: untouched
```

### The edit loop

```bash
vi app/billing.cedar          # edit the policy in place
permguard plan
#   ~ billing-ro: update (id unchanged — carried by path)
permguard apply
```

### The rename that keeps identity

```bash
mv app/billing.cedar app/billing-readonly.cedar
permguard plan
#   ~ billing-ro: unchanged (id carried by alias)
```

## Failure behaviour

| Situation | Behaviour |
| --- | --- |
| No manifest file | `validate/plan/apply` refuse with the paths expected (`manifest.yml` or `manifest.yaml`) |
| Both `manifest.yml` and `manifest.yaml` | refuse everywhere — ambiguity is never resolved silently |
| Unsupported language at `init` | error listing the built-in languages |
| Engine outside the manifest range | refuse to build/evaluate — `unavailable`, never best-effort |
| Ref moved between plan and apply | NOTP CAS answers `conflict`; `apply` says it plainly: run `permguard pull`, review, apply again |
| Second command on the same workspace | refused by `.permguard/lock`, naming the holder; remove the file only if it crashed |
| `.permguard` written by another CLI version | refused, naming both layout versions; use a matching CLI or re-clone |
| Interrupted pull | objects persisted incrementally; checkpoint **not** advanced; re-pull sends only what is still missing |
| Same alias declared twice (any two files) | `validate` rejects, naming both paths |
| Same policy (same id) in two local files | `validate` rejects, naming both paths — one policy, one place |

## Future-proof, by construction

| Future | Already accommodated |
| --- | --- |
| Branching | `HEAD` + `refs/<name>` are already plural; `checkout @ref` exists; branch creation is a free NOTP push (spec) |
| Forking | a fork is a ref — same objects, shared by digest |
| New languages | a new engine in the build + a runtime entry in the manifest; the workspace format does not change |
| Browser | a `WorkspaceStore` implementation over browser storage; the crate is already the whole logic |
| Extending | additive only: new TOML keys, new manifest fields (unknown ones rejected server-side by schema version, tolerated client-side per format version) — never breaking |
