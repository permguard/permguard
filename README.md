<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permguard

[![ci](https://github.com/permguard/permguard/actions/workflows/ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/permguard/main/assets/readme/hero.png?v=2" alt="Permguard. Policy as code. Decisions as evidence. Authorization policy, versioned like code and shipped like code." width="820">
</p>

<p align="center">
  <a href="https://permguard.com"><b>Website</b></a> ·
  <a href="https://docs.permguard.com/"><b>Documentation</b></a> ·
  <a href="#five-minutes"><b>Five minutes</b></a> ·
  <a href="https://github.com/permguard/soglia"><b>Soglia</b></a>
</p>

**Authorization policy, versioned like code and shipped like code.**

Permguard keeps your policies in a content-addressed, Git-like ledger.
It distributes signed versions over a protocol built for it, and answers *can this subject do this to this?* either from its own Data Plane, or from **inside your process, at zero network cost**.
Every answer names the exact policies and commit that decided it, and can be kept as signed evidence.

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/permguard/main/assets/readme/flow.png" alt="Five steps. Author: Cedar and Rego, tested offline with permguard test. Publish: content-addressed, under a signed head, with permguard apply. Mirror: the Data Plane verifies it first, over NOTP. Decide: near the workload, failing closed, with permguard check. Prove: every answer names its policies, with permguard decisions. Author once, decide close to the workload." width="820">
</p>

You write policy in a workspace, test it offline, and `apply` it like code.
The Control Plane keeps it as an immutable commit under a signed head.
Every Data Plane mirrors it, verifies the head before using it, and decides next to the workload.
When nothing permits, the answer is deny, and every answer leaves evidence you can verify later.

## One Server, independent planes

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/permguard/main/assets/readme/server.png" alt="A Permguard Server is one Host and zero or more planes. The Host, on 5443 for discovery, health and metrics and 5444 for the Host API over TLS, owns identity, authorization, keys, audit, membership, streams, storage and lifecycle. Through typed, least-privilege handles it serves the Control Plane on 6443, which publishes, the Data Plane on 7443, which decides, and the Trust Plane on 8443, which will continue authority and is in development. Deploy all-in-one, one process with every enabled plane, or split by plane, one Host per plane with its own volume." width="820">
</p>

A **Permguard Server** is one process with exactly one **Host** and zero or more **planes**.
The Host owns trust and operations: identity, authentication and authorization, keys and secrets, audit, membership, streams, storage and lifecycle.
A plane owns one business domain, and receives typed, least-privilege handles from the Host instead of building its own key manager, audit trail or persistence path.

| Role                   |   Port | What it does                                                   | Status         |
| ---------------------- | -----: | -------------------------------------------------------------- | -------------- |
| Server Host operations | `5443` | discovery, health, readiness, version and metrics              | available      |
| Host listener          | `5444` | the Host API (`/host/v1` and `permguard.host.v1`), over TLS    | available      |
| Control Plane          | `6443` | zones, ledgers, signed heads, NOTP, decision and event stores  | available      |
| Data Plane             | `7443` | mirror, verify, compile, evaluate, record decisions            | available      |
| Trust Plane            | `8443` | Trust Anchors and authority continuity with PIC; port reserved | in development |

The role owns the port.
HTTP and gRPC share it, and TLS changes the scheme, never the number.
Run every plane in one process, or split them so that each Host serves one plane and owns its own volume.
Containers and pods have their own network namespaces; standalone binaries that share one should bind different IP addresses rather than change a role's port.

<details>
<summary><b>What the Host owns, and why it matters</b></summary>

- **Identity.** A stable `host_id`, proof of possession, succession and rotation, kept in signed key rings.
- **Authorization.** Grants per principal, operation and resource selector; absence of an allow is deny.
- **Keys and secrets.** Rings per purpose, published ahead of use, rotated and retained; custody in files, an HSM or a KMS.
- **Audit.** Trails per class and resource, hash-chained, with signed checkpoints.
- **Membership.** Host-to-Host trust is direct, never transitive: every remote action names one membership, task, scope and epoch.
- **Streams.** Decisions and events leave as signed, ordered batches with acknowledgements, retention and recovery.
- **Storage and lifecycle.** Files are the canonical backend, with one writer per volume, fsync ordering, application-consistent backup and offline restore.
- **Assurance.** A deployment declares `development`, `production` or `regulated`, and publishes every relaxation it takes.

A Data Plane that mirrors from another Server reaches its Control Plane through an authenticated Host task session, not through an anonymous plane-to-plane call.

</details>

## Where decisions run

<p align="center">
  <img src="https://raw.githubusercontent.com/permguard/permguard/main/assets/readme/where.png" alt="Three places to decide. The Permguard Data Plane, as a sidecar or remote service over HTTP and gRPC, the secure default. Your own data plane, embedded or at the edge, consuming the same signed ledger over NOTP and verifying it before use. Offline in the CLI, with permguard test and no server. One signed ledger, the same engines, the same answer." width="820">
</p>

**Bring your own data plane.**
The objects are self-describing and the engines are a library.
Run Permguard's Data Plane, or pull the ledger and evaluate **in your own process**: no PDP hop, no network on the decision path, the same manifest, the same engines, the same answer.
`permguard test` is that path in the CLI: it decides a workspace off disk, before anything is pushed anywhere.

## Why this is not another policy server

**Policy is a repository, not a blob.**
`init`, `validate`, `plan`, `apply`, `pull`, `history`: a workspace on disk, with commits, trees and blobs, all content-addressed.
A decision does not cite "the policy that was live"; it cites the **exact commit** and the **identity of the policy** that decided, and those identities survive a rename.
You can check out the state a decision was made against, months later, and ask the question again.

**One question, many engines.**
A ledger holds **partitions**, Cedar here and Rego there, and a **profile** says which of them answer.
`admin` consults the org chart *and* the guardrails; `pipeline` consults the rules for machines and loads nothing else.
An explicit deny from any partition beats a permit from another, so "who is entitled" and "is it safe right now" can be written by different people, in different languages, and still compose.

**NOTP, not "an API".**
Policy distribution is content-addressed transfer with negotiation: send what the other side is missing, and nothing else, over HTTP or gRPC, with a **signed head** at the end of it.
A Data Plane refuses a ledger whose head it cannot verify, and refuses one whose engine range it is outside.
An engine interpreting the same policies differently is a silent authorization bypass, not a compatibility note.

**Decisions are evidence.**
Every decision can be recorded with the commit, the policy identity, the reason, and **keyed commitments** over what the caller supplied: proof of the inputs without keeping them.
The record is durable on the plane's volume before the answer is given, shipped to the Control Plane as signed, hash-chained batches, and verifiable afterwards by somebody who does not trust the plane that wrote it.
A caller can also ask for the response itself to be signed.

**An interface Permguard owns.**
`permguard.api.pdp.native.v1` is Permguard's native policy decision interface, designed for profile-based decisions evaluated across one or more heterogeneous policy partitions.
It is not an implementation of, nor a compatibility claim for, anybody else's authorization API.
The shape will look familiar, a subject, an action, a resource and a context in, a decision and a reason out, because that is the obvious shape for the question.
What owning it buys is that the parts nobody else specifies are specified *here*, in [`crates/permguard-languages/src/request.rs`](crates/permguard-languages/src/request.rs), and can change when Permguard needs them to.

### Supported policy languages

| Language                                                     | Runtime                             | Decides from                          | Status       |
| ------------------------------------------------------------ | ----------------------------------- | ------------------------------------- | ------------ |
| [Cedar](https://www.cedarpolicy.com)                         | `cedar` (`cedar-policy` 4.x)        | the request                           | stable       |
| [Rego](https://www.openpolicyagent.org/docs/policy-language) | `rego` (`regorus`)                  | the request                           | stable       |
| [Dogwood](https://github.com/dogwood-policy/dogwood)         | `dogwood` (`amzn-dogwood-language`) | the request **and** a durable history | experimental |

A language is a **build**, not a deployment action: all three are compiled in.
What a deployment chooses is whether a ledger naming a runtime will be *served*, and the experimental one is gated.

<details>
<summary><b>Experimental: Dogwood, and deciding from what has happened</b></summary>

Cedar and Rego answer *may this subject do this to this?* from the request in front of them.
[Dogwood](https://github.com/dogwood-policy/dogwood) is Cedar plus **history**: a policy may ask what has happened recently, with `formerly`, `since` and aggregations over a window, as well as what is being asked now.

```cedar
@id("read_only_after_login")
permit (principal, action == Drupe::Action::"Read", resource)
when temporal {
  formerly within 1h Drupe::Action::"Login"::response{ input.user: context.input.user }
};
```

Answering that takes a durable history, so Dogwood is served through a second interface, `permguard.api.pdp.temporal.v1alpha1`.
An occurrence is recorded into a hash-chained journal, made durable, observed, and only then decided against.
Upstream supplies the language, its lowering to Cedar, validation and the per-request authorizer, and is explicit that its included interpreter is a **reference** implementation rather than a production one.
Permguard supplies what a deployment needs around it: the policy lifecycle, multi-tenancy, a durable and bounded event history, provenance, replication, limits and operational safety.

It is **experimental**, and gated by two switches that must both be set:

```yaml
experimental:
  dogwood:
    enabled: "true"        # this deployment accepts a contract that is not yet stable

dataPlane:
  events:
    enabled: "true"        # this plane keeps a durable event history, on the Host's stream
```

Setting one and not the other refuses to start, by name.
`v1alpha1` is honest: the wire and replication shapes may still change, and the switch is what makes accepting that a decision rather than a default that moved.

Working configurations ship as `config.local-experimental.yml` beside each server crate.
[`examples/dogwood-session-access`](examples/dogwood-session-access) is a whole ledger: schemas, policies, and a test that asserts the verdicts its README claims.
The contract is documented under [Temporal Authorization](https://docs.permguard.com/how-it-works/temporal-authorization).

</details>

## Install

```sh
brew install permguard/tap/cli
permguard --help
```

<details>
<summary>From this checkout instead</summary>

```sh
cargo install --path crates/permguard-cli --bin permguard --force
export PATH="$HOME/.cargo/bin:$PATH"
```

It needs Rust `1.97`+, `cargo`, and `task` or `make`.
Docker Compose runs the observability lab, `jq` the JSON examples, and `k6` only the load tests.

</details>

<details>
<summary>Verify a release before running it</summary>

Every archive, package and image of a release carries SLSA Build L3 provenance from one builder, the reusable workflow `.github/workflows/release-build.yml`.
A release is published only after the provenance of every file names that builder and the tagged commit as the source; images are verified the same way as soon as they are pushed.
Check a download against the same policy, naming the commit the tag pointed at when it was released (`provenance-files.txt` in the release names it): a tag can be moved, a commit digest cannot.

```sh
gh attestation verify permguard_cli_Linux_x86_64.tar.gz \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
  --source-ref refs/tags/v<version> \
  --source-digest <commit> \
  --deny-self-hosted-runners
gh attestation verify oci://ghcr.io/permguard/permguard/data-plane:<version> \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
  --source-ref refs/tags/v<version> \
  --source-digest <commit> \
  --deny-self-hosted-runners
```

Releases up to `0.1.6` were attested by `release-pipeline.yml`; name that file as `--signer-workflow` to verify them.
`provenance-files.txt` and `provenance-images.txt` in the release list the builder and source of every artifact.
`reproducibility.txt` holds the verdict of an independent rebuild of the Linux and Windows binaries; a release claims to be reproducible only when it ends with `reproducible: yes`.
For container images, see [ops/container-verification.md](ops/container-verification.md).

</details>

## Ask a Server what it hosts

Nothing is agreed out of band.
A client is handed **one Server Host URL** and reads the rest off it: which planes are present, where to push policy, where to ask for a decision, which keys sign what, and what each interface offers.
All the endpoints below are up after `task run:all`, the first command of [Five minutes](#five-minutes); `permguard discover http://127.0.0.1:5443` walks the same chain for you.

| Document                                                          | Question it answers                              |
| ----------------------------------------------------------------- | ------------------------------------------------ |
| `/.well-known/server-configuration` on the Server Host (`:5443`)  | which Host, in which state, hosting which planes |
| `/.well-known/server-configuration` on a plane (`:6443`, `:7443`) | who is this plane, what keys, which interfaces   |
| `/.well-known/permguard-pdp-v1-configuration`                     | what `permguard.api.pdp.native.v1` offers here   |

### The Server Host: which planes this process hosts

```sh
curl -s http://127.0.0.1:5443/.well-known/server-configuration | jq
```

```json
{
  "host_id": "01a16e64-cbf0-7a15-ac06-f4a5ba7cf3ee",
  "state": "serving",
  "planes": {
    "control-plane": {
      "state": "serving",
      "server_configuration": "http://127.0.0.1:6443/.well-known/server-configuration"
    },
    "data-plane": {
      "state": "serving",
      "server_configuration": "http://127.0.0.1:7443/.well-known/server-configuration"
    }
  },
  "assurance": {
    "profile": "development",
    "enforcement": "local",
    "added_controls": [],
    "relaxations": ["custody.plaintext", "grpc.transport_parity_partial"]
  },
  "jwks_uri": "https://127.0.0.1:5444/host/v1/keys/host.operations"
}
```

The document also lists every listener with its class and what it demands of its clients, and whether the Host serves peer sessions; they are left out here for brevity.
`assurance` is the part a reviewer reads first: the profile this deployment runs under, and every relaxation it takes, published rather than implied.

### The Control Plane: where policy is published

```sh
curl -s http://127.0.0.1:6443/.well-known/server-configuration | jq
```

```json
{
  "plane": "control-plane",
  "state": "serving",
  "transports": { "http": true, "grpc": true },
  "jwks_uri": "http://127.0.0.1:6443/control-plane/keys",
  "notp": {
    "media_type": "application/vnd.permguard.notp.v1+cbor",
    "compression": "deflate",
    "ref_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/refs/{ref}",
    "push_negotiation_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/notp/push/negotiate",
    "push_commit_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/notp/push/commit",
    "pull_negotiation_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/notp/pull/negotiate",
    "object_upload_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/notp/objects",
    "object_fetch_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers/{ledger}/notp/objects/fetch"
  },
  "zones_endpoint": "http://127.0.0.1:6443/v1/zones",
  "ledgers_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers",
  "streams_endpoint": "http://127.0.0.1:6443/v1/streams",
  "interfaces": {
    "permguard.api.decisions.native.v1": {
      "configuration": "http://127.0.0.1:6443/.well-known/permguard-decisions-native-v1-configuration",
      "stage": "v1"
    }
  }
}
```

That `notp` block is the whole distribution protocol, discovered rather than agreed in advance: the media type, the compression, and the endpoints for negotiating a push, uploading only the objects the other side is missing, committing a ref, and pulling back.
`jwks_uri` is where the keys that sign a head statement are published, which is what lets a mirror refuse a ledger it cannot verify.

### The Data Plane: where decisions are made

```sh
curl -s http://127.0.0.1:7443/.well-known/server-configuration | jq
```

```json
{
  "plane": "data-plane",
  "state": "serving",
  "jwks_uri": "http://127.0.0.1:7443/data-plane/keys",
  "streams_endpoint": "http://127.0.0.1:7443/v1/streams",
  "interfaces": {
    "permguard.api.pdp.native.v1": {
      "configuration": "http://127.0.0.1:7443/.well-known/permguard-pdp-v1-configuration",
      "stage": "v1"
    }
  }
}
```

A plane says who it is, what it signs with, and **which interfaces it exposes**, each with its stage and its own configuration.
Follow the link and the interface describes itself:

```sh
curl -s http://127.0.0.1:7443/.well-known/permguard-pdp-v1-configuration | jq
```

```json
{
  "interface": "permguard.api.pdp.native.v1",
  "state": "serving",
  "stage": "v1",
  "pdp": "http://127.0.0.1:7443",
  "endpoints": {
    "evaluation": "http://127.0.0.1:7443/access/v1/evaluation",
    "evaluations": "http://127.0.0.1:7443/access/v1/evaluations"
  },
  "capabilities": [
    "urn:permguard:pdp:v1:store-in-payload",
    "urn:permguard:pdp:v1:profile-selection",
    "urn:permguard:pdp:v1:partition-inputs",
    "urn:permguard:pdp:v1:principal",
    "urn:permguard:pdp:v1:structured-reasons",
    "urn:permguard:pdp:v1:boxcarring",
    "urn:permguard:pdp:v1:signed-response"
  ],
  "store_scope": { "in": "payload", "zone": "required", "ledger": "required", "profile": "optional" },
  "limits": { "max_evaluations": 64 },
  "response_signing": { "state": "optional", "validity_seconds": 300, "clock_skew_seconds": 30 }
}
```

`endpoints` are the routes actually mounted: they come from the same constants the router does, so the document cannot advertise a path the plane does not answer.
`store_scope` states what a caller would otherwise have to read prose to learn: `zone` and `ledger` travel in the body, `profile` is optional.

`capabilities` are promises, so each one is implemented here, tested here, and answered identically over HTTP and gRPC.
Nothing is listed because it is planned, and nothing that is only half-true: a caller that configures itself from this document and is then refused by the same server has been lied to.

A **generic** client walks that chain: plane, then interface, then endpoints.
Permguard's own CLI does not: it is a versioned client for `permguard.api.pdp.native.v1` and links against the same constants the server mounts its routes from, so the two cannot drift.
Both arrive at the same endpoints.

Below discovery sit two more layers, in the ledger rather than on the wire: a **profile** names which partitions answer a request, and each **partition** declares the input contract a request may hand it.
The examples are about those.

## Five minutes

### 1. A workspace is a directory

A workspace holds exactly four things: the manifest, the partition folders it declares, `.permguardignore` and `.permguard/`.
Anything else, such as a `.cedar` file beside the partitions, a `documents.cedr` inside one, or a folder nobody declared, is refused by every command until it is moved into a partition, removed, or listed in `.permguardignore`.
A policy in a folder nobody compiles is a policy nobody enforces, and the author who put it there believes otherwise.

`init` and `clone` write a `.permguardignore` for the usual neighbours (`README.md`, `requests/`, `tests/`, `.git/`).
It reads like `.gitignore`: a name matches at any depth, a path with a `/` is a prefix from the root, and it is a starting point, not a rule.
What an operating system drops on its own (`.DS_Store`, `Thumbs.db`, `desktop.ini`) is never read and needs no entry.
`checkout` of another ledger refuses while the tree holds changes not applied to the one it tracks, and, on a clean tree, replaces the manifest and the partitions with the other ledger's, like `git checkout`, not like a merge.
An empty ledger is an empty workspace: `init` gives it a shape again and keeps the binding.

`examples/basics/manifest.yml` says what this ledger is, what it holds, and how it may be asked:

```yaml
runtimes:
  cedar:
    language: { name: cedar, constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
  rego:
    language: { name: rego, constraint: ">=1.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }

partitions:
  cedar:
    runtime: cedar
    schema: true                                     # and every policy type-checks against it
    input: { type: permguard.cedar.entities.v1, required: false }   # what a request may hand it
  rego:
    runtime: rego
    schema: false

profiles:
  default: { type: permguard.api.pdp.native.v1, partitions: [cedar, rego] }  # both answer
  gateway: { type: permguard.api.pdp.native.v1, partitions: [rego] }         # only the machine rules
```

Beside it, the policies.
Cedar:

```cedar
@alias("document-readers")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);

@alias("document-owners")
permit (
    principal,
    action == Action::"write",
    resource
) when { resource.owner == principal };
```

`@alias` is a handle for people.
What a decision cites is the **identity** Permguard derives and keeps across renames, so the audit trail still names the same policy after somebody tidies the file.

And Rego, in the same ledger, answering under its own profile:

```rego
# METADATA
# custom:
#   alias: gateway-access
package gateway.access

import rego.v1

default allow := false

allow if {
    input.subject.properties.role == "admin"
    input.action.name in {"create", "update", "delete"}
}
```

### 2. Ask it, with no server anywhere

```sh
permguard -w examples/basics validate    # parses, type-checks against the schema, derives identities
permguard -w examples/basics test        # and does it decide what you meant?
```

```text
  ok    a member of the finance group may read a document                   [default] permit by document-readers, gateway-access
  ok    writing a document somebody else owns is refused                    [default] deny, nothing permitted it
  ok    the gateway profile answers with Rego alone                         [gateway] permit by gateway-access
  ok    the same request under the default profile leaves the Cedar schema  [default] not evaluated
  ok    three questions in one request, and the batch is their conjunction  [gateway] deny — read=permit(gateway-access) create=permit(gateway-access) purge=deny

  asked these sources, compiled here

5 case(s), 5 passed, 0 failed.
```

The same engines a Data Plane uses, the same routing, the same resolution, compiled from the working tree.
This is the "bring your own data plane" path, and it is also your test suite.

<details>
<summary>Run it through the Taskfile instead</summary>

```sh
task cli -- -w examples/basics validate
task cli -- -w examples/basics test
```

</details>

### 3. Now publish it and ask a real PDP

```sh
task run:all                             # Server Host :5443, Host API :5444, Control Plane :6443, Data Plane :7443

permguard zones create acme
permguard ledgers create main-ledger --zone acme

permguard -w examples/basics init basics --language cedar,rego   # the example ships the sources; this tracks them
permguard -w examples/basics remote add origin http://127.0.0.1:6443
permguard -w examples/basics checkout origin/acme/main-ledger
permguard -w examples/basics plan
permguard -w examples/basics apply -m "lab policies"
```

The Data Plane mirrors it, verifies the signed head, compiles each partition once, and serves:

```sh
permguard -w examples/basics check -f requests/permit.json
permguard -w examples/basics --data-endpoint grpc://127.0.0.1:7443 check -f requests/permit.json
permguard -w examples/basics test --remote   # the same cases, against the plane
```

Straight at the API, on the endpoint the discovery document named:

```sh
curl -s -X POST http://127.0.0.1:7443/access/v1/evaluation \
  -H 'content-type: application/json' -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' examples/basics/requests/permit.json)" | jq
```

<details>
<summary>Run it through the Taskfile instead</summary>

```sh
task run:all

task cli -- zones create acme
task cli -- ledgers create main-ledger --zone acme

task cli -- -w examples/basics init basics --language cedar,rego
task cli -- -w examples/basics remote add origin http://127.0.0.1:6443
task cli -- -w examples/basics checkout origin/acme/main-ledger
task cli -- -w examples/basics apply -m "lab policies"
task cli -- -w examples/basics check -f requests/permit.json
```

</details>

### 4. What a request looks like

```json
{
  "subject":  { "type": "User", "id": "alice" },
  "action":   { "name": "read", "properties": { "risk": "high" } },
  "resource": { "type": "Document", "id": "budget-2026" },
  "context":  { "environment": "production" },

  "partition_inputs": {
    "cedar": {
      "type": "permguard.cedar.entities.v1",
      "data": [ { "uid": { "type": "Group", "id": "finance" } } ]
    }
  }
}
```

`subject`, `action`, `resource` and `context` reach **every** partition of the profile.
`partition_inputs` reaches **one**, by the partition's own name, because an entity store is written in Cedar's shape, a Rego document in JSON, and two Cedar partitions with different schemas hold different worlds.
The **ledger** decides what each partition accepts; the `type` in the request is checked against that and never obeyed, so a caller can never pick the parser for bytes it also supplies.

An action's properties reach Rego at `input.action.properties`.
Cedar cannot carry attributes on an action at all, so Permguard projects them into `context.action`, and refuses a caller who writes that key.
One request, two readings, nothing for a caller to keep in step.

### 5. Read the decisions back, and verify them

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions get  <decision-id> --zone acme --ledger main-ledger

# and check the chain and the signatures, with the plane's published keys
permguard decisions list --zone acme --ledger main-ledger --verify --keys data-plane-keys.json
```

The `decision id` a caller gets back is the one the record carries: an answer and its evidence are joined by an identifier, not by a timestamp and a guess.

## Examples

| Example                                                              | Domain                   | What it shows                                                                                                                     |
| -------------------------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| [`examples/basics`](examples/basics)                                 | users, groups, documents | the platform end to end: apply, mirror, decide, read the decisions back, verify them, and two workspaces pushing at each other    |
| [`examples/release-pipeline`](examples/release-pipeline)             | software delivery        | a realistic set of controls (team ownership, machine identities, separation of duties, incident-only rollback) and their evidence |
| [`examples/dogwood-session-access`](examples/dogwood-session-access) | session access           | the **temporal** interface: a policy that decides on what has already happened, and the durable history it reads                  |

Each example has its own README, written for somebody who has never used Permguard, with the commands and the decisions they produce.
Copy one into a scratch directory and take it apart:

```sh
mkdir -p playground/basics && cd playground/basics
task cp:basics          # or: task cp:rspipe, task cp:dogwood
```

The Dogwood one needs a plane with the temporal interface on:

```sh
task run:experimental        # both planes in one process, event path enabled
```

<details>
<summary><b>Inside an example</b></summary>

```text
examples/release-pipeline/
|-- manifest.yml            three partitions, two pdp profiles, one input contract each
|-- admin-cedar/            the org chart: teams, ownership, roles (schema, type-checked)
|   `-- model.cedarschema
|-- admin-rego/             the guardrails: deny only, and a JSON Schema over their own input
|   `-- guardrails.regoschema
|-- pipeline-rego/          what CI, the signer and the controller may do
|-- requests/*.json         twenty-three decision requests, refusals included
`-- tests/release.yml       what this workspace claims its own policies decide
```

Two of the three partitions run Rego.
A profile compiles the partitions it names and nothing else, so `pipeline` never loads the guardrails and `admin` never loads the rules for machines.
Each partition declares what a request may hand it: the org chart is **required**, the guardrails' list is optional, and the pipeline rules accept nothing, and the suite asserts every way a caller can get that wrong.

`lab/` at the repository root is something else: the configuration of the observability stack below.

</details>

## Reference

<details>
<summary><b>Run commands</b></summary>

Use `task`:

```sh
task build                         # build the workspace
task run:all                       # Control Plane + Data Plane in one process
task run:control                   # Control Plane only
task run:data                      # Data Plane only
task run-as-tls:all                # all-in-one with TLS
task run-as-mtls:all               # all-in-one with HTTP+gRPC mTLS on each plane role port
task run:experimental              # all-in-one with the temporal interface on
```

Use `make`:

```sh
make build
make run-all
make run-control
make run-data
make run-as-tls-all
make run-as-mtls-all
```

Use Cargo directly for the runtime binaries:

```sh
cargo run -p permguard-all-in-one --bin permguard-all-in-one -- crates/permguard-all-in-one/config.local.yml
cargo run -p permguard-control-plane --bin permguard-control-plane -- crates/permguard-control-plane/config.local.yml
cargo run -p permguard-data-plane --bin permguard-data-plane -- crates/permguard-data-plane/config.local.yml
```

Server commands accept a config file and optional overrides:

```sh
cargo run -p permguard-control-plane --bin permguard-control-plane -- \
  crates/permguard-control-plane/config.local.yml \
  --public-http-addr 127.0.0.1:6443 \
  --public-grpc-addr 127.0.0.1:6443 \
  --telemetry-addr 127.0.0.1:5443 \
  --admin-addr 127.0.0.1:5444 \
  --log-level debug \
  --log-format terminal
```

Each server crate (`permguard-all-in-one`, `permguard-control-plane`, `permguard-data-plane`) ships the same set of configurations beside its `Cargo.toml`:

| Configuration                   | For                                               |
| ------------------------------- | ------------------------------------------------- |
| `config.local.yml`              | a laptop, plain HTTP and gRPC                     |
| `config.local-tls.yml`          | a laptop, with TLS                                |
| `config.local-mtls.yml`         | a laptop, with mutual TLS on each plane role port |
| `config.local-experimental.yml` | a laptop, with the temporal interface on          |
| `config.lab.yml`                | the observability lab                             |
| `config.docker*.yml`            | the container images, plain, TLS and mutual TLS   |
| `config.template.yml`           | every setting, documented                         |

</details>

<details>
<summary><b>CLI workflow</b></summary>

Create and manage remote state:

```sh
permguard zones create acme --control-endpoint http://127.0.0.1:6443
permguard zones list
permguard zones get acme
permguard ledgers create --zone acme main-ledger
permguard ledgers list --zone acme
permguard ledgers get --zone acme main-ledger
```

Author and publish policies:

```sh
mkdir my-policies
permguard -w my-policies init my-policies --language cedar
permguard -w my-policies remote add origin http://127.0.0.1:6443
permguard -w my-policies checkout origin/acme/main-ledger
permguard -w my-policies refresh
permguard -w my-policies validate
permguard -w my-policies plan
permguard -w my-policies apply -m "update policies"
permguard -w my-policies status
permguard -w my-policies history
permguard -w my-policies verify
```

Inspect local objects:

```sh
permguard -w my-policies objects list
permguard -w my-policies objects list --tracked
permguard -w my-policies objects prune --dry-run
permguard -w my-policies objects cat <digest> --human
```

Ask for authorization:

```sh
permguard -w my-policies check --subject User:alice --action read --resource Document:budget
permguard -w my-policies check -f request.json
cat request.json | permguard -w my-policies check -f -
permguard check -f request.json --zone acme --ledger main-ledger -o json
```

Read and verify decision records, and the events of the temporal interface:

```sh
permguard decisions list --zone acme --ledger main-ledger
permguard decisions tail --zone acme --ledger main-ledger --follow
permguard decisions get <decision-id> --zone acme --ledger main-ledger
permguard decisions export --zone acme --ledger main-ledger -o json
permguard decisions list --zone acme --ledger main-ledger --verify --keys data-plane-keys.json
permguard events --help
```

Look at a running Server:

```sh
permguard discover http://127.0.0.1:5443   # walk the discovery chain: process, planes, interfaces
permguard inspect                          # what each plane is, and whether it accepts work
permguard config show                      # this CLI's own configuration
permguard completion zsh                   # shell completions
```

Operate a Host:

```sh
permguard host members --help    # membership enrollment, approval and lifecycle, on the Host listener
permguard host streams --help    # the streams the Host produces and consumes
permguard host grants --help     # the Host authorization store; recovery bootstrap is offline
permguard host identity --help   # the Host identity; provisioning and emergency reset are offline
permguard host holds --help      # legal and incident holds that keep ledgers from garbage collection
permguard restore plan --help    # restore a stopped Host's volume from a snapshot: plan, then run
```

</details>

<details>
<summary><b>Observability lab</b></summary>

Start both planes plus Prometheus, Grafana and Loki:

```sh
task lab:up                # or: make lab-up
```

Start only observability, for planes running on the host:

```sh
task lab:observability     # or: make lab-observability
```

Print the local addresses:

```sh
task lab:where             # or: make lab-where
```

```text
Grafana     http://127.0.0.1:7590
Prometheus  http://127.0.0.1:7591
Loki        http://127.0.0.1:7592
Host        http://127.0.0.1:5443   (all-in-one or control)
Host        http://127.0.0.2:5443   (standalone data)
Control     http://127.0.0.1:6443
Data        http://127.0.0.1:7443
```

Follow logs and stop the lab:

```sh
task lab:logs
task lab:logs SERVICE=grafana
task lab:down
task lab:clean
```

</details>

<details>
<summary><b>Load testing</b></summary>

Start the benchmark server, then run a k6 profile:

```sh
task bench:server
task bench:peak            # or: bench:ladder, bench:shed, bench:grpc, bench:tls, bench:hold
```

Those measure the transport with nothing behind it.
Two measure the product:

```sh
task bench:decide      # a stateless decision; needs a Data Plane mirroring a ledger
task bench:temporal    # an occurrence: recorded, decided, and under overlap; needs task run:experimental
```

Send k6 metrics to the observability lab:

```sh
task lab:observability
task bench:grafana
```

</details>

<details>
<summary><b>Workspace layout</b></summary>

The dependency direction is composition, then planes, then Host contracts and codecs, then core primitives.
The Host never depends on a concrete plane.

| Crate                      | Layer       | Purpose                                                                                             |
| -------------------------- | ----------- | --------------------------------------------------------------------------------------------------- |
| `permguard-core`           | contracts   | Stable traits, identifiers, errors, canonical codecs and crypto primitives.                         |
| `permguard-host`           | Host        | Identity, authorization, keys and secrets, audit, membership, storage, lifecycle and the Host API.  |
| `permguard-stream`         | codecs      | The Host stream engine: signed batches, acknowledgements, cursors, retention and recovery.          |
| `permguard-objects`        | codecs      | Canonical policy objects, digests, manifests and signed head statements.                            |
| `permguard-notp`           | codecs      | Negotiated Object Transfer Protocol messages and codecs.                                            |
| `permguard-decisions`      | codecs      | Decision evidence records, commitments and their verification.                                      |
| `permguard-events`         | codecs      | Event evidence records for the temporal interface.                                                  |
| `permguard-languages`      | planes      | Cedar, Rego and Dogwood integration, and the native request model.                                  |
| `permguard-control-plane`  | planes      | Control Plane binary: ledgers, NOTP server, catalog, decision and event stores.                     |
| `permguard-data-plane`     | planes      | Data Plane binary: mirrors, load gate, evaluation endpoints and decision recording.                 |
| `permguard-control-client` | clients     | Client-side access to endpoints, trust material, catalogs, NOTP, decisions and mirrors.             |
| `permguard-server`         | composition | Server Host composition: configuration, registration, dependency wiring and lifecycle.              |
| `permguard-all-in-one`     | composition | Runs every enabled plane behind one Host, in one process.                                           |
| `permguard-transport`      | support     | HTTP, gRPC, TLS, mutual TLS, revocation, reload and graceful shutdown.                              |
| `permguard-telemetry`      | support     | Liveness, readiness and metrics.                                                                    |
| `permguard-std`            | support     | Default implementations behind feature flags.                                                       |
| `permguard-cli`            | clients     | `permguard`, the command-line interface and authoring engine.                                       |
| `permguard-conformance`    | tests       | REST/gRPC parity, fault injection, the `kill -9` crash harness and the untrusted-boundary registry. |

</details>

## Development

```sh
task check                   # lint, structural checks and tests
task test                    # workspace tests
task test PKG=permguard-cli  # one crate
task lint                    # clippy with warnings denied
task coverage                # coverage gate
```

Structural checks:

```sh
task check:core-deps
task check:seams
task check:systems
task check:headers
task check:boundaries
```

Equivalent Make targets are available: `make check`, `make test`, `make lint`, `make coverage`.

<details>
<summary><b>Conformance harness</b></summary>

`crates/permguard-conformance` holds what every plane proves the same way, and `task check` runs it.
Its parity runner serves a plane's REST router and gRPC routes on real sockets and drives the same operation through the production client on each, requiring the same answer or the same `{class, code}`.
Its fault hooks let a test fail an fsync, fill a disk or jump a clock; `src/fault.rs` shows how a test asks for each.
Its crash harness kills a child appending to the decision spool and the event journal with `SIGKILL`, then reopens what it left; `PERMGUARD_CRASH_ROUNDS` raises the round count.

`crates/permguard-conformance/boundaries.json` registers every decoder of untrusted input, with its bound and its fuzz target.
`task check:boundaries` fails when a decoder is exported, renamed or removed without the registry changing with it, so a change to a decoder updates both in the same commit.
The fuzz targets run for a short budget on every pull request and a long one nightly; `task fuzz SECONDS=60` runs them locally with a nightly toolchain, `cargo install cargo-fuzz` and `jq`.

</details>

See the organization-wide [contribution rules](https://github.com/permguard/.github/blob/main/CONTRIBUTING.md) and this repository's [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

| Area                | Guide                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| Architecture        | [Server, Host and Planes](https://docs.permguard.com/how-it-works/architecture)                |
| Getting started     | [Getting Started](https://docs.permguard.com/how-it-works/getting-started)                     |
| Policy              | [Policy Lifecycle](https://docs.permguard.com/how-it-works/policy-lifecycle)                   |
| Decisions           | [Decision Lifecycle](https://docs.permguard.com/how-it-works/decision-lifecycle)               |
| Evidence            | [Evidence](https://docs.permguard.com/how-it-works/evidence)                                   |
| Your own data plane | [Bring Your Own Data Plane](https://docs.permguard.com/how-it-works/bring-your-own-data-plane) |
| Trust Plane         | [Trust Plane, in development](https://docs.permguard.com/trust-plane)                          |
| Operations          | [Verify released container images](ops/container-verification.md)                              |

## Part of a bigger picture

Permguard is the Policy Decision Point of the [Permguard organization](https://github.com/permguard).
Its Trust Plane, in development, will carry authority from one execution to the next with the [PIC protocol](https://www.pic-protocol.org).
[Soglia](https://github.com/permguard/soglia), also in development, is the runtime where AI agents run under that authority: Permguard decides, Soglia confines.

## License

Apache-2.0.
See [LICENSE](LICENSE).
