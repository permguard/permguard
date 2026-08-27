<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The basics lab

The smallest workspace that exercises the whole platform: a deliberately
trivial domain — users, groups and documents — so that what you are looking at
is Permguard rather than the policies.

For a realistic domain, see **[the release pipeline lab](../release-pipeline)**
and the use case it implements.

A ready-made workspace — **one manifest, two partitions (Cedar and Rego), example
policies** — and two use cases you can run end to end.

```text
examples/basics/
├── manifest.yml            two runtimes, two partitions, two pdp profiles
├── cedar/documents.cedar   two Cedar policies (@alias on each)
├── cedar/model.cedarschema the Cedar schema — one per partition, at most
├── rego/gateway.rego       one Rego module (# METADATA custom.alias)
└── requests/*.json         decision requests to send with `permguard check`
```

| Use case | What it shows |
| --- | --- |
| **[A — One workspace](#use-case-a--one-workspace)** | policies up, decisions answered, and the decisions read back |
| **[B — Two workspaces](#use-case-b--two-workspaces)** | a second author, pushes crossing in both directions, and what that does to the decisions |

Every command runs **from the repository root**, and `-w examples/basics` points the
CLI at this workspace.

> **Two ways to type these, and you want one or the other.** Every block is written
> for the installed `permguard` binary, run from the repository root. Folded under each
> one is the same thing through the Taskfile, for a checkout with nothing installed.
> Prefer the binary where the exit status matters: `task cli` reports a clean refusal as
> success on purpose, so it always exits `0`.

## What `task run:all` already wires up

One process, both planes, and **both directions already configured** — there is
nothing to connect by hand:

```text
                    ┌──────────────────────── control plane :7556 ───────────────┐
   apply ─────────► │  ledgers (git-like objects)      decision log (segments)   │
                    └───────┬─────────────────────────────────▲──────────────────┘
                            │ mirrors, every 15s              │ ships, every 1s
                    ┌───────▼─────────────────────────────────┴──────────────────┐
   check ─────────► │  data plane :7656 — decides from what it mirrored,          │
                    │  records every decision, ships it back                      │
                    └────────────────────────────────────────────────────────────┘
```

- **Policies flow down**: `dataPlane.mirrors` in `config.local.yml` follows the
  control plane in the same process, over the loopback, with the same NOTP
  transfer a remote plane uses. Not a shortcut — the real path.
- **Decisions flow up**: `dataPlane.decisions.log` records every answer to a
  local durable spool and ships signed batches to `controlPlane.decisions`.
- You read them back with `permguard decisions`, from the **control plane**.

---

## Use case A — one workspace

Policies up, decisions answered, decisions read back.

### A1. Start, and create the ledger

```bash
task run:all          # control :7556, data :7656
```

```bash
permguard zones create acme --endpoint http://127.0.0.1:7556
permguard ledgers create main-ledger --zone acme --endpoint http://127.0.0.1:7556
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- zones create acme --endpoint http://127.0.0.1:7556
task cli -- ledgers create main-ledger --zone acme --endpoint http://127.0.0.1:7556
```

</details>

### A2. Push the policies

```bash
permguard -w examples/basics init basics --language cedar,rego    # adopts the existing manifest.yml
permguard -w examples/basics remote add origin http://127.0.0.1:7556
permguard -w examples/basics validate                              # Cedar + Rego parse, schema, identities
permguard -w examples/basics checkout origin/acme/main-ledger      # bind + resolve GUIDs
permguard -w examples/basics plan
permguard -w examples/basics apply -m "lab policies"               # negotiate → upload → signed commit
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics init basics --language cedar,rego    # adopts the existing manifest.yml
task cli -- -w examples/basics remote add origin http://127.0.0.1:7556
task cli -- -w examples/basics validate                              # Cedar + Rego parse, schema, identities
task cli -- -w examples/basics checkout origin/acme/main-ledger      # bind + resolve GUIDs
task cli -- -w examples/basics plan
task cli -- -w examples/basics apply -m "lab policies"               # negotiate → upload → signed commit
```

</details>

Expected plan:

```text
  + document-readers (cedar) <uuid>
  + document-owners  (cedar) <uuid>
  + gateway-access   (rego)  <uuid>
Plan: 3 to create, 0 to update, 0 to delete (0 unchanged).
```

```bash
permguard -w examples/basics verify        # the head statement + the local closure
permguard -w examples/basics history
permguard -w examples/basics status        # tracked ledger, checkpoint, pending
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics verify        # the head statement + the local closure
task cli -- -w examples/basics history
task cli -- -w examples/basics status        # tracked ledger, checkpoint, pending
```

</details>

### A3. Ask for decisions

The data plane serves what it mirrors, so give it one round:

```bash
sleep 20
permguard -w examples/basics check -f requests/permit.json
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
sleep 20
task cli -- -w examples/basics check -f requests/permit.json
```

</details>

`check` runs from inside the workspace, so the zone and ledger come from the
checkout — the requests in `requests/` name neither, which is what makes them
portable between ledgers.

**A permit.** `alice` is in `Group::"finance"`, and `document-readers` permits
that group to read:

```text
  decision PERMIT
  ledger   acme/main-ledger [workspace]
  request  User:alice read Document:budget-2026
  + permitted by 01a0…                      ← the policy identity, not a file name
  decision id 68aa…                         ← the same id the log records

Permitted.
```

**A deny.** `bob` asks to *write* a document `carol` owns:

```bash
permguard -w examples/basics check -f requests/deny.json
# decision DENY … and exit status 0, because a deny is an answer.
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics check -f requests/deny.json
# decision DENY … and exit status 0, because a deny is an answer.
```

</details>

**What the request handed the policies.** `requests/permit.json` carries the org chart the Cedar
rules traverse, addressed to the partition that reads it:

```json
{
  "subject":  { "type": "User", "id": "alice" },
  "action":   { "name": "read" },
  "resource": { "type": "Document", "id": "budget-2026" },
  "partition_inputs": {
    "cedar": {
      "type": "permguard.cedar.entities.v1",
      "data": [ { "uid": { "type": "Group", "id": "finance" } }, … ]
    }
  }
}
```

`subject`, `action`, `resource` and `context` reach **every** partition of the profile.
`partition_inputs` reaches **one**, by name — because an entity store is written in Cedar's shape
and a Rego module could not read it, and because two Cedar partitions with different schemas hold
different worlds. `manifest.yml` says which type each partition accepts; the `type` here is checked
against it, never obeyed. The `rego` partition declares no input, so it reads the request alone —
and anything addressed to it is refused rather than quietly dropped.

`examples/release-pipeline` takes this further: two runtimes reading one question, a Rego partition
with a JSON Schema over its own document, and every way a request can get the addressing wrong.

**The other profile**, **boxcarring**, and **two ways to be wrong**:

```bash
permguard -w examples/basics check -f requests/gateway-permit.json    # Rego alone
permguard -w examples/basics check -f requests/boxcarred.json -o json | jq '.evaluations'

permguard -w examples/basics check -f requests/error-no-store.json --ignore-workspace
# no zone and no ledger anywhere: refused before a round trip (exit 64)

permguard -w examples/basics check -f requests/error-unknown-ledger.json --ignore-workspace
# a ledger this plane does not mirror: 404, not a deny — a PEP must tell "no"
# from "ask somebody else"
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics check -f requests/gateway-permit.json    # Rego alone
task cli -- -w examples/basics check -f requests/boxcarred.json -o json | jq '.evaluations'

task cli -- -w examples/basics check -f requests/error-no-store.json --ignore-workspace
# no zone and no ledger anywhere: refused before a round trip (exit 64)

task cli -- -w examples/basics check -f requests/error-unknown-ledger.json --ignore-workspace
# a ledger this plane does not mirror: 404, not a deny — a PEP must tell "no"
# from "ask somebody else"
```

</details>

Same over gRPC, and straight at the API:

```bash
permguard -w examples/basics --data-endpoint grpc://127.0.0.1:7656 check -f requests/permit.json

# what `permguard.pdp.v1` offers here — the endpoints below come from this document
curl -s http://127.0.0.1:7656/.well-known/permguard-pdp-v1-configuration | jq
curl -s -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' examples/basics/requests/permit.json)" | jq
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics --data-endpoint grpc://127.0.0.1:7656 check -f requests/permit.json

# what `permguard.pdp.v1` offers here — the endpoints below come from this document
curl -s http://127.0.0.1:7656/.well-known/permguard-pdp-v1-configuration | jq
curl -s -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' -H 'x-request-id: lab-1' \
  -d "$(jq '. + {zone: "acme", ledger: "main-ledger"}' examples/basics/requests/permit.json)" | jq
```

</details>

### A4. Read what was decided

Every answer above was recorded on the data plane and shipped to the control
plane. Ask the **control plane** for them:

```bash
permguard decisions list --zone acme --ledger main-ledger
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- decisions list --zone acme --ledger main-ledger
```

</details>

```text
  scope    acme/main-ledger

  ~      1  marker  sampling permits=1.0, build 0.1.0
  +      2  2026-08-24T21:45:03Z  User:v1:3717f5b1… read Document:budget-2026
         at commit sha256:0e5e305fd961 [5852 µs]
         policy af4c4260-ba94-8f5f-8ae1-942ea8644f4e
  -      3  2026-08-24T21:45:04Z  User:v1:4180c27b… write Document:budget-2026
         at commit sha256:0e5e305fd961 [4097 µs]

2 decision(s), 1 permitted, 1 denied.
```

Three things in that output are worth stopping on:

- **`marker`** — an epoch. It declares the sampling rate, the build and the
  commitment key that govern the records after it, so a reader knows what the
  log claims to be complete about instead of inferring it.
- **`User:v1:3717f5b1…`** — pseudonymised **on the data plane**, before the
  record left it. The control plane never holds a raw identifier, and neither
  does any consumer.
- **`at commit sha256:0e5e…`** — the exact policy state that produced the
  answer. This is the forensic join: the log says what a decision was decided
  against, and it is a content-addressed digest, so it means the same thing
  forever.

Everything else the command does:

```bash
permguard decisions tail --zone acme --ledger main-ledger --follow   # as they arrive
permguard decisions get 68aa1f3c9e2b47d0 --zone acme --ledger main-ledger
permguard decisions export --zone acme --ledger main-ledger -o json  # bulk, resumable
permguard decisions list --zone acme --ledger main-ledger -o yaml --limit 5
permguard --control-endpoint grpc://127.0.0.1:7556 decisions list --zone acme --ledger main-ledger
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- decisions tail --zone acme --ledger main-ledger --follow   # as they arrive
task cli -- decisions get 68aa1f3c9e2b47d0 --zone acme --ledger main-ledger
task cli -- decisions export --zone acme --ledger main-ledger -o json  # bulk, resumable
task cli -- decisions list --zone acme --ledger main-ledger -o yaml --limit 5
task cli -- --control-endpoint grpc://127.0.0.1:7556 decisions list --zone acme --ledger main-ledger
```

</details>

**Verify it yourself**, without trusting the server that served it:

```bash
curl -s http://127.0.0.1:7656/data-plane/keys -o /tmp/pdp-keys.json
permguard decisions list --zone acme --ledger main-ledger --verify --keys /tmp/pdp-keys.json
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
curl -s http://127.0.0.1:7656/data-plane/keys -o /tmp/pdp-keys.json
task cli -- decisions list --zone acme --ledger main-ledger --verify --keys /tmp/pdp-keys.json
```

</details>

```text
  inclusion   3 record(s) proven in a signed batch
  signatures  2 verified, 0 failed
```

Which proof runs is decided by the scope, not by preference. A **tenant view**
is a subsequence of a producer's stream — the records in between belong to other
tenants and must not be disclosed — so the chain cannot be checked across it,
and each record is proven by its **inclusion path** into a batch the data plane
signed. Ask for the whole producer stream and the **chain** is what verifies:

```bash
PDP=all-in-one-local
INST=$(ls .volume/all-in-one/data/decisions/store/streams/$PDP | head -1)
permguard decisions list --pdp $PDP --instance $INST --verify --keys /tmp/pdp-keys.json
# chain  intact
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
PDP=all-in-one-local
INST=$(ls .volume/all-in-one/data/decisions/store/streams/$PDP | head -1)
task cli -- decisions list --pdp $PDP --instance $INST --verify --keys /tmp/pdp-keys.json
# chain  intact
```

</details>

**Where the offset comes in.** The control plane keeps no cursor: each page
returns an opaque offset that belongs to you, and presenting it is how you
continue. It is **bound to the scope that issued it** — one from `acme`
presented under another zone is refused rather than reinterpreted:

```bash
NEXT=$(permguard decisions list --zone acme --ledger main-ledger -o json --limit 1 | jq -r .next)
permguard decisions list --zone acme --ledger main-ledger --from "$NEXT"
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
NEXT=$(task cli -- decisions list --zone acme --ledger main-ledger -o json --limit 1 | jq -r .next)
task cli -- decisions list --zone acme --ledger main-ledger --from "$NEXT"
```

</details>

---

## Use case B — two workspaces

A second author, pushes crossing in both directions, and the decisions that
follow the policy as it moves. Start from a finished use case A.

### B1. A second workspace

Two ways — pick either.

**Clone** (one command, fetches everything into a fresh directory):

```bash
permguard -w /tmp clone http://127.0.0.1:7556/acme/main-ledger lab-clone
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w /tmp clone http://127.0.0.1:7556/acme/main-ledger lab-clone
```

</details>

**Or checkout from an empty folder** (init first, then bind — same result):

```bash
mkdir -p /tmp/lab-b
permguard -w /tmp/lab-b init lab-b --language cedar,rego
rm /tmp/lab-b/manifest.yml                    # the manifest arrives from the ledger
permguard -w /tmp/lab-b remote add origin http://127.0.0.1:7556
permguard -w /tmp/lab-b checkout origin/acme/main-ledger
ls /tmp/lab-b/cedar /tmp/lab-b/rego           # policies and schema, materialized by alias
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
mkdir -p /tmp/lab-b
task cli -- -w /tmp/lab-b init lab-b --language cedar,rego
rm /tmp/lab-b/manifest.yml                    # the manifest arrives from the ledger
task cli -- -w /tmp/lab-b remote add origin http://127.0.0.1:7556
task cli -- -w /tmp/lab-b checkout origin/acme/main-ledger
ls /tmp/lab-b/cedar /tmp/lab-b/rego           # policies and schema, materialized by alias
```

</details>

### B2. They push, you pull

```bash
sed -i '' 's/Group::"finance"/Group::"analysts"/' /tmp/lab-b/cedar/document-readers.cedar
permguard -w /tmp/lab-b plan                # ~ document-readers: update — same id, identity kept
permguard -w /tmp/lab-b apply -m "readers are the analysts group"

permguard -w examples/basics pull                   # counter advances; your files stay yours
permguard -w examples/basics history                # both commits, newest first
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
sed -i '' 's/Group::"finance"/Group::"analysts"/' /tmp/lab-b/cedar/document-readers.cedar
task cli -- -w /tmp/lab-b plan                # ~ document-readers: update — same id, identity kept
task cli -- -w /tmp/lab-b apply -m "readers are the analysts group"

task cli -- -w examples/basics pull                   # counter advances; your files stay yours
task cli -- -w examples/basics history                # both commits, newest first
```

</details>

> **Stay inside the schema.** This partition declares one, so `read` and `write`
> are the actions that exist and `Group`, `User`, `Document` are the types. Name
> an action the schema does not declare and the data plane refuses to serve that
> commit — `503 ledger_incompatible`, written to `<mirror>/BLOCKED` — until a
> commit fixes it, at which point it retries by itself. That check runs where
> the policies are evaluated; it does **not** yet run at `apply`.

### B3. What that did to the decisions

Wait for the mirror, then ask the same question again:

```bash
sleep 20
permguard -w examples/basics check -f requests/permit.json
permguard decisions list --zone acme --ledger main-ledger -o json \
  | jq -r '.decisions[] | "\(.seq) \(.decision) \(.commit[0:19]) \(.policies)"'
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
sleep 20
task cli -- -w examples/basics check -f requests/permit.json
task cli -- decisions list --zone acme --ledger main-ledger -o json \
  | jq -r '.decisions[] | "\(.seq) \(.decision) \(.commit[0:19]) \(.policies)"'
```

</details>

```text
2 true  sha256:0cbe3f9459d2 ["af4c4260-…","e63ec998-…"]   ← Cedar and Rego both permitted
3 false sha256:0cbe3f9459d2 null                          ← the write: nothing permitted it
4 true  sha256:4332333c24d2 ["e63ec998-…"]                ← only Rego, now
```

**The answer is still `PERMIT`, and that is the interesting part.** `alice` is in
`finance`, and the Cedar policy now permits `analysts` — so `af4c4260` stopped
permitting her. The Rego module in the other partition lets any `User` read, and
either partition permitting is enough. The decision did not change; **the reason
did**, and the log is where that is visible.

This is what recording the commit and the policy identities buys, and why
neither is a file name: `at commit` says *which policy state* produced each
answer, `policies` says *which policies inside it* actually decided, and both
survive a rename. `permguard -w examples/basics history` shows the same two states
from the other side.

> To see the answer itself flip, change the policy the *other* partition would
> not cover — a `write`, which the Rego module permits to nobody.

### B4. And back the other way

Edit here, push, and let the clone pull it:

```bash
sed -i '' 's/admin/operator/' examples/basics/rego/gateway.rego
permguard -w examples/basics apply -m "operators mutate"
permguard -w /tmp/lab-b pull

sleep 20
permguard -w examples/basics check -f requests/gateway-permit.json
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
sed -i '' 's/admin/operator/' examples/basics/rego/gateway.rego
task cli -- -w examples/basics apply -m "operators mutate"
task cli -- -w /tmp/lab-b pull

sleep 20
task cli -- -w examples/basics check -f requests/gateway-permit.json
```

</details>

Now a **DENY**, and it should be: `gateway-permit.json` asks as `dora` with
`role: admin`, and the module was just changed to permit `operator`. The
`gateway` profile answers with the Rego partition alone, so there is no second
partition to permit it instead — which is exactly the difference between the two
profiles, made visible by one edit.

```bash
permguard decisions tail --zone acme --ledger main-ledger --follow
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- decisions tail --zone acme --ledger main-ledger --follow
```

</details>

Leave that running in one terminal and re-run a `check` in another: the record
appears within a second or two, because the shipper batches on a one-second
interval. Two people can run that tail at once — the control plane keeps no
cursor for either of them.

Every flow above also rides gRPC — the scheme is the transport, nothing else
changes:

```bash
permguard -w /tmp clone grpc://127.0.0.1:7556/acme/main-ledger lab-grpc
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w /tmp clone grpc://127.0.0.1:7556/acme/main-ledger lab-grpc
```

</details>

---

## Watching it happen

```bash
task lab:up          # Prometheus, Grafana, Loki
task lab:where       # the URLs
```

| Dashboard | Answers |
| --- | --- |
| **Permguard · Data plane** | decisions by outcome, latency, cache hits against compilations, mirror freshness, **what the log is holding and shipping** |
| **Permguard · Control plane** | zones and ledgers, pushes and pulls, disk per zone, **decisions received per tenant and how far each producer has got** |
| **Permguard · Decision log** | the log end to end: written against shipped against accepted, the unshipped backlog, refusals by reason |

The one number to watch is `permguard_decisions_unshipped_records`. It climbing
and not coming back is a shipper that is not shipping, and it is visible long
before the spool fills and the stream has to end.

## Check what it decides, without a plane

[`tests/documents.yml`](tests/documents.yml) states what these policies decide, and
`permguard test` compiles them here and checks it — no server, nothing applied:

```bash
permguard -w examples/basics test
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/basics test
```

</details>

```text
  ok    a member of the finance group may read a document                   [default] permit by document-readers, gateway-access
  ok    writing a document somebody else owns is refused                    [default] deny, nothing permitted it
  ok    the gateway profile answers with Rego alone                         [gateway] permit by gateway-access
  ok    the same request under the default profile leaves the Cedar schema  [default] not evaluated
  ok    three questions in one request, and the batch is their conjunction  [gateway] deny — read=permit(gateway-access) create=permit(gateway-access) purge=deny

5 case(s), 5 passed, 0 failed.
```

These cases are checked twice, from the same file: by `permguard test`, which
compiles the workspace here, and by
`cargo test -p permguard-data-plane --test examples`, which builds a mirror and asks
the real decision path. An example cannot claim something neither can produce.

The first line is the whole point of two partitions in one profile: **both** permit
the read, and the decision cites both. The fourth is the schema doing its job — under
`default`, `create` is an action the Cedar partition cannot evaluate, and a partition
that cannot evaluate denies. The last is a **boxcarred** request: three questions in
one, and a case may name what each of them must answer.

```yaml
- name: three questions in one request, and the batch is their conjunction
  request: ../requests/boxcarred.json
  expect:
    decision: deny
    evaluations: { read: permit, create: permit, purge: deny }
```

The request is parsed with the data plane's own `CheckRequest`, so the boxcarring
rule — each evaluation inheriting the top-level defaults, the batch stopping where
`options.evaluations_semantic` says, the whole request being the conjunction — is
the plane's, not a second implementation of it. `test` and `test --remote` print the
same line for this case.

## Things that refuse, on purpose

```bash
echo 'permit (principal' >> examples/basics/cedar/broken.cedar
permguard -w examples/basics validate                                   # Cedar parse error
rm examples/basics/cedar/broken.cedar

cp examples/basics/manifest.yml examples/basics/manifest.yaml
permguard -w examples/basics validate                                   # two manifests = ambiguity
rm examples/basics/manifest.yaml

cp examples/basics/cedar/model.cedarschema examples/basics/cedar/second.cedarschema
permguard -w examples/basics validate                                   # two schemas = ambiguity
rm examples/basics/cedar/second.cedarschema

permguard -w examples/basics apply -m x   # after someone else pushed: conflict — pull, re-plan, re-apply

# Raise the engine range past anything that exists, and the CLI's own load gate
# refuses before a server is asked — every consumer runs that gate:
#   sed -i '' 's/>=0.1.0 <0.2.0/>=9.0.0/' examples/basics/manifest.yml
#   permguard -w examples/basics apply -m x
#   # error: manifest rejected: runtime `cedar`: engine permguard 0.1.0 does not satisfy `>=9.0.0`
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
echo 'permit (principal' >> examples/basics/cedar/broken.cedar
task cli -- -w examples/basics validate                                   # Cedar parse error
rm examples/basics/cedar/broken.cedar

cp examples/basics/manifest.yml examples/basics/manifest.yaml
task cli -- -w examples/basics validate                                   # two manifests = ambiguity
rm examples/basics/manifest.yaml

cp examples/basics/cedar/model.cedarschema examples/basics/cedar/second.cedarschema
task cli -- -w examples/basics validate                                   # two schemas = ambiguity
rm examples/basics/cedar/second.cedarschema

task cli -- -w examples/basics apply -m x   # after someone else pushed: conflict — pull, re-plan, re-apply

# Raise the engine range past anything that exists, and the CLI's own load gate
# refuses before a server is asked — every consumer runs that gate:
#   sed -i '' 's/>=0.1.0 <0.2.0/>=9.0.0/' examples/basics/manifest.yml
#   task cli -- -w examples/basics apply -m x
#   # error: manifest rejected: runtime `cedar`: engine permguard 0.1.0 does not satisfy `>=9.0.0`
```

</details>

What happens underneath is the specification, live: policies (not files) as
content-addressed objects, identities carried by alias, one NOTP push —
negotiate once, batches, one signed compare-and-swap commit — every pull
verified against the key ring before the checkpoint moves, and every decision
recorded in a hash-chained, signed log that names the commit it was decided
against.
