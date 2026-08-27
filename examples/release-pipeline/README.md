<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The release pipeline lab

Authorization for a software delivery platform: **who may cut a release, who may
approve it, and what may deploy it.** One ledger, two languages, twenty-three requests.

Why these controls, in plain terms:
**[docs/use-cases/release-pipeline.md](../../docs/use-cases/release-pipeline.md)**.

## What is in here

```text
admin-cedar/     the org chart — teams, ownership, roles (Cedar schema, type-checked)
admin-rego/      the guardrails — deny only, plus a JSON Schema over their own input
pipeline-rego/   what CI, the signer and the controller may do
requests/        twenty-three decision requests, refusals included
tests/           what this workspace claims its own policies decide
```

| Profile | Partitions | Answers |
| --- | --- | --- |
| `admin` | `admin-cedar` + `admin-rego` | what a **person** asks |
| `pipeline` | `pipeline-rego` | what the **pipeline** asks |

Three partitions, two of them Rego. A profile compiles what it names and nothing
else, so the guardrails are never loaded to answer a pipeline request. **An
explicit deny from either partition beats a permit from the other** — that is the
whole mechanism behind separation of duties below.

Two consequences worth knowing before the demo:

- **There is no `default` profile here.** Every request names `admin` or
  `pipeline`; one that names neither is refused with `profile_unknown`.
- **`admin` requests need a request file, not flags.** `--subject`/`--resource`
  build a request with no entity graph, and `admin-cedar`'s schema requires one
  (`User.role`, `Service.owner`). The flag form works against `pipeline`, whose
  partition declares no schema:

  ```bash
  permguard check --profile pipeline --zone delivery --ledger release-pipeline \
    --subject Workload:ci-pipeline --action artifact:upload --resource Release:v2.4.0
  ```

> **Two ways to type these, and you want one or the other.** Every block is written
> for the installed `permguard` binary, run from the repository root. Folded under each
> one is the same thing through the Taskfile, for a checkout with nothing installed.
> Prefer the binary where the exit status matters: `task cli` reports a clean refusal as
> success on purpose, so it always exits `0`.

---

## Step 1 — Start the planes

```bash
task run:all
```

Control plane on `:7556`, data plane on `:7656`, mirroring and decision shipping
already wired.

## Step 2 — Create the zone and the ledger

```bash
permguard zones create delivery
permguard ledgers create --zone delivery release-pipeline
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- zones create delivery
task cli -- ledgers create --zone delivery release-pipeline
```

</details>

## Step 3 — Publish the policies

```bash
permguard -w examples/release-pipeline init release-pipeline --language cedar,rego
permguard -w examples/release-pipeline remote add origin http://127.0.0.1:7556
permguard -w examples/release-pipeline validate
permguard -w examples/release-pipeline checkout origin/delivery/release-pipeline
permguard -w examples/release-pipeline plan
permguard -w examples/release-pipeline apply -m "release pipeline policies"
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/release-pipeline init release-pipeline --language cedar,rego
task cli -- -w examples/release-pipeline remote add origin http://127.0.0.1:7556
task cli -- -w examples/release-pipeline validate
task cli -- -w examples/release-pipeline checkout origin/delivery/release-pipeline
task cli -- -w examples/release-pipeline plan
task cli -- -w examples/release-pipeline apply -m "release pipeline policies"
```

</details>

`plan` names policies, not files — the identity comes from the `@alias` and
survives a rename:

```text
  + admin-cedar/release-approvers.cedar     86c0b18f-…
  + admin-cedar/release-authors.cedar       d25aa345-…
  + admin-cedar/rollback-responders.cedar   cf3d2c64-…
  + admin-rego/delivery-guardrails.rego     e51bf02e-…
  + pipeline-rego/pipeline-workloads.rego   49a568a0-…

Plan: 5 to create, 0 to update, 0 to delete (0 unchanged).
```

Give the data plane one mirror round:

```bash
sleep 20
```

---

## Step 4 — Ask

Shortcut for the four blocks below:

```bash
alias pg='permguard -w examples/release-pipeline check -f requests'
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
alias pg='task cli -- -w examples/release-pipeline check -f requests'
```

</details>

### 4a. Ownership decides who may act at all

`alice` is a Developer in `payments`; `payments` owns `payments-api`.

```bash
pg/release-create-permit.json     # PERMIT — release-authors
pg/release-create-deny.json       # DENY  — the service belongs to another team
```

### 4b. Separation of duties — a guardrail overrides an entitlement

`bob` is a Release Manager, so Cedar permits him to approve. He approves
`v2.4.0`, created by `alice`:

```bash
pg/signoff-permit.json
```

```text
  decision PERMIT
  request  User:bob release:signoff Release:v2.4.0
  + permitted by 86c0b18f-…                     ← release-approvers
```

Now he approves `v2.5.0`, which **he** created:

```bash
pg/signoff-separation-of-duties-deny.json
```

```text
  decision DENY
  request  User:bob release:signoff Release:v2.5.0
  - denied by e51bf02e-…                        ← delivery-guardrails
```

Same person, same action, same entitlement. Cedar still permits; the deny from the
other partition decides, and the log records which policy refused.

```bash
pg/signoff-untested-deny.json     # DENY — tests did not pass
```

### 4c. Machine identities, under their own profile

```bash
pg/artifact-upload-permit.json    # PERMIT — the build, for the service it builds
pg/artifact-sign-deny.json        # DENY  — signing is not the build's job
pg/deploy-permit.json             # PERMIT — every gate cleared
pg/deploy-scan-failed-deny.json   # DENY  — the security scan failed
```

Note the *kind* of no:

```text
  - no policy permits this request
```

Nothing permits it, rather than something refusing it. The CLI and the log tell
the two apart.

### 4e. One question, two runtimes reading it

A request describes what is being asked. It does not say how each runtime reads it — that is
Permguard's job, and it is what lets one profile hold partitions in two languages.

**An action's properties.** The request states them once, on the action:

```json
{ "action": { "name": "release:signoff", "properties": { "risk": "high" } } }
```

Rego reads them where it always did, `input.action.properties.risk`. Cedar cannot: an action there
is an identifier and carries no attributes. So Permguard projects them into the context Cedar does
read, under a key of its own:

```json
{ "branch": "main", "action": { "risk": "high" } }
```

`admin-cedar/model.cedarschema` declares that key, so the schema checks it like anything else —
`risk: 42` is refused with Cedar's own diagnosis, not ignored:

```bash
pg/signoff-risk-not-a-string-deny.json
# cedar: the request does not satisfy the schema: context `{action: {risk: 42}, …}`
#        is not valid for `Action::"release:signoff"`
```

**`context.action` is Permguard's.** A caller may not send it — for any profile, Rego-only
included, because a contract that changed shape with the profile would not be one:

```bash
pg/error-context-action-reserved.json
# field_reserved: `context.action` is populated from `action.properties`
```

**A partition's input is addressed to it by name.** Cedar reads an entity store; a Rego module
reads a JSON document. Neither can read the other's, and two Cedar partitions with different
schemas cannot read each other's either — so there is no addressing by language. There is only the
name:

```json
{
  "partition_inputs": {
    "admin-cedar": {
      "type": "permguard.cedar.entities.v1",
      "data": [ … the org chart, in Cedar's shape … ]
    },
    "admin-rego": {
      "type": "permguard.rego.data.v1",
      "data": { "frozen_services": ["payments-api"] }
    }
  }
}
```

```bash
pg/rollback-frozen-service-deny.json     # DENY — delivery-guardrails
```

Cedar reads the org chart and still entitles `alice`; the guardrail reads its **own** list, at
`input.partition.frozen_services`, and refuses. One question, two inputs, neither reachable from
the other side.

**The ledger decides what each partition accepts, not the caller.** `manifest.yml` says it:

```yaml
admin-cedar:
  input: { type: permguard.cedar.entities.v1, required: true }
admin-rego:
  input: { type: permguard.rego.data.v1, required: false }
pipeline-rego:
  # no `input`: these rules read the request alone
```

`type` in the request is an **assertion**, checked against that and never obeyed. If a caller could
name the type, a caller would be choosing which parser runs over bytes it also supplies — and
`acme.anything.v1` is not a type anybody can invent: Permguard implements two, and a manifest
naming a third is refused when it is pushed.

`required: true` on `admin-cedar` is not decoration: its policies traverse that store, so a request
without one would be decided against an empty world and denied for a reason that has nothing to do
with the rules.

| what a request does | what happens |
| --- | --- |
| addresses a partition of the profile, with the declared type and shape | it is read |
| addresses nothing, `required: false` | the type's **empty** input — an empty store, an empty document |
| addresses nothing, `required: true` | refused — `partition_input_required` |
| addresses `pipeline-rego`, which declares no input | refused — `partition_input_unsupported` |
| names a partition the profile does not hold | refused — `partition_unknown` |
| states a type the ledger does not declare | refused — `partition_input_type_mismatch` |
| states a type nobody registered | refused — `partition_input_type_unknown` |
| sends an object where the type carries an array | refused — `partition_input_malformed` |
| sends a document the partition's schema refuses | refused — `partition_input_schema` |

Every one of those is refused **before a policy is consulted**, and that is the point: a caller who
addressed the wrong partition has made a mistake nobody's rules have an opinion about. `deny` would
send them reading policies that were never the problem. The suite asserts all of them —
`permguard test` runs the six of them at the end of [`tests/release.yml`](tests/release.yml).

An input supplies **data**. It cannot add a partition, skip one, or choose which policies answer:
the profile decides that.

**Rego's own schema.** `admin-rego` declares `schema: true` and carries
`guardrails.regoschema` — a JSON Schema describing the document above:

```json
{ "type": "object", "additionalProperties": false,
  "properties": { "frozen_services": { "type": "array", "items": { "type": "string" } } } }
```

Rego is untyped by design, and that is a virtue in a rule. It is not a virtue in the data a rule
reads: send `frozen` instead of `frozen_services` and the guardrail reads nothing, decides nothing,
and the release goes out. A rename turning a control into silence is exactly what the schema is
for — compiled once when the partition loads, and checked before any rule runs:

```bash
pg/error-input-schema.json
# partition_input_schema: `partition_inputs.admin-rego`: rego: the document does not
#                         satisfy this partition's schema
```

**Where the input rides, and why it matters.** `input.partition`, not `data`. `data` is the
partition's own compiled world — identical for every request; `input` is what this request said.
Grafting a caller's document into `data` made a global store that changed per evaluation: a shared
surface a caller could write into, and one nothing could validate, because a schema describes a
request and not a store.

### 4d. Context — the same person, refused and then allowed

```bash
pg/rollback-deny.json                    # DENY  — production, no incident, not on call
pg/rollback-during-incident-permit.json  # PERMIT — on call, incident open
```

Nothing about `alice`, the action or the service changed. Three context fields did.

---

## Step 5 — Read the evidence

```bash
permguard decisions list --zone delivery --ledger release-pipeline
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- decisions list --zone delivery --ledger release-pipeline
```

</details>

```text
  +     51  2026-08-27T09:19:49Z  User:v1:788cb7ea… release:signoff Release:v2.4.0
         at commit sha256:1a2412cf4706
         policy 86c0b18f-25d6-8ed0-96e4-267164de5b67
  -     52  2026-08-27T09:19:49Z  User:v1:788cb7ea… release:signoff Release:v2.5.0
         at commit sha256:1a2412cf4706
         policy e51bf02e-1fad-89a8-9a14-9114cacaca38
```

- `at commit` — the exact policy state that decided, content-addressed.
- `policy …` — the approval and the refusal name different policies.
- `User:v1:788cb7ea…` — pseudonymised on the data plane; the control plane never
  held `bob`.

Verify it without trusting the server that served it:

```bash
curl -s http://127.0.0.1:7656/data-plane/keys -o /tmp/pdp-keys.json
permguard decisions list --zone delivery --ledger release-pipeline \
  --verify --keys /tmp/pdp-keys.json
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
curl -s http://127.0.0.1:7656/data-plane/keys -o /tmp/pdp-keys.json
task cli -- decisions list --zone delivery --ledger release-pipeline \
  --verify --keys /tmp/pdp-keys.json
```

</details>

```text
  inclusion   52 record(s) proven in a signed batch
  signatures  12 verified, 0 failed
```

More of the same log:

```bash
permguard decisions list --zone delivery --ledger release-pipeline --decision deny
permguard decisions tail --zone delivery --ledger release-pipeline --follow
permguard decisions export --zone delivery --ledger release-pipeline -o json
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- decisions list --zone delivery --ledger release-pipeline --decision deny
task cli -- decisions tail --zone delivery --ledger release-pipeline --follow
task cli -- decisions export --zone delivery --ledger release-pipeline -o json
```

</details>

---

## Step 6 — Change a rule, watch the answer move

```bash
# Let a Developer approve — self-approval is still refused.
sed -i '' 's/"ReleaseManager"/"Developer"/' \
  examples/release-pipeline/admin-cedar/release-approvers.cedar

# Drop the incident requirement — a routine production rollback starts passing.
sed -i '' 's/input.context.incident_active/true/' \
  examples/release-pipeline/admin-rego/delivery-guardrails.rego
```

```bash
permguard -w examples/release-pipeline plan      # an update; the identity is kept
permguard -w examples/release-pipeline apply -m "loosen the approval rule"
sleep 20
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/release-pipeline plan      # an update; the identity is kept
task cli -- -w examples/release-pipeline apply -m "loosen the approval rule"
sleep 20
```

</details>

## Try it without editing the example

```bash
mkdir -p playground/rspipe && cd playground/rspipe
task cp-rspipe          # copies the policies here; `playground/` is git-ignored
```

## Reset

```bash
git checkout examples/release-pipeline
rm -rf examples/release-pipeline/.permguard
permguard ledgers delete --zone delivery release-pipeline
```

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
git checkout examples/release-pipeline
rm -rf examples/release-pipeline/.permguard
task cli -- ledgers delete --zone delivery release-pipeline
```

</details>

## What keeps this page true

Every decision above is a case in [`tests/release.yml`](tests/release.yml), and
`permguard test` checks all twenty-three **offline** — the policies are compiled here,
with the same engines a data plane uses, before anything is pushed:

```bash
permguard -w examples/release-pipeline test
```

```text
  ok    a release manager approves somebody else's release         [admin] permit by release-approvers
  ok    nobody approves the release they created themselves        [admin] deny by delivery-guardrails
  ok    signing is not the build's job                             [pipeline] deny, nothing permitted it
  ok    a document its partition's schema refuses never reaches a rule  [admin] not evaluated
  …
23 case(s), 23 passed, 0 failed.
```

Requests are read with `permguard.pdp.v1`'s own type — the one the data plane
deserializes into — so what is refused here is what a plane refuses: a field that is
not stated, a field of the wrong JSON type, a profile the ledger does not declare.
A case may expect any of them with `expect: { error: field_required }`.

A case states not only the answer but **which policy gave it**, which is what
separates a deny by the guardrail from a deny because nothing permitted:

```yaml
- name: nobody approves the release they created themselves
  request: ../requests/signoff-separation-of-duties-deny.json
  expect: { decision: deny, policies: [delivery-guardrails] }
```

Exit `0` when every case passes, `2` when one does not — a pipeline can gate on it.
`--list` shows the cases without deciding, `--name` runs one.

### After the apply: ask the plane the same cases

```bash
permguard -w examples/release-pipeline test --remote
```

```text
  ok    nobody approves the release they created themselves        [admin] deny by delivery-guardrails
  …
  asked http://127.0.0.1:7656 about delivery/release-pipeline [workspace]

23 case(s), 23 passed, 0 failed.
```

A different question from the one above, and the one worth asking after `apply`:
not *do my sources decide this*, but *does the ledger that is deployed still
decide this*. It catches what a local run structurally cannot — a mirror that has
not caught up, a commit the plane refuses to serve, a ledger somebody else applied
to. When the plane cites a policy this workspace does not contain, the report says
so, because that is the finding:

```text
  fail  nobody approves the release they created themselves        [admin] permit by release-approvers
        the decision cites `7b3f…`, which is no policy of this workspace —
        what answered is not what these sources would apply
```

> **It writes to the decision log.** A Permguard plane records every decision, and
> one that cannot record refuses to decide rather than decide unrecorded — so a
> suite run this way leaves its cases in the log as real decisions. Point it at a
> plane whose log you are willing to have them in.

<details>
<summary>Run it through the Taskfile instead</summary>

```bash
task cli -- -w examples/release-pipeline test
```

</details>

<details>
<summary>The same example, through the data plane's own decision path</summary>

```bash
cargo test -p permguard-data-plane --test examples
```

That test reads this directory — manifest, policies, requests **and the very cases
above** — builds a mirror and asks the real `Decider`. It covers what `permguard
test` does not: the ledger as a plane actually loads it. Both examples go through
it, and neither keeps a second copy of its expectations: the `.yml` is the only
place they are written. It also asserts that each profile names only the partitions
it needs.

</details>
