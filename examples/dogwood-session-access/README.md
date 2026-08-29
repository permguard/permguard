<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Session access, decided on what already happened

The other examples answer *may this subject do this to this?* from the request
alone. This one answers a question the request cannot contain:

> may this user read, **given that** they logged in within the last hour and
> have not logged out since?

Nothing in a `Read` request says whether a `Login` happened. The history does,
and Dogwood is the runtime that reads it.

Adapted from Dogwood's own `read_login_not_logout` example — same policy, same
action schema, same event schema — so what you are looking at is Permguard
around it rather than a policy written to flatter it.

## What is here

```text
examples/dogwood-session-access/
├── manifest.yml                        one runtime, one partition, one temporal profile
├── governance/read-after-login.dw      the policy: a `when temporal { … }` clause
├── governance/schema.cedarschema       the ACTION schema — actions, entities, request context
├── governance/events.dwschema          the EVENT schema — kinds, logged fields, and the pin
├── events/*.json                       five occurrences, in the order they happen
├── refusals/*.json                     four submissions that are refused, and why
└── tests/session-access.yml            the claims below, as cases `permguard test` runs
```

Two schemas, because they answer different questions about the same occurrence:

```text
event occurrence
  ├── action schema: principal, resource, action and request context
  └── event schema:  kind, logged fields, pins and the maximum temporal window
```

That is why a Dogwood partition declares `artifacts:` rather than `schema: true`.
"There is a schema" cannot say *which*, and this partition has two.

## The pin, and why the policy never mentions the principal

`events.dwschema` declares:

```dogwood
decision event <A>::request {
    ...inputs(A),
    pin callerPrincipal: principalType(A) = principal,
    ...
}
```

`pin` correlates every temporal predicate on this event to the principal of the
request being decided. Alice's `Login` is invisible to Bob's `Read` — not because
the policy checks, but because the two are in different histories.

The value is never taken from the caller. Permguard derives it from the request's
authoritative root, and if a caller *also* sends `logged.callerPrincipal` with a
different value the submission is refused rather than one of the two being chosen:
a pin decides which history an event belongs to, and choosing would let a caller
pick its own.

## Run it

The temporal interface is off by default, and gated a second time because
Dogwood's contracts are `v1alpha1`. In the data plane's configuration:

```yaml
experimental:
  dogwood:
    enabled: "true"

dataPlane:
  events:
    enabled: "true"
    producer_id: data-plane-local-1
```

Then apply the workspace and submit the five occurrences in order:

```bash
permguard -w examples/dogwood-session-access apply

for event in examples/dogwood-session-access/events/*.json; do
  curl -sS -X POST http://127.0.0.1:7656/temporal/v1alpha1/events \
    -H 'content-type: application/json' --data @"$event" | jq -c
done
```

## What you should see

| # | Occurrence | Outcome | Why |
| --- | --- | --- | --- |
| 1 | `Login::request` at 10:00:00 | `decided`, **deny** | `request` is a decision kind, and no rule permits a `Login` |
| 2 | `Login::response` at 10:00:05 | `accepted` | a history-only kind: recorded, observed, **no verdict invented** |
| 3 | `Read::request` at 10:01:40 | `decided`, **permit** | alice logged in 95 s ago — inside the 1 h window |
| 4 | `Read::request` at 11:06:40 | `decided`, **deny** | the login is now 1 h 6 m old — outside the window |
| 5 | `Read::request` by bob | `decided`, **deny** | bob has no login, and alice's is in another history |

Occurrence 2 is the one worth pausing on. A history-only kind returns

```json
{ "outcome": "accepted", "event_id": "…", "watermark": { … } }
```

with **no `decision` field at all** — not `false`. A fabricated verdict a caller
cannot tell from a decided one is the most dangerous thing this interface could
return, so it does not return one.

## Checking the claims

The table above is not prose: it is a test plan, and `permguard test` runs it offline — the policy
is compiled here, so it holds before anything is applied to a plane.

```bash
permguard -w examples/dogwood-session-access test
```

A temporal case is a claim about **order**, so it is written as one: `events` are the occurrences
that happened first, applied in the order given, and `request` is the one whose verdict is judged.

```yaml
- name: a read inside the window is permitted by the login before it
  events:
    - ../events/1-login-request.json
    - ../events/2-login-response.json
  request: ../events/3-read-permitted.json
  expect: { decision: permit }
```

The plan deliberately contains that case and its opposite — the *same* read with no login before
it, which must be denied. Those two differ in nothing but the order, which is the property the whole
example is about, and a pair no stateless case could express.

What this does not check is the durable half: journalling, shipping, replication and restart are the
planes' own business and have their own tests. What it checks is that the policy decides what this
README says it decides.

## What is refused, and why

Half of a contract is what it will not accept, and it is the half an integration meets first. Each
file under `refusals/` is a submission somebody sends by accident:

```bash
for event in examples/dogwood-session-access/refusals/*.json; do
  curl -sS -X POST http://127.0.0.1:7656/temporal/v1alpha1/events \
    -H 'content-type: application/json' --data @"$event" | jq -c
done
```

| File | Status | `code` | Why |
| --- | --- | --- | --- |
| `unknown-action.json` | `400` | `event_action_undeclared` | the schema derives no `Drupe::Action::Delete`, so no temporal predicate could ever match it |
| `undeclared-field.json` | `400` | `event_field_undeclared` | `logged.input.clearance` is nobody's field: storing it would put a value in the record that the engine cannot see |
| `pin-disagrees.json` | `400` | `event_pin_contradicted` | the caller sent `callerPrincipal: bob` on a request whose principal is alice |
| `conflicting-retry.json` | `409` | `event_id_conflict` | one `event_id`, two different occurrences |

None of them is accepted with the offending part dropped. An event stored minus a field it claimed
to carry is an event that means something other than what was sent, and nothing downstream can tell.

`pin-disagrees.json` is the one worth reading twice. A pin decides **which history** an event
belongs to, so letting a caller supply it would let a caller choose whose history its event lands
in. Permguard derives the value from the request's authoritative root and refuses a caller's
disagreeing copy rather than picking one of the two.

Submitting the same occurrence twice is not in that table, because it is not an error in the same
sense: it answers `409 event_already_recorded`, naming the sequence that holds the one that *was*
recorded. It is neither stored again nor **observed** again — observing it twice is the one thing a
retry must never do, because a temporal engine counts occurrences.

## Restarting is not forgetting

Stop the plane after occurrence 2 and start it again. Occurrence 3 is still permitted.

That is not free, and it is the part of a temporal interface most likely to be got wrong: the
history is on disk, but the engine that decides against it holds its history in memory and starts
empty. A plane that answered before replaying would return a `deny` indistinguishable from a correct
one — the login it should have seen is on disk, and simply not in the engine.

So before an occurrence is observed, this plane makes sure the engine has seen what its ledger holds:
its own journal, and — under a shared mode — the imported history, merged into one ordered run and
replayed. It is paid once per fresh engine, not once per submission, and the same replay is what
absorbs history that arrives late from another plane.

## What every answer carries

```json
{
  "outcome": "decided",
  "decision": true,
  "watermark": { "instance": "…", "sequence": 3, "history": "sha256:…" },
  "history": { "mode": "local" }
}
```

`watermark` is where the occurrence sits in this plane's stream — proof it is
durable, and the coordinate a later read cites. `history.mode` says which history
the decision ranged over; with `pull.mode` set to a shared mode it also carries the
import watermark and how stale it was, so an auditor can reproduce exactly what
was visible.

## Reading it back

The events are shipped to the control plane, which is the only supported remote
source for reading them: a data plane's journal holds what its policies still read
and what has not yet been acknowledged, so a read there would answer differently
depending on which plane it reached.

```bash
permguard events list --zone acme --ledger agent-governance
permguard events get 01J8Z9-read-inside-window
permguard events verify --zone acme --ledger agent-governance --keys plane-keys.json
```

`verify` checks each record's digest against its inclusion path and the path
against the root its envelope attests; with `--keys` it also checks the envelope's
signature. The report says which of the two happened, because "verified" that
quietly skipped the signatures is worse than no verification at all.

## The order is the point

Submit occurrence 3 before occurrence 2 and it is denied: the login had not
happened yet. That is not a quirk to work around — it is the whole difference
between this interface and the stateless one, and it is why the event is made
durable *before* it is observed and before the answer is returned.

## Where this comes from

Adapted from Dogwood's own `dogwood-docs/examples/read_login_not_logout` bundle. Permguard changed
the wire format, the packaging and the deployment around it and preserved Dogwood's semantics — the
verdicts in the table above are the ones upstream records for the same trace, which is what
`crates/permguard-languages` asserts against upstream's corpus.

Dogwood is Apache-2.0: <https://github.com/dogwood-policy/dogwood>. The full attribution, including
the reviewed revision this build pins, is in [`NOTICE.md`](../../NOTICE.md). Neither Amazon nor the
Dogwood maintainers endorse this integration.

Dogwood support in Permguard is **experimental**: its wire and replication contracts are
`v1alpha1`, and a deployment serves them only by saying so — `experimental.dogwood.enabled: true`.
