---
pageClass: pg-page-concepts
title: Decision Path
description: What the Data Plane does with one request, from admission to an answer on record.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Decision path</div>
  <h1>One question. One answer, on record.</h1>
  <p>What the Data Plane does between your PEP's request and the answer it enforces.</p>
</div>

<div class="pgx-decision" role="img" aria-label="One request crosses five steps in the Data Plane: admit the caller and the request, select the verified version of the ledger, evaluate each partition with its engine, combine the results with the decision algebra, and record the decision durably before the answer leaves.">
  <div class="pgx-decision__rail"><i></i></div>
  <article><b>1</b><strong>Admit</strong><span>token · request shape</span></article>
  <article><b>2</b><strong>Select</strong><span>zone · ledger · verified version</span></article>
  <article><b>3</b><strong>Evaluate</strong><span>each partition, its engine</span></article>
  <article><b>4</b><strong>Combine</strong><span>decision algebra</span></article>
  <article><b>5</b><strong>Record</strong><span>durable, then answer</span></article>
</div>

## The question

The PEP sends who, does what, on what, under which facts, and names the zone and ledger that decide.

```sh
curl -sS -X POST http://127.0.0.1:7443/access/v1/evaluation \
  -H 'content-type: application/json' \
  -H 'x-request-id: quickstart-1' \
  -d '{
    "zone": "quickstart",
    "ledger": "policies",
    "subject": { "type": "User", "id": "alice" },
    "action": { "name": "read" },
    "resource": { "type": "Document", "id": "budget" },
    "context": {}
  }'
```

The same question from the CLI is `permguard check --subject User:alice --action read --resource Document:budget`, and from Go it is `client.Evaluate`.
An optional `profile` picks which of the ledger's partitions run; without it, the ledger's `default` profile.
The request never names an engine: the ledger's manifest binds each partition to one.

## Five steps

| Step         | What the Data Plane does                                                                    | When it cannot                                    |
| ------------ | ------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **Admit**    | In production, checks the caller's Authority Plane access token; then the request's shape.  | refusal, no decision                              |
| **Select**   | Finds its mirror of `zone/ledger` and reads the verified checkpoint: one version, whole.    | `ledger_not_served` 404 · `ledger_expired` 503    |
| **Evaluate** | Runs each partition of the profile with its own engine, Cedar or Rego, compiled per commit. | that partition returns an error, E                |
| **Combine**  | Reduces the partition results to one outcome with the decision algebra below.               | `evaluation_indeterminate` 503                    |
| **Record**   | Appends the decision to the signed, chained log, and waits until the record is durable.     | `decision_unrecordable` 503: no record, no answer |

## The decision algebra

Each partition returns one of four results; the profile combines them, in this order.

<div class="pgx-algebra">
  <article class="pgx-algebra--permit"><b>P</b><strong>Permit</strong><span>a policy allowed it</span></article>
  <article class="pgx-algebra--deny"><b>D</b><strong>Deny</strong><span>a policy refused it</span></article>
  <article><b>A</b><strong>Abstain</strong><span>no policy matched</span></article>
  <article class="pgx-algebra--error"><b>E</b><strong>Error</strong><span>evaluation could not complete</span></article>
</div>

<div class="pgx-resolution"><strong>Combine</strong><span>any deny → deny</span><span>else any error → indeterminate</span><span>else any permit → permit</span><span>else → deny by default</span></div>

Deny unless permitted.
An explicit deny and a deny by default both answer `decision: false`; `reason_admin` tells them apart, naming the denying policy or saying that no policy permits.
An indeterminate result is never a deny and never a permit: it leaves as a refusal, like a plane that cannot serve the ledger at all.

## Three outcomes

<div class="pgx-answers" role="img" aria-label="Three outcomes compared. Permit: HTTP 200, decision true, the policies that permitted it, recorded; the PEP may allow. Deny: HTTP 200, decision false, reason no policy permits this request, recorded; the PEP denies. Refusal: an HTTP error with a class and a code and no decision; the PEP treats it as a no.">
  <article class="pgx-answers__permit">
    <header><b>Permit</b><small>HTTP 200</small></header>
    <code>"decision": true</code>
    <p>Names the policies that permitted it, and the decision id.</p>
    <p>Recorded: <code>durable</code></p>
    <footer>PEP allows</footer>
  </article>
  <article class="pgx-answers__deny">
    <header><b>Deny</b><small>HTTP 200</small></header>
    <code>"decision": false</code>
    <p>A normal answer: <em>no policy permits this request</em>.</p>
    <p>Recorded: <code>durable</code></p>
    <footer>PEP denies</footer>
  </article>
  <article class="pgx-answers__refusal">
    <header><b>Refusal</b><small>HTTP 4xx · 5xx</small></header>
    <code>"class", "code"</code>
    <p>No decision was made: an error, not a deny.</p>
    <p>No decision to record</p>
    <footer>PEP treats it as a no</footer>
  </article>
</div>

The real answers of the Data Plane 0.1.33 to the request above, for `alice`, for `bob`, and for a plane that does not serve `quickstart/policies`:

::: code-group

```json [Permit]
{
  "decision": true,
  "request_id": "quickstart-1",
  "context": {
    "id": "01a1f111-df65-77cf-b171-3facea0cbc27",
    "reason_admin": {
      "code": "200",
      "message": "permitted by 92efe24a-8620-8bcd-b026-a19c1f440c45"
    },
    "reason_user": { "code": "200", "message": "permitted" },
    "policies": ["92efe24a-8620-8bcd-b026-a19c1f440c45"],
    "evidence": {
      "mode": "required",
      "status": "durable",
      "record_id": "01a1f111-df65-77cf-b171-3facea0cbc27",
      "position": {
        "host_id": "01a1f110-6550-759a-8d3a-b48851feacbb",
        "run": "683d0666310e237b02cd1c2ea4106c6d",
        "sequence": "2"
      }
    }
  }
}
```

```json [Deny]
{
  "decision": false,
  "request_id": "quickstart-2",
  "context": {
    "id": "01a1f111-df7c-737b-82ef-9208ea5e1685",
    "reason_admin": {
      "code": "403",
      "message": "no policy permits this request"
    },
    "reason_user": {
      "code": "403",
      "message": "insufficient privileges. Contact your administrator"
    },
    "evidence": {
      "mode": "required",
      "status": "durable",
      "record_id": "01a1f111-df7c-737b-82ef-9208ea5e1685",
      "position": {
        "host_id": "01a1f110-6550-759a-8d3a-b48851feacbb",
        "run": "683d0666310e237b02cd1c2ea4106c6d",
        "sequence": "3"
      }
    }
  }
}
```

```json [Refusal]
{
  "class": "not_found",
  "code": "ledger_not_served",
  "message": "this plane does not serve `quickstart/policies`"
}
```

:::

`request_id` echoes the caller's `x-request-id`.
`reason_admin` is for operators; `reason_user` is safe to show the user.

### Fail closed

A refusal, a timeout or no answer at all is not a decision.
The PEP treats every one of them as a no.
In the Go SDK a deny is a response with `Decision == false`, and a refusal is an error of type `*permguard.Refusal`:

```go
func mayRead(ctx context.Context, client *permguard.Client, user string) bool {
    response, err := client.Evaluate(ctx, &permguard.EvaluateRequest{
        Zone:     "quickstart",
        Ledger:   "policies",
        Subject:  &permguard.Entity{Type: "User", ID: user},
        Action:   &permguard.Action{Name: "read"},
        Resource: &permguard.Entity{Type: "Document", ID: "budget"},
    })
    if err != nil {
        var refusal *permguard.Refusal
        if errors.As(err, &refusal) {
            log.Printf("refused: class=%s code=%s", refusal.Class, refusal.Code)
        }
        return false // no decision is a no
    }
    return response.Decision
}
```

The refusals of the decision path, by class:

| Class         | Code                       | HTTP | Means                                                          |
| ------------- | -------------------------- | ---: | -------------------------------------------------------------- |
| `not_found`   | `ledger_not_served`        |  404 | this plane does not mirror that ledger                         |
| `validation`  | `profile_unknown`          |  400 | the ledger has no such profile                                 |
| `unavailable` | `evaluation_indeterminate` |  503 | a partition failed and no policy denied: not a deny            |
| `unavailable` | `ledger_incompatible`      |  503 | this engine cannot serve the ledger's current commit           |
| `unavailable` | `ledger_expired`           |  503 | the mirror is older than the deployment's `expire_after` bound |
| `unavailable` | `decision_unrecordable`    |  503 | the record cannot be made durable, so the decision is withheld |

## On record before it leaves

By default the evidence mode is `required`: the answer leaves only once its record is durable.
`evidence.record_id` is the decision id, `context.id`; `position` is where the record sits in its Host's chain, and the deny above took the next `sequence`.
A deployment can choose `best_effort` or `disabled` instead, and `evidence.status` then says what became of the record.

Read a decision back by the id the PEP was given:

```sh
permguard decisions get 01a1f111-df65-77cf-b171-3facea0cbc27 \
  --zone quickstart --ledger policies
```

How records are signed, chained and verified is in [Verifiable Evidence](./evidence).

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-lifecycle"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy Delivery</strong></a>
  <a class="pgx-pager__next" href="./evidence"><span>Next</span><strong>Verifiable Evidence <b aria-hidden="true">→</b></strong></a>
</nav>
