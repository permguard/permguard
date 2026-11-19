---
pageClass: pg-page-concepts
title: Zones & Ledgers
description: The zone is the security boundary; each ledger belongs to exactly one zone, and every request names both.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Zones &amp; ledgers</div>
  <h1>The zone is the boundary.</h1>
  <p>A zone holds one or more ledgers. A ledger belongs to exactly one zone. Every request names both.</p>
</div>

<figure class="pgx-zl" role="img" aria-label="Two zones, acme and billing, each a security boundary. Zone acme holds the ledgers main-ledger and sessions; zone billing holds the ledger invoices. A request naming zone acme and ledger main-ledger reaches that one ledger. A ledger drawn across both zones is refused: a ledger carries one zone id.">
  <svg class="pgx-zl__wide" viewBox="0 0 960 384" aria-hidden="true" focusable="false">
    <rect class="pgx-zl__zone" x="268" y="20" width="372" height="344" rx="18"/>
    <text class="pgx-zl__k" x="292" y="50">ZONE · ACME</text>
    <text class="pgx-zl__m" x="292" y="70">security boundary</text>
    <rect class="pgx-zl__ledger pgx-zl__ledger--target" x="292" y="92" width="324" height="76" rx="12"/>
    <text class="pgx-zl__s" x="312" y="124">main-ledger</text>
    <text class="pgx-zl__m" x="312" y="148">policies · commits · signed head</text>
    <rect class="pgx-zl__ledger" x="292" y="184" width="324" height="76" rx="12"/>
    <text class="pgx-zl__s" x="312" y="216">sessions</text>
    <text class="pgx-zl__m" x="312" y="240">its own history and head</text>
    <rect class="pgx-zl__zone pgx-zl__zone--other" x="688" y="20" width="256" height="344" rx="18"/>
    <text class="pgx-zl__k" x="712" y="50">ZONE · BILLING</text>
    <text class="pgx-zl__m" x="712" y="70">another boundary</text>
    <rect class="pgx-zl__ledger" x="712" y="92" width="208" height="76" rx="12"/>
    <text class="pgx-zl__s" x="732" y="124">invoices</text>
    <text class="pgx-zl__m" x="732" y="148">outside acme's grants</text>
    <rect class="pgx-zl__ghost" x="548" y="284" width="232" height="60" rx="12"/>
    <text class="pgx-zl__ghost-s" x="664" y="310" text-anchor="middle">never in two zones</text>
    <text class="pgx-zl__m" x="664" y="330" text-anchor="middle">a ledger carries one zone id</text>
    <g class="pgx-zl__x"><circle cx="548" cy="284" r="11"/><path d="M543.5 279.5 L552.5 288.5 M552.5 279.5 L543.5 288.5"/></g>
    <rect class="pgx-zl__request" x="16" y="126" width="216" height="124" rx="14"/>
    <text class="pgx-zl__k" x="34" y="154">REQUEST</text>
    <text class="pgx-zl__c" x="34" y="184"><tspan>zone</tspan>   acme</text>
    <text class="pgx-zl__c" x="34" y="208"><tspan>ledger</tspan> main-ledger</text>
    <text class="pgx-zl__m" x="34" y="234">+ subject · action · resource</text>
    <path class="pgx-zl__flow" d="M232 188 H256 V130 H284"/>
    <path class="pgx-zl__head" d="M284 124 L292 130 L284 136 Z"/>
  </svg>
  <svg class="pgx-zl__compact" viewBox="0 0 360 648" aria-hidden="true" focusable="false">
    <rect class="pgx-zl__request" x="16" y="8" width="328" height="112" rx="14"/>
    <text class="pgx-zl__k" x="32" y="34">REQUEST</text>
    <text class="pgx-zl__c" x="32" y="62"><tspan>zone</tspan>   acme</text>
    <text class="pgx-zl__c" x="32" y="86"><tspan>ledger</tspan> main-ledger</text>
    <text class="pgx-zl__m" x="32" y="108">+ subject · action · resource</text>
    <path class="pgx-zl__flow" d="M180 124 V184"/>
    <rect class="pgx-zl__zone" x="16" y="144" width="328" height="272" rx="18"/>
    <text class="pgx-zl__k" x="32" y="170">ZONE · ACME</text>
    <rect class="pgx-zl__ledger pgx-zl__ledger--target" x="32" y="198" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="230">main-ledger</text>
    <text class="pgx-zl__m" x="48" y="254">policies · commits · signed head</text>
    <path class="pgx-zl__flow" d="M180 144 V186"/>
    <path class="pgx-zl__head" d="M174 188 L180 196 L186 188 Z"/>
    <rect class="pgx-zl__ledger" x="32" y="288" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="320">sessions</text>
    <text class="pgx-zl__m" x="48" y="344">its own history and head</text>
    <rect class="pgx-zl__zone pgx-zl__zone--other" x="16" y="444" width="328" height="196" rx="18"/>
    <text class="pgx-zl__k" x="32" y="504">ZONE · BILLING</text>
    <rect class="pgx-zl__ledger" x="32" y="518" width="296" height="76" rx="12"/>
    <text class="pgx-zl__s" x="48" y="550">invoices</text>
    <text class="pgx-zl__m" x="48" y="574">outside acme's grants</text>
    <rect class="pgx-zl__ghost" x="44" y="388" width="272" height="80" rx="12"/>
    <text class="pgx-zl__ghost-s" x="180" y="422" text-anchor="middle">never in two zones</text>
    <text class="pgx-zl__m" x="180" y="446" text-anchor="middle">a ledger carries one zone id</text>
    <g class="pgx-zl__x"><circle cx="44" cy="388" r="11"/><path d="M39.5 383.5 L48.5 392.5 M48.5 383.5 L39.5 392.5"/></g>
  </svg>
</figure>

## Two records, one rule

| Rule     | Zone                                                       | Ledger                                                    |
| -------- | ---------------------------------------------------------- | --------------------------------------------------------- |
| holds    | one or more ledgers                                        | policies, as commits under a signed head                  |
| address  | `plane/<plane>/zone/<zone_id>`                             | `…/zone/<zone_id>/ledger/<ledger_id>`: one zone, for life |
| name     | lowercase `a-z`, `0-9`, `-`, `_`; unique in the deployment | unique within its zone                                    |
| identity | a permanent GUID; a rename never changes it                | a permanent GUID; a rename never changes it               |
| retire   | delete, refused while it still holds ledgers               | delete, or archive: still readable and mirrored, no push  |

Nothing moves a ledger between zones: its record carries one `zone_id`, and an update changes only its name.

## Zone, ledger, partition

Three levels, each inside the one above.
The zone is the boundary, the ledger is the history, and the partition is where the policies of one language live.

<div class="pgx-nest" role="img" aria-label="The zone acme contains the ledger main-ledger. Every commit of the ledger carries its manifest, which declares the runtimes, the partitions and the profiles. The partition cedar holds the Cedar policies and schema; the partition rego holds the Rego module. The profile default evaluates both partitions; the profile gateway evaluates rego alone.">
  <div class="pgx-nest__zone">
    <div class="pgx-nest__head"><small>ZONE · acme</small><span>the security boundary</span></div>
    <div class="pgx-nest__ledger">
      <div class="pgx-nest__head"><small>LEDGER · main-ledger</small><span>commits under a signed head</span></div>
      <div class="pgx-nest__manifest"><code>manifest.yml</code><span>runtimes · partitions · profiles, in every commit</span></div>
      <div class="pgx-nest__parts">
        <div class="pgx-nest__part"><small>PARTITION · cedar</small><span>Cedar runtime, with its schema</span><code>cedar/documents.cedar</code></div>
        <div class="pgx-nest__part"><small>PARTITION · rego</small><span>Rego runtime</span><code>rego/gateway.rego</code></div>
      </div>
      <div class="pgx-nest__profiles"><span><b>profile default</b> evaluates cedar + rego</span><span><b>profile gateway</b> evaluates rego</span></div>
    </div>
  </div>
</div>

| Level     | What it is                                               | What it holds                                         | How a request names it            |
| --------- | -------------------------------------------------------- | ----------------------------------------------------- | --------------------------------- |
| Zone      | the security boundary                                    | one or more ledgers                                   | `zone`                            |
| Ledger    | the versioned history of one set of policies             | commits, each with its manifest and partitions        | `ledger`                          |
| Partition | the policies of exactly one runtime, Cedar or Rego       | policy files, a schema, the input it accepts          | through `profile`, else `default` |

The manifest is the ledger's contract: which runtimes it uses, which partitions exist, and which partitions each profile evaluates.
From `examples/basics/manifest.yml`, trimmed:

```yaml
partitions:
  cedar:
    runtime: cedar
    schema: true
    input: { type: permguard.cedar.entities.v1, required: false }
  rego:
    runtime: rego
    schema: false
profiles:
  default: { type: permguard.api.pdp.native.v1, partitions: [cedar, rego] }
  gateway: { type: permguard.api.pdp.native.v1, partitions: [rego] }
```

A request reaches every partition of its profile, and the answers combine under one rule.
How languages, partitions and profiles work together is in [Policy as Code](./policy-languages).

## Why a zone is a boundary

Every call lands on one concrete resource in one tree, and the zone sits above the ledger in it:

```txt
plane/control/zone/<zone_id>/ledger/<ledger_id>    push, pull, read decisions and events
plane/data/zone/<zone_id>/ledger/<ledger_id>       decide, submit events
```

A grant is a scope: operations on a selector, an exact resource or one ending in `/*` for everything under it.
Matching is by whole path segment, so a zone's grant never spills into another zone.

| Selector                                       | Covers                                 |
| ---------------------------------------------- | -------------------------------------- |
| `plane/data/zone/<zone-id>/ledger/<ledger-id>` | that one ledger                        |
| `plane/data/zone/<zone-id>/*`                  | the zone and every ledger in it        |
| `plane/data/*`                                 | every zone of the Data Plane           |
| `plane/data/zone/*`                            | refused: no selector cuts across zones |

Give each workload the zone it needs and nothing more:

```sh
permguard authority service-accounts create pusher --description "CI policy push" \
  --scope 'policy.push@plane/control/zone/<zone-id>/*'
permguard authority service-accounts create billing --description "the billing service" \
  --scope 'decision.evaluate,event.submit@plane/data/zone/<zone-id>/*'
```

A token decides alone, and absence of a grant is a deny: `403` for a token without the scope.
The Data Plane's compiled-policy cache is budgeted per zone too: a zone over its bound evicts its own entries, never another zone's.

## Every decision names zone and ledger

A request carries both, and the answer comes from that ledger's published head:

```json
{
  "zone": "quickstart",
  "ledger": "policies",
  "subject": { "type": "User", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "Document", "id": "budget" },
  "context": {}
}
```

From a workspace, `permguard check` takes both from the checkout, so the request file stays portable between ledgers.
Outside one, or to override it, name them:

```sh
permguard check -f request.json --zone delivery --ledger release-pipeline
permguard decisions list --zone delivery --ledger release-pipeline
```

## Create and use them

```sh
permguard zones create acme
permguard ledgers create main-ledger --zone acme
permguard ledgers list --zone acme
```

Then bind a workspace to the ledger, as `<remote>/<zone>/<ledger>[@<ref>]`, and publish into it:

```sh
permguard remote add origin https://permguard.internal:6443
permguard checkout origin/acme/main-ledger
permguard plan
permguard apply -m "first policies"
```

The catalog commands reach the Control Plane at `--control-endpoint`, or `PERMGUARD_CONTROL_PLANE_ENDPOINT`.

| When you need to…              | Run                                                                        |
| ------------------------------ | -------------------------------------------------------------------------- |
| stop pushes, keep serving      | `permguard ledgers archive --zone acme main-ledger`                        |
| take pushes again              | `permguard ledgers restore --zone acme main-ledger`                        |
| re-home a zone on another Host | `permguard zones export acme --out acme.export`, then `zones import` there |
| remove a zone                  | delete its ledgers, then `permguard zones delete acme`                     |

<div class="pgx-note"><strong>One zone per blast radius.</strong><span>Put together what one team governs and one grant may reach. Split what must never share a token.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-languages"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy as Code</strong></a>
  <a class="pgx-pager__next" href="./policy-storage"><span>Next</span><strong>Git-like Versioning <b aria-hidden="true">→</b></strong></a>
</nav>
