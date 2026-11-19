---
pageClass: pg-page-concepts
title: Policy as Code
description: Cedar and Rego side by side in one ledger, bound by a manifest, tested offline and decided under one rule.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Policy as code</div>
  <h1>Policies are code.</h1>
  <p>Cedar and Rego, side by side in one ledger: versioned, tested offline, decided under one rule.</p>
</div>

<div class="pgx-languages">
  <article>
    <div class="pgx-language-mark">C</div>
    <div><span>Stable</span><h2>Cedar</h2><p>Typed rules over principal, action and resource, checked against a schema.</p><strong>Best for · application permissions</strong></div>
  </article>
  <article>
    <div class="pgx-language-mark">R</div>
    <div><span>Stable</span><h2>Rego</h2><p>Rules over the request as JSON: <code>input.subject</code>, <code>input.action</code>, <code>input.resource</code>.</p><strong>Best for · contextual guardrails</strong></div>
  </article>
  <article class="pgx-languages__experimental">
    <div class="pgx-language-mark" aria-hidden="true"><svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 2.64-6.36"/><path d="M3 4v4h4"/><path d="M12 7.5V12l3 2"/></svg></div>
    <div><span>Experimental</span><h2>Dogwood</h2><p>Rules over verified history: what already happened, and within which window.</p><strong>Best for · decisions from history</strong></div>
  </article>
</div>

## Two languages, one ledger

A workspace is a folder: a manifest and the policy files.
This one is `examples/basics` in the Permguard repository.

```txt
examples/basics/
├── manifest.yml            two runtimes, two partitions, two pdp profiles
├── cedar/documents.cedar   two Cedar policies (@alias on each)
├── cedar/model.cedarschema the Cedar schema — one per partition, at most
├── rego/gateway.rego       one Rego module (# METADATA custom.alias)
└── requests/*.json         decision requests to send with `permguard check`
```

<div class="pgx-anatomy">
  <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>Cedar</b><span><code>cedar/documents.cedar</code>: the finance group reads; owners write.</span></div>

```cedar
// The application policies: who may do what on documents.

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

</div>
  <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>Rego</b><span><code>rego/gateway.rego</code>: users read; only admins mutate.</span></div>

```rego
# METADATA
# custom:
#   alias: gateway-access
package gateway.access

import rego.v1

default allow := false

# Users may read; only admins may mutate.
#
# The types are the ledger's vocabulary — the ones the Cedar schema beside this
# partition declares. One request reaches every partition of a profile, so the
# two speak the same nouns.
allow if {
    input.subject.type == "User"
    input.action.name == "read"
}

allow if {
    input.subject.properties.role == "admin"
    input.action.name in {"create", "update", "delete"}
}
```

</div>
</div>

Every policy carries an alias: `@alias` in Cedar, `custom.alias` in the Rego METADATA.
Plans and tests cite policies by alias; an answer cites the policy's identity, never a file name.

## The manifest binds them

<div class="pgx-binding" role="img" aria-label="One ledger's manifest declares two partitions, cedar owning documents.cedar and its schema, rego owning gateway.rego. The profile default evaluates both partitions and is used when a request names no profile; the profile gateway evaluates rego alone.">
  <div class="pgx-binding__label"><strong>One ledger · <code>manifest.yml</code></strong><span>partitions own files · profiles pick partitions</span></div>
  <div class="pgx-binding__grid">
    <div class="pgx-binding__col">
      <small>PARTITIONS</small>
      <article class="pgx-binding__part--cedar"><strong>cedar</strong><span>runtime cedar · schema · entity input</span><code>documents.cedar</code><code>model.cedarschema</code></article>
      <article class="pgx-binding__part--rego"><strong>rego</strong><span>runtime rego · reads the request alone</span><code>gateway.rego</code></article>
    </div>
    <div class="pgx-binding__link" aria-hidden="true"><b>→</b></div>
    <div class="pgx-binding__col">
      <small>PROFILES</small>
      <article><strong>default</strong><span>used when the request names no profile</span><div class="pgx-binding__chips"><i>cedar</i><i class="is-rego">rego</i></div></article>
      <article><strong>gateway</strong><span><code>"profile": "gateway"</code></span><div class="pgx-binding__chips"><i class="is-rego">rego</i></div></article>
    </div>
  </div>
</div>

```yaml
runtimes:
  cedar:
    language: { name: cedar, constraint: ">=4.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
  rego:
    language: { name: rego, constraint: ">=1.0.0" }
    engine:   { name: permguard, constraint: ">=0.1.0 <0.2.0" }
partitions:
  # `input` is what a request may hand each partition, and the ledger decides it.
  # The Cedar partition reads an entity store; the Rego module here reads the
  # request alone, so it declares no input and anything addressed to it is refused.
  cedar:
    runtime: cedar
    schema: true
    input: { type: permguard.cedar.entities.v1, required: false }
  rego:
    runtime: rego
    schema: false
profiles:
  # Both partitions answer one request. They therefore share one vocabulary:
  # the entity types the Cedar schema declares (`User`, `Document`, `Group`)
  # are the ledger's, and the Rego module reads the same ones.
  default: { type: permguard.api.pdp.native.v1, partitions: [cedar, rego] }
  # Only the gateway's rules. What a profile is *for*: the same ledger, a
  # narrower contract — here, questions the Cedar schema does not declare
  # (`create`, `update`, `delete`) and therefore could not evaluate.
  gateway: { type: permguard.api.pdp.native.v1, partitions: [rego] }
```

| Term      | What it is                                                                    | In `basics`                         |
| --------- | ----------------------------------------------------------------------------- | ----------------------------------- |
| runtime   | a language and the engine versions the ledger accepts                         | `cedar`, `rego`                     |
| partition | policies owned by exactly one runtime, with its schema and the input it takes | `cedar`, `rego`                     |
| profile   | the partitions one request is evaluated against, under one interface          | `default`: both · `gateway`: `rego` |

`subject`, `action`, `resource` and `context` reach every partition of the profile; `partition_inputs` reaches one, by the partition's name.
A request picks the profile:

```json
{
  "profile":  "gateway",

  "subject":  { "type": "User", "id": "dora", "properties": { "role": "admin" } },
  "action":   { "name": "create" },
  "resource": { "type": "Document", "id": "q4-forecast" }
}
```

## One rule across languages

Each partition answers; the profile resolves them in this order.

<div class="pgx-algebra" role="img" aria-label="Partition answers resolve in order: any explicit deny gives deny; otherwise any failure gives indeterminate, refused; otherwise any permit gives permit; otherwise deny by default.">
  <article class="pgx-algebra--deny"><b>1</b><strong>Deny</strong><span>any partition denied explicitly, whatever else failed</span></article>
  <article class="pgx-algebra--error"><b>2</b><strong>Indeterminate</strong><span>any partition failed: refused, never a permit</span></article>
  <article class="pgx-algebra--permit"><b>3</b><strong>Permit</strong><span>any partition permitted, none denied or failed</span></article>
  <article><b>4</b><strong>Deny</strong><span>nothing permitted: absent means no</span></article>
</div>

The CLI and the Data Plane share one definition of this rule, so a test that passes offline decides the same way in production.

## Prove it before you publish

```sh
permguard -w examples/basics validate    # Cedar + Rego parse, schema, identities
permguard -w examples/basics test        # the cases below, offline
```

```yaml
- name: a member of the finance group may read a document
  request: ../requests/permit.json
  # Both partitions permit it, and the decision cites both: the Cedar policy that
  # permits the finance group, and the Rego module that lets any User read. Either
  # alone would be enough — which is why the reason names them.
  expect: { decision: permit, policies: [document-readers, gateway-access] }

- name: writing a document somebody else owns is refused
  request: ../requests/deny.json
  # Nothing permitted it: neither partition said yes.
  expect: { decision: deny, policies: [] }

- name: the gateway profile answers with Rego alone
  request: ../requests/gateway-permit.json
  expect: { decision: permit, policies: [gateway-access] }
```

Start a new workspace in both languages with `permguard init <name> --language cedar,rego`.

## Choose by question

| If the question is…                                       | Write it in |
| --------------------------------------------------------- | ----------- |
| “May this user perform this action on this resource?”     | Cedar       |
| “Does this structured request satisfy operational rules?” | Rego        |
| “May this happen after those verified events?”            | Dogwood     |

Dogwood reads history the request cannot carry, here a login within the hour:

```dogwood
@id("read_after_login")
permit (
    principal,
    action == Drupe::Action::"Read",
    resource
)
when temporal {
    formerly within 1h Drupe::Action::"Login"::response{ input.user: context.input.user }
    && !Drupe::Action::"Logout"::response{ input.user: context.input.user }
};
```

<div class="pgx-note"><strong>Experimental.</strong><span>Dogwood answers through its own temporal profile and is off unless the server enables it. See <a href="./temporal-authorization">Temporal Authorization</a>.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./architecture"><span>Previous</span><strong><b aria-hidden="true">←</b> Server, Host &amp; Planes</strong></a>
  <a class="pgx-pager__next" href="./zones-and-ledgers"><span>Next</span><strong>Zones &amp; Ledgers <b aria-hidden="true">→</b></strong></a>
</nav>
