---
pageClass: pg-page-concepts
title: Temporal Authorization
description: Decisions that depend on what already happened, written in Dogwood, an experimental policy language.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Temporal authorization · experimental</div>
  <h1>Decide from what happened.</h1>
  <p>Some answers depend on the past: Permguard records what happened, in order, and the policy reads it.</p>
</div>

## The idea

Temporal authorization means decisions that depend on what already happened.
An ordinary [policy](./glossary#policy) sees only the request: who asks, to do what, on what.
A temporal policy also sees the history before it, so it can say: alice may read the report only within an hour after logging in, and not after she logs out.

<ol class="pgx-tline" aria-label="One user's day, in order. A read before any login is denied. Then alice logs in, and the login is recorded. A read inside the hour after the login is permitted. Then alice logs out, and the logout is recorded. A read after the logout is denied.">
  <li class="is-deny"><small>FIRST</small><strong>Read</strong><span>no login yet</span><em>Deny</em></li>
  <li class="is-event"><small>THEN</small><strong>Login</strong><span>recorded in the history</span><em>Event</em></li>
  <li class="is-permit"><small>WITHIN 1H</small><strong>Read</strong><span>a login before it, no logout</span><em>Permit</em></li>
  <li class="is-event"><small>LATER</small><strong>Logout</strong><span>recorded in the history</span><em>Event</em></li>
  <li class="is-deny"><small>AFTER</small><strong>Read</strong><span>logged out</span><em>Deny</em></li>
</ol>

The same read gets a different answer, and nothing in the request changed: only the history did.
Once the hour has passed, the read is denied too.

## In practice

Each event, a login or a logout, is recorded in order before Permguard uses it.
The policy reads that history.
The language is Dogwood, and this is the real policy of the example in `examples/dogwood-session-access`:

```dogwood
// Permit a Read only if the same user logged in within the last hour
// and has not logged out since.
@id("read_after_login")
permit (
    principal,
    action == Drupe::Action::"Read",
    resource
)
when temporal {
    !Drupe::Action::"Logout"::response{ input.user: context.input.user }
    since within 1h
    Drupe::Action::"Login"::response{ input.user: context.input.user }
};
```

`since` reads in time order: a login within the last hour, and no logout at any step after it.
Its tests run offline: a read inside the window is permitted, and a read with no login before it, after a logout, outside the window, or after another user's login is denied.

<div class="pgx-note"><strong>Experimental.</strong><span>Dogwood and the event stores are off in an ordinary server. Turn both on when you start the all-in-one image of <a href="./getting-started">Getting Started</a>.</span></div>

```sh
docker run -d --name permguard \
  -p 5443:5443 -p 6443:6443 -p 7443:7443 -p 8443:8443 \
  -e PERMGUARD_EXPERIMENTAL_DOGWOOD_ENABLED=true \
  -e PERMGUARD_EVENTS_ENABLED=true \
  -v "$PWD/permguard.yml:/etc/permguard/config.yml:ro" \
  ghcr.io/permguard/permguard/all-in-one:${VERSION}
```

## Why it matters

<div class="pgx-principles">
  <article><span>Developers</span><h3>No session state in your code.</h3><p>The application records what happened; the rule about it lives in one policy.</p></article>
  <article><span>Platform &amp; IT</span><h3>Off until you turn it on.</h3><p>It is experimental, and an ordinary server runs without it.</p></article>
  <article><span>Security &amp; CISO</span><h3>Rules that follow the sequence.</h3><p>Answer questions a single request cannot: did login succeed before this read, was this deployment approved.</p></article>
</div>

## Go deeper

<div class="pgx-link-grid">
  <a href="./policy-languages"><strong>Policy as Code</strong><span>Cedar · Rego · Dogwood</span></a>
  <a href="../data-plane"><strong>Data Plane</strong><span>where decisions are made</span></a>
  <a href="./getting-started"><strong>Getting Started</strong><span>start the server</span></a>
  <a href="./glossary"><strong>Glossary</strong><span>every term, in one line</span></a>
</div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./policy-languages"><span>Previous</span><strong><b aria-hidden="true">←</b> Policy as Code</strong></a>
  <a class="pgx-pager__next" href="./zones-and-ledgers"><span>Next</span><strong>Zones &amp; Ledgers <b aria-hidden="true">→</b></strong></a>
</nav>
