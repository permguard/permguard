---
pageClass: pg-page-concepts
title: Access Tokens & Clusters
description: The Authority Plane issues the access tokens every Plane of the cluster decides by, offline, revocable within a bound you choose.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Access tokens</div>
  <h1>One Authority Plane. Every Plane decides by its tokens.</h1>
  <p>The Authority Plane keeps the service accounts and issues short-lived access tokens; each Plane and Host checks them offline, against keys and revocation lists it fetched itself.</p>
</div>

## The cluster

| Server                       | Runs                                 | Holds                                                    | Decides by         |
| ---------------------------- | ------------------------------------ | -------------------------------------------------------- | ------------------ |
| the Authority Plane's Server | the Authority Plane, a Control Plane | the service accounts, the `authority.tokens` keys, lists | the tokens' scopes |
| any other Server             | a Control or Data Plane, or both     | the keys and lists it fetched from `authority.url`       | the tokens' scopes |

A Server without the Authority Plane fetches its keys every five minutes, and at once for a key it does not know, at most once a minute; it fetches each status list every half of its `ttl`.
What it fetched is kept on its volume, so a restart without the Authority Plane still decides.

## Verifying a token

Every request with a bearer token is checked, in order, before anything is decided:

1. its shape and size, and that it is an `at+jwt`;
2. its signature, under a key of the held `authority.tokens` set;
3. its issuer, `authority.url`, and its audience, `permguard` unless `authority.audience` says otherwise;
4. its validity, within the Host's clock skew;
5. its status, `VALID` in the list it names;
6. its scopes, against the operation and the resource the request names.

A token refused at any step is `401` with `WWW-Authenticate: Bearer error="invalid_token"`; a token without the scope is `403` with `error="insufficient_scope"`.

## Revocation

A token revoked, an account suspended or deleted, a key deleted: the Authority Plane marks each token in its status list, and every Plane refuses it once it holds the new list, within half the list's `ttl`.

```sh
permguard authority tokens list --account billing
permguard authority tokens revoke <jti>
```

## Signals

| Metric                                       | Meaning                                                     |
| -------------------------------------------- | ----------------------------------------------------------- |
| `permguard_token_status_list_age_seconds`    | how old each held list is                                   |
| `permguard_token_status_lists_expired`       | lists held past their expiry: every token they name refused |
| `permguard_authority_refresh_failures_total` | fetches of the keys or lists that failed                    |
| `permguard_token_status_list_rejected_total` | lists refused for their signature, issuer or time           |
