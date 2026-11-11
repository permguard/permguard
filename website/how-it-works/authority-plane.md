---
pageClass: pg-page-concepts
title: Authority Plane
description: Service accounts, access keys and the access tokens every Plane of the cluster verifies.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Authority Plane</div>
  <h1>One authority. Every Plane verifies its tokens.</h1>
  <p>Service accounts hold scopes and access keys; the Authority Plane issues short-lived access tokens, and every Plane and Host checks them itself, offline, against keys and revocation lists it holds.</p>
</div>

## The model

| Step             | Who does it                     | What it produces                                                   |
| ---------------- | ------------------------------- | ------------------------------------------------------------------ |
| who is calling   | the Authority Plane's token     | the service account `sa:<name>` it was issued to                   |
| what they may do | the token's scopes              | operations on a selector, the account's or a narrower set it asked |
| where it is read | every Plane and Host, by itself | the signature, issuer, audience, validity, status and scopes       |

A token decides alone: a public grant never widens what it carries.
The same scopes answer on every surface, over REST and over gRPC, and a route a token does not cover is refused: `401` for nobody or a refused token, `403` for a token without the scope.
A certificate acts only as a Host's bootstrap principal, its recovery access committed offline with `host grants bootstrap`.

## Where it runs

The Authority Plane is a Plane like the others, on its own listener, port 8443 in the shipped configurations, over REST at `/authority/v1` and gRPC in `permguard.authority.v1`.
In an all-in-one it runs beside the Control and Data Planes, and hands its keys and lists to them in-process; in a cluster it runs beside the Control Plane, and every other Server fetches them from `authority.url`.

```yaml
runtime: { planes: [authority, control, data] }
authority:
  url: "https://permguard.example:8443"     # what every token names as its issuer
authorityPlane:
  public:
    http: { addr: 0.0.0.0:8443, tls: { cert: tls/server.pem, key: tls/server.key } }
    grpc: { addr: 0.0.0.0:8443, tls: { cert: tls/server.pem, key: tls/server.key } }
```

## The administrator

The Authority Plane's first start makes the service account `admin`, with every operation on the Host and every Plane.
Its access key and secret key are written to `planes/authority/admin.key` on the volume, readable by its owner alone; the log names the access key, never the secret.
Move the file somewhere safe and delete it.
`admin` is never deleted and never left without a live key; when every key is lost, `permguard authority admin-key --volume <dir> --secret-out <file>` makes a new one on the stopped server's volume, and the next start records it in the audit trail.

## Service accounts, scopes and keys

```sh
permguard authority service-accounts create billing --description "the billing service" \
  --scope 'decision.evaluate,event.submit@plane/data/zone/<zone-id>/*'
permguard authority keys create billing --secret-out ./billing.key     # written once, 0600
permguard authority scopes set billing --scope 'decision.evaluate@plane/data/*' --revoke-tokens
```

| Rule        | Meaning                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------ |
| scopes      | at most 64, each operations on a selector they apply to: one that never allows is refused  |
| access keys | at most two live per account; `pgak_` and 20 characters, the secret `pgsk_` and 43         |
| secrets     | answered once, in the file they are written to; the Authority Plane keeps an Argon2id hash |
| suspension  | a suspended account obtains no token, and every token it holds is refused                  |
| deletion    | an account or a key deleted takes every live token it obtained with it                     |

## Tokens

A program obtains a token at `POST /authority/v1/token` with `grant_type=client_credentials`, its access key and secret key in `Authorization: Basic`, over TLS.
The token is an RFC 9068 `at+jwt` signed by the `authority.tokens` ring, an hour long unless asked shorter, carrying the account's scopes or the narrower ones asked.

```sh
permguard --authority-endpoint https://permguard.example:8443 --secret-key-file ./billing.key \
  --data-endpoint https://data-plane.example:7443 \
  check -f request.json --zone <zone-id> --ledger <ledger-id>
```

The command line obtains, caches and renews its own token; a secret key travels only over verified TLS.
See [Access Tokens & Clusters](./access-tokens) for how each Plane verifies and revokes them.
