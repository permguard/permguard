---
pageClass: pg-page-concepts
title: Identity & Access
description: Sign operators in with your identity providers or local users, and authorize them with roles the Host keeps.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Identity & access</div>
  <h1>Your provider says who. Permguard says what.</h1>
  <p>Operators sign in with Entra, Okta, Keycloak, Auth0 or a local password; every HTTP and gRPC route then decides with grants and roles the Host keeps.</p>
</div>

## The model

Permguard separates authentication from authorization.

| Step             | Who does it                  | What it produces                                                          |
| ---------------- | ---------------------------- | ------------------------------------------------------------------------- |
| who is calling   | a client certificate         | the principal its SAN URI or key names                                    |
|                  | an identity provider's token | `oidc:<issuer>#<subject>`, or the local user the subject is linked to     |
|                  | a local password sign-in     | `user:<name>`                                                             |
| what they may do | the Host                     | the grants the principal holds, and those of every role it is a member of |

A token's groups or roles grant nothing: the provider authenticates, the Host authorizes.
The same grants and roles answer on every surface, over REST and over gRPC, and a route without a grant is refused: `401` for nobody, `403` for a principal without the grant.

## Identity providers

Each provider is one entry of `host.principals`, and several may be configured at once.

```yaml
host:
  principals:
    - oidc:
        name: entra                     # what operators type: --user entra:<value>
        issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
        audience: "<api-application-id>"
        algorithms: [RS256]
        claim: oid
    - oidc:
        name: keycloak
        issuer: "https://sso.example.com/realms/ops"
        audience: "permguard"
        ca_file: "./internal-ca.pem"
        link: email
```

| Key           | Meaning                                                                                               |
| ------------- | ----------------------------------------------------------------------------------------------------- |
| `name`        | a short unique name; never part of a principal, so renaming a provider changes nobody's grants        |
| `issuer`      | the exact `iss` the provider signs                                                                    |
| `audience`    | the `aud` the token must carry                                                                        |
| `algorithms`  | `RS256`, `ES256`, `EdDSA`; the token's header is compared, never obeyed                               |
| `claim`       | the claim that names the subject, `sub` by default; `email` only when the token says `email_verified` |
| `clients`     | optional: the `azp` or `client_id` values accepted                                                    |
| `token_types` | the accepted `typ` header values: `JWT`, `at+jwt` and `application/at+jwt` by default                 |
| `link`        | `email`: a verified email equal to a local user's email signs in as that user                         |
| keys          | discovery by default; `jwks_uri` to pin the key set URL; `jwks_file` for a set the deployment keeps   |
| `ca_file`     | the authority of a private provider's certificate, beside the system's                                |
| `refresh`     | how often the keys are fetched again, `1h` by default                                                 |
| `max_stale`   | how long the last keys serve when the provider cannot be reached, `24h` by default                    |

The Host fetches each provider's keys itself, one task per provider, never while answering a request.
A token signed by a key the Host does not hold yet is refused, and asks for an early fetch, at most once a minute; the next token verifies.
The last good key set is kept on the volume, so a restart without network keeps serving it until `max_stale`.
Keys are fetched over HTTPS only, outside the `development` profile, and no redirect is followed.

### Microsoft Entra ID

Register an application for the API Permguard is, and set its manifest's `requestedAccessTokenVersion` to `2`, so its tokens carry the v2.0 issuer.

```yaml
- oidc:
    name: entra
    issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
    audience: "<api-application-id>"
    algorithms: [RS256]
    claim: oid                          # stable across applications; sub is per application
    clients: ["<cli-application-id>"]   # optional: only this client's tokens
```

Entra's access tokens carry no `email_verified`, so link users explicitly: `permguard host users link alice --user entra:<object-id>`.
Each tenant is a provider of its own: multi-tenant issuer templates are not supported.

### Okta

Use a custom authorization server: tokens of the org authorization server are not meant to be verified by an API.

```yaml
- oidc:
    name: okta
    issuer: "https://<org>.okta.com/oauth2/<authorization-server-id>"
    audience: "api://permguard"
    algorithms: [RS256]
```

When Okta's tokens name a `typ` the defaults do not hold, the refusal says which; add it to `token_types`.

### Keycloak

Add an audience mapper to the client, so its access tokens carry `permguard` in `aud`.

```yaml
- oidc:
    name: keycloak
    issuer: "https://sso.example.com/realms/<realm>"
    audience: "permguard"
    algorithms: [RS256]
    ca_file: "./internal-ca.pem"        # when the realm's certificate is from a private authority
    link: email                         # Keycloak says email_verified
```

### Auth0

Create an API whose identifier is the audience; the issuer ends with a slash.

```yaml
- oidc:
    name: auth0
    issuer: "https://<tenant>.auth0.com/"
    audience: "https://permguard.example.com"
    algorithms: [RS256]
```

Auth0's access tokens carry no verified email by default: link users explicitly.

## Local users

A deployment without a provider, or beside one, can sign people in with the Host's own users.

```yaml
host:
  authentication:
    methods: [password, oidc]           # password, oidc, or both
    password:
      min_length: 12
      mfa: optional                     # off, optional or required
      factor_key: { ref: mfa-seal, version: "v1" }
      lockout: { attempts: 5, window: 15m, duration: 15m }
    sessions:
      lifetime: 8h
      idle: 1h
```

| Rule          | What it does                                                                                                     |
| ------------- | ---------------------------------------------------------------------------------------------------------------- |
| methods       | a method not listed is refused, whatever else is configured                                                      |
| passwords     | kept as Argon2id hashes; never logged, never returned                                                            |
| sign-in       | `POST /auth/v1/sessions` on the Server Host surface, over TLS outside `development`                              |
| one refusal   | an unknown user, a wrong password, a disabled or locked user and a wrong code all get the same answer            |
| lockout       | failures lock the user, and a source address at four times the threshold                                         |
| sessions      | 256 random bits, kept by the Host only as a hash, ended by sign-out, password change, disabling or a restart     |
| second factor | TOTP, sealed under the Host-local root `factor_key` names; `required` is mandatory under the `regulated` profile |

```sh
printf '%s' "$PASSWORD" | permguard host users create paperino --email paperino@hotmail.com --password-stdin
permguard login https://pg.example.com:5443 --user paperino      # the password is read with echo off
permguard factor https://pg.example.com:5443 begin                # then: confirm --code 123456
```

A provider subject acts as a local user when it is linked to it, or, under `link: email`, when its verified email is the user's.
`paperino@hotmail.com` signing in through a provider then acts as `user:paperino`, with the user's grants and roles.
A disabled user signs in by no method, its linked subjects included.

### The first administrator

When only a provider signs people in, nobody can grant the first grant online.
Create the first administrator offline, on the Host's volume, before it starts:

```sh
permguard host users bootstrap --volume /var/lib/permguard --name alice --email alice@acme.com
```

With `--password-stdin` the user can sign in with a password; with only an email, its first sign-in through a provider with `link: email` acts as it.

## Roles

A role is a set of grants the Host holds for `role:<name>`; its members act with them.

```sh
permguard host roles create operators --description "run the Host"
permguard host roles members add operators --user entra:0042-abcd
permguard host roles members add readers --issuer okta          # every subject of a provider
permguard host roles grant operators --operations authz.admin --selector host
```

Several Hosts are kept alike with one file:

```yaml
roles:
  operators:
    description: run the Host
    members:
      - local: paperino
      - user: entra:alice@acme.com
    grants:
      - operations: [authz.admin]
        selector: host
```

```sh
permguard host roles apply plan -f roles.yml --out roles.plan   # every change, removals included
permguard host roles apply run --confirm-file roles.plan        # refused if the Host moved since
```

The plan widens before it narrows, a role the file does not name is left alone, and applying the same file again changes nothing.
A role or a user that holds grants is not deleted until they are revoked; `--revoke-grants` revokes them first.
A call a role's grant allowed is recorded in the `access` audit trail, naming the role.

## Bearer tokens travel over TLS

A bearer token on a listener without TLS is refused before it is read, unless the listener is on a loopback address or an ingress terminates TLS in front of it and the plane says so with `public.tls.terminated_upstream: true`.
A refused token is answered `401` with `WWW-Authenticate: Bearer realm="permguard", error="invalid_token"`.

## Observing the providers

| Signal                                          | Meaning                                                                      |
| ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `permguard host providers list`                 | each provider's key source, keys, last fetch, last failure and state         |
| `permguard host providers refresh <name>`       | fetch now                                                                    |
| Host status `degraded: oidc`                    | a provider's keys are older than twice `refresh`, or missing after a failure |
| `permguard_oidc_keys_oldest_age_seconds`        | the oldest key set held                                                      |
| `permguard_oidc_providers_not_fresh`            | how many providers are behind                                                |
| `permguard_oidc_refresh_failures_total`         | failed fetches                                                               |
| `PermguardIdentityProviderKeysNotFresh` alert   | a provider has been behind for five minutes                                  |
| `PermguardIdentityProviderRefreshFailing` alert | more than three failed fetches in thirty minutes                             |

Past `max_stale` a provider's tokens are refused as unavailable: its keys are too old to trust, and the Host never falls back to a fetch on the request path.
