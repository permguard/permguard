---
pageClass: pg-page-concepts
title: Access Tokens & Clusters
description: One Control Plane issues the access tokens every Data Plane of the cluster decides by, offline, revocable within a bound you choose.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Access tokens</div>
  <h1>One IAM Host. Every Data Plane decides by its tokens.</h1>
  <p>The Control Plane's Host keeps the users, roles, grants and service accounts and issues short-lived access tokens; each Data Plane checks them offline, against keys and revocation lists it holds.</p>
</div>

## The cluster

| Host             | Runs                           | Holds                                                                                  | Decides by                                              |
| ---------------- | ------------------------------ | -------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| the **IAM Host** | a Control Plane                | users, roles, grants, providers, service accounts, the `iam.tokens` keys, status lists | its grants; a token caller is also bounded by the token |
| a **member**     | a Data Plane, no Control Plane | its memberships with the IAM Host, the keys and lists they pin                         | the IAM Host's access tokens, and nothing else          |

A member keeps no users, roles or grants and offers no sign-in: everything it accepts comes from the IAM Host it joined.
Its own bootstrap certificate administers it only when its IAM Host is lost, and never decides a request; every use of it once joined is audited and reported as `degraded: bootstrap`.

## Service accounts

A program acts as a service account, `sa:<name>`, which holds grants as a user does.

```sh
permguard iam service-accounts create billing --owner payments-team
permguard iam grants issue --principal sa:billing \
  --operations decision.evaluate,event.submit --selector "plane/data/zone/<zone-id>/*"
permguard iam credentials create billing --secret-out ./billing.secret      # written once, 0600
permguard iam credentials create billing --public-key ./billing.pub.pem     # a signed assertion instead
permguard iam credentials create billing --certificate ./billing.crt        # or its TLS certificate
```

A grant names only selectors its operations apply to: the IAM Host refuses one that could never allow anything.
A secret is shown once, in the file it is written to; the IAM Host keeps only its hash.
Suspending an account, or revoking one of its credentials, refuses every token it obtained.

## Obtaining a token

| Who                           | How                                                                                       | Token         |
| ----------------------------- | ----------------------------------------------------------------------------------------- | ------------- |
| a program, by its secret      | `client_credentials` with Basic authentication                                            | `application` |
| a program, by its key         | `client_credentials` with an RFC 7523 assertion addressed to the published token endpoint | `application` |
| a program, by its certificate | `client_credentials` over mutual TLS (RFC 8705)                                           | `application` |
| a person                      | their session from `permguard login`, exchanged (RFC 8693)                                | either family |

```sh
# A service account: the command line obtains, caches and renews its own token, addressed to
# the member it decides on.
PERMGUARD_CLIENT_AUDIENCE=member:<member-id> \
permguard --data-endpoint https://data-plane.example:7443 \
  --iam-endpoint https://iam.example:5444 --client-id billing \
  --client-secret-file ./billing.secret \
  check -f request.json --zone <zone-id> --ledger <ledger-id>

# A person: an administration token for one member, from the session `login` wrote.
permguard --host-endpoint https://iam.example:5444 --token-file ./alice.session \
  iam token --scope membership.read,identity.read \
  --audience member:<member-id> --target host --out ./admin.token
```

Programs embedding the client library use `permguard_control_client::token_source::TokenSource`, which obtains the token, keeps it in memory and renews it a minute before it expires.

| Family           | Allows                                                                                    | Addressed to                    | Lifetime                                  |
| ---------------- | ----------------------------------------------------------------------------------------- | ------------------------------- | ----------------------------------------- |
| `application`    | `decision.evaluate`, `event.submit` on the members' Planes                                | `member:<id>` or `group:<name>` | 1 hour by default, at most 24 hours       |
| `administration` | a member's per-Host operations: identity, keys, membership, configuration, backups, audit | exactly one `member:<id>`       | 10 minutes by default, at most 15 minutes |

A token carries one family: one obtained for an application never administers a Host.
Under `regulated`, an administration token is bound to the certificate of the connection that asked for it and is refused over any other.

## On a member

A member verifies each token in memory, with no call to the IAM Host: its size and shape, its type and key, the signature, the issuer and tenant, its times, its audience, its entry in the status list it holds, and its certificate binding.
Token verification adds a few tens of microseconds to a decision: `task bench:tokens` measures it and fails past a hundredth of the decision objective.

## Revocation

```sh
permguard iam tokens list --subject sa:billing        # by jti; a token is never shown
permguard iam tokens revoke <jti>
```

The IAM Host refuses a revoked token at once.
A member refuses it once it holds the status list that says so: the IAM Host signs a new list at every change and the members fetch it over their membership.
While a member cannot reach its IAM Host it keeps deciding with the list it holds, until that list expires; then it refuses every token of that list.

| Profile       | Lists renewed at least every | A list expires after | `application` at most |
| ------------- | ---------------------------- | -------------------- | --------------------- |
| `development` | 15 minutes                   | 24 hours             | 24 hours              |
| `production`  | 5 minutes                    | 1 hour               | 24 hours              |
| `regulated`   | 1 minute                     | 10 minutes           | 1 hour                |

A member past half its list's lifetime without a fresher one reports `degraded: token-status`; past its expiry, `not ready: token-status`.

## Deploying Data Planes

A Data Plane joins its IAM Host over membership: an invitation, a join, and the coordinator's approval.
In Kubernetes and Compose the join is automated from an invitation file; the approval stays the operator's.

A Data Plane holds two memberships, since a membership's tasks stay inside its selector: `control`, on the Control Plane's tree, to mirror its ledgers, and `data`, on its own, to ship the decisions and events it records.
The group's `-membership` ConfigMap states both.

```sh
# On the IAM Host: per replica, one invitation per membership the group's ConfigMap states.
# `--coordinator-address`: where the replicas reach it, when you came through a port-forward.
for kind in control data; do
  kubectl get configmap pg-permguard-data-plane-billing-membership \
    -o jsonpath="{.data.${kind}\.tasks\.json}" > ${kind}-tasks.json
  permguard --host-endpoint https://iam.example:5444 host members invite create \
    --selector "$(kubectl get configmap pg-permguard-data-plane-billing-membership -o jsonpath="{.data.${kind}\.selector}")" \
    --tasks ${kind}-tasks.json --name billing-0 --group billing \
    --coordinator-address https://iam.internal:5444 > ${kind}-0
done
kubectl create secret generic billing-invitations --from-file=control-0 --from-file=data-0   # and -1 …
```

```yaml
dataPlane:
  hostListener: { enabled: true, tls: { secretName: data-plane-host } }
  groups:
    - name: billing
      selector: plane/data/zone/<zone-id>/*
      replicas: 2
      join:
        secret: billing-invitations
        pinFingerprint: sha256:<the IAM Host's fingerprint>
```

Each replica reads the invitations of its ordinal, `control-<ordinal>` and `data-<ordinal>`, checks that they name the pinned IAM Host, and joins; it mirrors what its memberships grant.
Each membership waits for its approval: list them with `permguard host members pending`, check each one's Host, and approve it with `permguard host members approve`.
The replica picks up its approvals by itself within a minute, and never reads its invitations again: the Secret can then be removed.
A join needs Kubernetes 1.28 or later, where a Pod's index names its invitations.
Outside Kubernetes, set `PERMGUARD_HOST_JOIN_INVITATION_FILE`, `PERMGUARD_HOST_JOIN_PIN_FINGERPRINT` and, when the invitation leaves them open, `PERMGUARD_HOST_JOIN_NAME` and `PERMGUARD_HOST_JOIN_GROUPS`.

## Observing

| Signal                                        | Meaning                                                                             |
| --------------------------------------------- | ----------------------------------------------------------------------------------- |
| `degraded: token-status`                      | a held list is past half its lifetime without a fresher one, or held in memory only |
| not ready, `degraded: objective.token-status` | a held list expired: tokens of that list are refused                                |
| `degraded: token-sync`                        | on the IAM Host, tokens' statuses could not follow a directory change               |
| `degraded: token-custody`                     | under `production`, the IAM Host keeps `iam.tokens` in files                        |
| `degraded: bootstrap`                         | a member's bootstrap certificate was used while it is joined                        |
| `degraded: join`                              | a configured join has made no membership yet, or was refused                        |
| `permguard_token_status_list_age_seconds`     | the oldest list a member holds, since it was issued                                 |
| `host.authz.token` in the trail               | an administration call a token allowed, with the token's `jti`                      |
| `iam.token.*` in the trail                    | every token issued, exchanged, revoked or refused at the IAM Host                   |
