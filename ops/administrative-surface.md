<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The administrative surface

**Permguard does not separate administration from reading today. Isolating it is the network's job,
and this page says exactly what that means so nobody has to infer it from a configuration file.**

## What is on the public endpoint

A control plane answers all of this on `controlPlane.public`:

| | |
| --- | --- |
| read | `GET /catalog/v1/zones`, `GET …/ledgers`, the decision log, `/health`, `/version` |
| **mutate** | `POST`/`PATCH`/`DELETE` on zones and ledgers |
| **push policy** | the NOTP routes — negotiate, upload objects, commit a ref |
| **read audit** | the decision-log routes |
| **read events** | the event-log read routes, when the store is on; events arrive over the Host's `events.ship` |

The second listener is the Host listener (WP-2.5): `admin.addr`, over `admin.tls` with `admin.allow` as its peer gate, serves the Host API — `/host/v1` and `permguard.host.v1` — where the key rings, the memberships, the lifecycle and the effective configuration are administered and read.
It is not an administrative surface for the planes: creating a zone, deleting a ledger, pushing a policy version and reading the decision log stay on the public endpoint.
Every route on either listener decides by the caller's access token, issued by the Authority Plane and allowed what its scopes name; service accounts, their scopes and their access keys are administered online with `permguard authority`.
Nothing is administered offline but the ways back in: `permguard host grants bootstrap` commits the Host's one recovery principal by its certificate's fingerprint, and `permguard authority admin-key` issues a new access key for `admin`, both with the server stopped.

## What this means for a deployment

A caller that reaches the public endpoint with a token whose scopes allow it can create a zone, delete a ledger, push a policy version, read the decision log and — where the event store is on — read a tenant's event history; where the anonymous policy opens a route, as the development configurations do, so can anybody.
So the endpoint is a boundary of its own, and it has to be treated as one:

- **Reach it from nowhere it need not be reached from.** The chart's `networkPolicy.public.from`
  is that control; narrow it to the namespaces that hold your PEPs and your delivery pipeline.
- **Terminate mutual TLS in front of it**, with an allow list of the identities that may push —
  a gateway or a mesh policy, since the plane itself will not check one on this surface.
- **Do not expose it outside the cluster.** A PDP decision endpoint is on the data plane; the
  control plane is not something an application talks to.

## Why it is written down rather than implemented

Moving the mutations to a listener of their own is not a setting; it changes where every client
sends them. `permguard zones create`, `ledgers create` and `apply` all reach
`control-plane.endpoint` today, so a separate surface means a separate endpoint in the CLI, in the
configuration file, in the chart and in every example — a change to the product's public shape, and
one worth making deliberately rather than as a side effect.

Until it is made, **there is one endpoint, and what protects it is the caller's token and the network in front of it.**
