<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The administrative surface

**Permguard does not separate administration from reading today. Isolating it is the network's job,
and this page says exactly what that means so nobody has to infer it from a configuration file.**

## What is on the public endpoint

A control plane answers all of this on `controlPlane.public`:

| | |
| --- | --- |
| read | `GET /v1/zones`, `GET …/ledgers`, the decision log, `/health`, `/version` |
| **mutate** | `POST`/`PATCH`/`DELETE` on zones and ledgers |
| **push policy** | the NOTP routes — negotiate, upload objects, commit a ref |
| **read audit** | the decision-log routes |

There is no second listener. `admin.addr`, `admin.tls` and `admin.allow` exist in the configuration
contract and are validated — mutual TLS demanded, an allow list required outside development — and
**nothing binds them**. A process configured with `admin.addr` refuses to start rather than let an
operator believe a boundary is there.

## What this means for a deployment

Anything that reaches the public endpoint can create a zone, delete a ledger, push a policy version
and read the decision log. So the endpoint is the boundary, and it has to be treated as one:

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

Until it is made, this page is the whole truth about the boundary: **there is one endpoint, and
what protects it is the network in front of it.**
