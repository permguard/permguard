<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security posture

What this codebase defends against, what it deliberately delegates, and the constraints future work
has to respect. The threat analysis behind this page lives in the review history; this is the part
that has to stay true.

## What a surface defends itself against

Every listener — HTTP, gRPC and telemetry alike — serves inside the bounds in
[Running the planes](running.md#what-a-surface-refuses-to-spend): connection pool and per-address
share, handshake, header and request deadlines, header and body byte caps, request concurrency with
load shedding, a write-stall bound, and an optional connection lifetime. Each is tested as the attack
it stops, not as a getter.

Mutual TLS is **authentication and authorisation, separately**. `client_ca` decides which
certificates are genuine; the `allow` list beside it decides which of those peers the endpoint is
for — because an authority signs every client it was ever asked to. An authenticated peer off the
list gets `403` and a log record naming it; an empty list means the handshake is the whole decision,
which is right for a data plane answering any workload the mesh signed and refused by validation for
anything administrative.

Revocation-list expiry is **enforced**: a CRL past its `nextUpdate` refuses every mutual-TLS
handshake, deliberately — an expired list is revocation data nobody is maintaining, and the
alternative is a revoked client that stays admitted for months.
`permguard_tls_crl_expiry_timestamp_seconds` and its alert exist so that moment is predicted, not
discovered.

## What an error is allowed to say

Every API answers a refusal with the same shape — a class from a closed set, a stable code, one safe
sentence — and how much an internal failure discloses follows `public.error_detail`: `full` on a
workstation, `minimal` (the default) anywhere real. Paths, io errors and other operator material go
to the server's own log at full fidelity **whatever the wire says**, so hardening the wire costs the
operator nothing. Every future API must produce this shape; the transports and the disclosure logic
are written once and shared.

The audit trail records **successful mutations** by default — a caller's mistakes change nothing,
and letting anybody inflate the evidentiary record with bad requests would make the trail noise. A
deployment that wants denied attempts on the record — a compliance regime that asks for them, an
exposed surface under watch — sets `operations.audit.refusals: "true"` and gets
`<operation>.refused` records with the stable error code; internal faults never reach the trail,
because a record saying "we broke" attests to nothing about anybody's conduct and lives in the
operational log instead.

## Constraints on future work

These are design decisions, not omissions. Changing one is a review, not a refactor.

- **Rate limiting belongs in front of the planes.** None of the limits is a rate limiter, because
  rate limiting needs to know who a client *is* over time — an identity question, owned by the
  ingress or by a build with a notion of tenant. **The constraint this creates:** no endpoint that
  verifies a credential — the token-exchange endpoints `realm.rs` already describes configuration
  for — ships without a per-principal throttle in front of it, at the ingress or in process. An
  unthrottled credential check is a brute-force oracle.
- **`FileAuditSink` is for control-plane cadence, not raw request-rate traffic.** It flushes each
  record to disk because ordering the trail is the point. The data plane queues authorization audit
  records behind a bounded worker; a realm or extension that audits per request directly still needs
  a sink that batches rather than turning a slow disk into request latency.
- **The environment is a development-grade secret store.** `secrets.provider: environment` outside
  `development_mode` is allowed — the deployment decides — and warned about at startup: a process's
  environment is readable through `/proc` and inherited by every child.

## Delegated, and to what

- **Network segregation of the telemetry surface** is the cluster's job: the chart gives telemetry a
  Service of its own precisely so a NetworkPolicy can allow scraping and refuse everything else.
  The chart ships one, default-on: every port a pod does not serve is closed, and
  `networkPolicy.public.from` / `networkPolicy.telemetry.from` say who may reach the two surfaces.
  The policy itself is on the roadmap below; until it ships, write one alongside the release.
- **Real client addresses behind a load balancer.** The per-address connection share counts the
  address on the socket. Behind a balancer that is the balancer, so either exempt its block with
  `limits.peer_exempt` or set `limits.connections_per_peer: "0"` and count at the ingress.

## The decision endpoint, and what guards it today

A PDP is worth attacking, so what defends it is worth stating plainly.

| Property | How it holds |
| --- | --- |
| Nothing is served that was not proven | a mirror advances only after the signed head statement verifies against the published ring and the whole closure is present; every object is digest-checked when it is read |
| An engine outside the manifest's range never evaluates | the load gate refuses, and the refusal is remembered per commit. An engine interpreting the same policies differently is a silent authorization bypass, so it is not permitted to try |
| A schema is a contract | with `schema: true`, every policy type-checks against it at load, and a request outside it is refused rather than silently reinterpreted |
| Fail-closed | any evaluation error is a deny carrying its reason; a deny is a `200`, and a ledger that cannot be served is `503` — never a quiet `false` |
| A hostile payload cannot stall a worker | `authz.max_evaluations` bounds a batch; the request-body, header and concurrency bounds of every surface apply here too; and every Rego rule evaluation runs under a hard execution budget, so an expensive rule or input answers as an evaluation fault (a deny that says why) instead of occupying the worker. Cedar needs no such budget: the language has no recursion or loops, so its evaluation terminates by construction |
| Memory is bounded | `authz.cache.partitions` and `authz.cache.bytes`; the cache degrades (recompiles) rather than growing |
| A caller cannot mint metric series | metrics label the zone and ledger a plane actually mirrors; a request naming something else is counted under one refusal series |

**What does not guard it yet, and must be stated:** the endpoint has no
authentication or authorization of its own. Today it is reached over TLS, with
mutual TLS and a peer allow list (`tls.allow`) where a deployment configures
them — which is a real control, and the one this release ships. Tokens are a
later chapter, designed once for the CLI and both planes; until then, **a
deployment that exposes `7656` beyond its own network is relying on the network
for authentication**, and should use mutual TLS or an authenticating ingress.
The same is true of the control plane's APIs.

## Roadmap

Accepted gaps, in the order they should close:

1. **The audit seal must leave the machine.** Today the chain and its signed seals live on the
   volume they attest to, which makes tampering evident to whoever holds the trail and to nobody
   else. The design anticipates the fix — one digest attests to everything before it — and the
   shipping mechanism (a remote sink, an append-only store, even the structured log stream) is not
   built yet.
2. **Authentication and authorization of the APIs themselves** — the decision endpoint, the catalog
   and NOTP — designed once for the CLI and both planes rather than per surface. Mutual TLS and peer
   allow lists are what stand in the meantime, and they are not a substitute for a caller identity
   on the record.
3. **Signed decision responses** (`permguard.trust-anchor.v1`): the data plane's ring at `keys/data`
   exists for it, so a PEP can verify a decision was not altered by anything between it and the PDP.

## Reporting

Vulnerabilities go through [SECURITY.md](../SECURITY.md), never a public issue.
