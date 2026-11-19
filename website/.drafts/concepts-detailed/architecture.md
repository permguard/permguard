---
pageClass: pg-page-concepts
title: Server, Host and Planes
description: One Host owns the trust boundary; planes own business domains.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Architecture</div>
  <h1>One Host. Zero or more planes.</h1>
  <p>The Host owns trust and operations. A plane owns one business domain.</p>
</div>

<div class="pgx-system-map" role="img" aria-label="One Permguard Server contains one Host and the planes it composes: the Authority Plane on port 8443, the Control Plane on 6443 and the Data Plane on 7443. The Trust Plane is next on the roadmap and not served today.">
  <div class="pgx-system-map__frame">
    <div class="pgx-system-map__label"><strong>Permguard Server</strong><span>one Host · the planes you deploy</span></div>
    <div class="pgx-system-map__host"><small>HOST · :5443</small><strong>Identity · Authorization · Keys · Audit · Membership · Streams</strong></div>
    <div class="pgx-system-map__bus" aria-hidden="true"></div>
    <div class="pgx-system-map__planes">
      <article><small>AUTHORITY PLANE · :8443</small><strong>Admit</strong><span>service accounts · access tokens</span></article>
      <article><small>CONTROL PLANE · :6443</small><strong>Publish</strong><span>zones · ledgers · signed heads</span></article>
      <article><small>DATA PLANE · :7443</small><strong>Decide</strong><span>mirror · compile · decide · record</span></article>
    </div>
    <div class="pgx-system-map__next"><small>TRUST PLANE · NEXT</small><span>authority continuity with PIC-X · not served today</span></div>
  </div>
</div>

## The ownership rule

<div class="pgx-ownership">
  <article><strong>Host</strong><p>Identity, authentication, authorization, keys, secrets, audit, membership, streams, persistence and lifecycle.</p></article>
  <i aria-hidden="true">→</i>
  <article><strong>Plane</strong><p>Domain logic behind typed, least-privilege capabilities received from the Host.</p></article>
</div>

A plane never creates a second key manager, audit trail or persistence path.

## One URL discovers the rest

Start at the Server Host. Its well-known document is a descriptive directory: it says which planes this Server contains and where each plane describes itself.

```sh
curl -s http://127.0.0.1:5443/.well-known/server-configuration | jq
```

```json
{
  "planes": {
    "control-plane": {
      "server_configuration": "http://127.0.0.1:6443/.well-known/server-configuration"
    },
    "data-plane": {
      "server_configuration": "http://127.0.0.1:7443/.well-known/server-configuration"
    }
  }
}
```

<div class="pgx-config-map" role="img" aria-label="The Host server configuration advertises each deployed plane configuration. Control describes policy publication and NOTP. Data describes evaluation interfaces. Authority describes service accounts and tokens. Trust is next on the roadmap and is not advertised today.">
  <article class="pgx-config-map__host">
    <small>HOST CONFIGURATION · :5443</small>
    <strong>Which planes are present?</strong>
    <code>/.well-known/server-configuration</code>
    <span>Host functions: identity · authorization · keys · audit · membership · streams</span>
  </article>
  <div class="pgx-config-map__arrow"><span>advertises each plane configuration</span><b>↓</b></div>
  <div class="pgx-config-map__planes">
    <article>
      <small>CONTROL PLANE CONFIGURATION · :6443</small>
      <strong>How is policy published?</strong>
      <code>/.well-known/server-configuration</code>
      <span>Plane functions: zones · ledgers · signed heads · NOTP</span>
    </article>
    <article>
      <small>DATA PLANE CONFIGURATION · :7443</small>
      <strong>Which evaluation interfaces exist?</strong>
      <code>/.well-known/server-configuration</code>
      <span>Plane functions: mirror · compile · activate · decide</span>
      <div class="pgx-config-map__interface"><b>INTERFACE CONFIGURATION</b><code>/.well-known/permguard-pdp-v1-configuration</code><em>exact routes · capabilities · request scope</em></div>
    </article>
    <article>
      <small>AUTHORITY PLANE CONFIGURATION · :8443</small>
      <strong>Who may call?</strong>
      <code>/.well-known/server-configuration</code>
      <span>Plane functions: service accounts · access keys · tokens · status lists</span>
    </article>
    <article class="pgx-config-map__planned">
      <small>TRUST PLANE · NEXT</small>
      <strong>How may authority continue?</strong>
      <code>/.well-known/server-configuration</code>
      <span>Reserved domain: Trust Anchors · authority hand-off · execution continuity</span>
      <div class="pgx-config-map__interface"><b>NOT ADVERTISED TODAY</b><em>The configuration and interface contracts will be published only when implemented.</em></div>
    </article>
  </div>
</div>

These documents describe deployed capabilities. They do not create a plane, move policy or make a decision. The Host configuration describes composition and shared Host functions; each plane configuration describes only that plane's domain; an interface configuration describes one exact versioned API. The Trust Plane is shown because its architectural role and standard port are reserved, but it does not appear in the real Host document until it exists.

### Control Plane

The Control Plane describes publication and the complete NOTP transfer surface:

```sh
curl -s http://127.0.0.1:6443/.well-known/server-configuration | jq
```

```json
{
  "plane": "control-plane",
  "transports": {
    "http": true,
    "grpc": true
  },
  "jwks_uri": "http://127.0.0.1:6443/control-plane/v1/keys",
  "notp": {
    "media_type": "application/vnd.permguard.notp.v1+cbor",
    "compression": "deflate",
    "ref_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/refs/{ref}",
    "push_negotiation_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/push/negotiate",
    "push_commit_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/push/commit",
    "pull_negotiation_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/pull/negotiate",
    "object_upload_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/objects",
    "object_fetch_endpoint": "http://127.0.0.1:6443/notp/v1/zones/{zone}/ledgers/{ledger}/objects/fetch"
  },
  "zones_endpoint": "http://127.0.0.1:6443/v1/zones",
  "ledgers_endpoint": "http://127.0.0.1:6443/v1/zones/{zone}/ledgers"
}
```

`notp` is discovered, not agreed out of band: format, compression, negotiation, object transfer and commit routes travel together.

### Data Plane

The Data Plane names every evaluation interface it serves:

```sh
curl -s http://127.0.0.1:7443/.well-known/server-configuration | jq
```

```json
{
  "plane": "data-plane",
  "jwks_uri": "http://127.0.0.1:7443/data-plane/v1/keys",
  "interfaces": {
    "permguard.api.pdp.native.v1": {
      "configuration": "http://127.0.0.1:7443/.well-known/permguard-pdp-v1-configuration"
    }
  }
}
```

Follow the interface link to discover the routes and capabilities:

```sh
curl -s http://127.0.0.1:7443/.well-known/permguard-pdp-v1-configuration | jq
```

```json
{
  "interface": "permguard.api.pdp.native.v1",
  "pdp": "http://127.0.0.1:7443",
  "endpoints": {
    "evaluation": "http://127.0.0.1:7443/access/v1/evaluation",
    "evaluations": "http://127.0.0.1:7443/access/v1/evaluations"
  },
  "capabilities": [
    "urn:permguard:pdp:v1:store-in-payload",
    "urn:permguard:pdp:v1:profile-selection",
    "urn:permguard:pdp:v1:partition-inputs",
    "urn:permguard:pdp:v1:principal",
    "urn:permguard:pdp:v1:structured-reasons",
    "urn:permguard:pdp:v1:boxcarring"
  ],
  "store_scope": {
    "in": "payload",
    "zone": "required",
    "ledger": "required",
    "profile": "optional"
  }
}
```

The plane document lists interfaces. The interface document then lists the exact routes, capabilities and request scope.

#### PDP interface profiles

A PDP is not one universal authorization API. It may expose one or more evaluation-interface profiles, each naming an exact, versioned question and contract. This is separate from the policy profile selected inside a request.

<div class="pgx-cards pgx-cards--3">
  <article class="pgx-card pgx-card--accent"><span>Current general profile</span><h3><code>permguard.api.pdp.native.v1</code></h3><p>General subject–action–resource authorization with Permguard semantics.</p></article>
  <article class="pgx-card"><span>Familiar, not compatible</span><h3>AuthZEN-like shape</h3><p>The question looks familiar, but this is not an AuthZEN implementation or compatibility claim.</p></article>
  <article class="pgx-card"><span>Extensible</span><h3>Separate questions</h3><p>Experimental temporal and future interfaces keep their own ids, schemas, capabilities and evidence.</p></article>
</div>

Clients select only an interface the Data Plane advertises. One interface is never silently converted into another.

### Authority Plane

The Authority Plane keeps the service accounts, their scopes and access keys, and issues the short-lived access tokens every plane and Host verifies itself.
It serves port `8443`.
See [Authority Plane](../authority-plane).

### Trust Plane

The Trust Plane is a separate domain for authority continuity: whether authority may cross into the next execution, under which Trust Anchor, and without expanding.
It is next on the roadmap, with [PIC-X](https://pic-protocol.org/pic-x).

The runtime does not serve or advertise this plane today. Its plane configuration, Trust Anchor evaluation interface and authority hand-off contract remain [in development](../trust-plane).

## Standard ports

| Role            | Port   | Purpose                                         |
| --------------- | -----: | ----------------------------------------------- |
| Server Host     | `5443` | discovery, health, readiness, version, metrics  |
| Control Plane   | `6443` | zones, ledgers, policy distribution             |
| Data Plane      | `7443` | policy evaluation                               |
| Authority Plane | `8443` | service accounts, access keys, tokens           |
| Trust Plane     |      — | authority continuity; next on the roadmap       |

The role owns the port. HTTP and gRPC share it; TLS changes the scheme, not the number.

## Deployment topologies

Permguard Server is always the composition boundary. Deployment changes only how enabled planes are grouped behind Hosts.

<div class="pgx-deploy">
  <article><div class="pgx-kicker">All-in-one</div><h3>All enabled planes, one process</h3><p>One Permguard Server process composes one Host with every enabled plane. Today that means `5443`, `6443`, `7443` and `8443`.</p></article>
  <article><div class="pgx-kicker">Split by plane</div><h3>One plane per Host</h3><p>Each Permguard Server process composes its own Host with one plane. Control serves `5443` + `6443`; Data serves `5443` + `7443`; Authority serves `5443` + `8443`. Each Host owns its volume.</p></article>
</div>

The Server model is unchanged in both deployments: Host functions remain on the Host and domain functions remain in the plane. Split Servers use different IP addresses or network namespaces; standard role ports are not reassigned.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./getting-started"><span>Previous</span><strong><b aria-hidden="true">←</b> Getting Started</strong></a>
  <a class="pgx-pager__next" href="./policy-languages"><span>Next</span><strong>Policy as Code <b aria-hidden="true">→</b></strong></a>
</nav>
