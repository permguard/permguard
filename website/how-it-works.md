---
layout: page
pageClass: pg-page-concepts
title: How Permguard works
description: From authored policy to a verifiable authorization decision.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">How it works</div>
    <h1>From policy to proof.</h1>
    <p>Author once. Distribute an immutable version. Decide close to the workload. Keep evidence that can be verified later.</p>
    <div class="pgx-flow" role="img" aria-label="A policy moves from authoring to the control plane, then to the data plane, where a decision produces evidence.">
      <div class="pgx-flow__track"><i aria-hidden="true"></i></div>
      <div class="pgx-flow__step"><b>01</b><strong>Author</strong><span>policy as code</span></div>
      <div class="pgx-flow__step"><b>02</b><strong>Publish</strong><span>signed head</span></div>
      <div class="pgx-flow__step"><b>03</b><strong>Mirror</strong><span>verify first</span></div>
      <div class="pgx-flow__step"><b>04</b><strong>Decide</strong><span>fail closed</span></div>
      <div class="pgx-flow__step"><b>05</b><strong>Prove</strong><span>evidence</span></div>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Flexible architecture</div><h2>One system. Any shape.</h2></div><p>Run planes together, split them into separate processes or connect your own implementation.</p></div>
    <div class="pgx-system-map" role="img" aria-label="A Server Host provides shared identity, authorization, keys, audit, membership and streams to independently composable Control, Data and Trust planes. All planes use discovery and signed protocols.">
      <div class="pgx-system-map__frame">
        <div class="pgx-system-map__label"><strong>Permguard Server</strong><span>one Host · zero or more planes</span></div>
        <div class="pgx-system-map__host"><small>SERVER HOST</small><strong>Identity · Authorization · Keys · Audit · Membership · Streams</strong></div>
        <div class="pgx-system-map__bus" aria-hidden="true"></div>
        <div class="pgx-system-map__planes">
          <article><small>CONTROL PLANE</small><strong>Publish</strong><span>policy ledgers</span></article>
          <article><small>DATA PLANE</small><strong>Decide</strong><span>close to workloads</span></article>
          <article class="pgx-system-map__optional"><small>TRUST PLANE · IN DEVELOPMENT</small><strong>Continue authority</strong><span>trust anchors · execution chains</span></article>
        </div>
      </div>
      <div class="pgx-system-map__protocols">
        <article><small>OBJECT STORAGE</small><strong>Git-like history</strong><span>immutable commits · signed heads</span></article>
        <article><small>STREAMS</small><strong>Ordered evidence</strong><span>events · decisions · audit</span></article>
        <article><small>DISCOVERY</small><strong>Well-known</strong><span>server → plane → interface</span></article>
      </div>
    </div>
    <div class="pgx-discovery pgx-discovery--compact" aria-label="A client starts with one Server Host URL, follows a plane configuration, then discovers an exact interface.">
      <article><small>ONE URL</small><strong>Server configuration</strong><span>Which planes are here?</span></article><i>→</i>
      <article><small>PLANE</small><strong>Plane configuration</strong><span>Keys, protocols, interfaces</span></article><i>→</i>
      <article><small>INTERFACE</small><strong>Exact contract</strong><span>Routes and capabilities</span></article>
    </div>
    <p class="pgx-system-map__truth">Discovery is the truth: a Server advertises only the planes and interfaces it actually hosts. Control and Data Plane are available today. Trust Plane has a reserved place and port, but remains in development and is not advertised by the runtime.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The decision boundary</div><h2>Ask. Decide. Enforce.</h2></div><p>Two roles are enough to understand the runtime.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="A Policy Enforcement Point asks an authorization question, the Policy Decision Point evaluates the published policy, and the Policy Enforcement Point enforces the answer.">
      <article><small>PEP · ASK</small><strong>Can this action happen?</strong><span>application · gateway · agent</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>PDP · DECIDE</small><strong>Evaluate policy</strong><span>Permguard Data Plane</span></article><i>→</i>
      <article><small>PEP · ENFORCE</small><strong>Apply the answer</strong><span>permit · deny · error</span></article>
    </div>
    <p><strong>PEP</strong> means Policy Enforcement Point: the component guarding an action. It asks the question and enforces the answer. <strong>PDP</strong> means Policy Decision Point: it evaluates the selected, verified policy version. The Control Plane publishes policy; the Data Plane is the PDP; your application, gateway or agent is usually the PEP.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Start</div><h2>See it working.</h2></div><p>A local decision first. A real server next.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <a class="pgx-card pgx-card--accent" :href="withBase('/how-it-works/install')"><span>01</span><h3>Install</h3><p>Put the Permguard CLI on your machine.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/getting-started')"><span>02</span><h3>Getting Started</h3><p>Create, test, publish and ask a policy.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/architecture')"><span>03</span><h3>Architecture</h3><p>One Host. Independent planes. Known ports.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Mental model</div><h2>Three rules are enough.</h2></div></div>
    <div class="pgx-principles">
      <article><span>Immutable</span><h3>A version never changes.</h3><p>Policies become content-addressed objects. A signed head selects the accepted commit.</p></article>
      <article><span>Local</span><h3>Decisions stay near the workload.</h3><p>Run Permguard as a sidecar or remote PDP; build custom only for embedded or specialised edge placement.</p></article>
      <article><span>Traceable</span><h3>An answer leaves evidence.</h3><p>The signer, decision and exact policy version remain independently verifiable.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Concepts</div><h2>Go one layer deeper.</h2></div></div>
    <div class="pgx-link-grid">
      <a :href="withBase('/how-it-works/architecture')"><strong>Server, Host &amp; Planes</strong><span>compose the architecture</span></a>
      <a :href="withBase('/how-it-works/policy-storage')"><strong>Git-like Policy Storage</strong><span>files → objects → immutable history</span></a>
      <a :href="withBase('/how-it-works/bring-your-own-data-plane')"><strong>Bring Your Own Data Plane</strong><span>Permguard policy → your runtime</span></a>
      <a :href="withBase('/how-it-works/policy-lifecycle')"><strong>Policy Lifecycle</strong><span>source → signed version → mirror</span></a>
      <a :href="withBase('/how-it-works/decision-lifecycle')"><strong>Decision Lifecycle</strong><span>request → evaluation → answer</span></a>
      <a :href="withBase('/how-it-works/evidence')"><strong>Evidence &amp; Verification</strong><span>record → chain → proof</span></a>
      <a :href="withBase('/how-it-works/temporal-authorization')"><strong>Temporal Authorization</strong><span>history becomes policy input</span></a>
      <a :href="withBase('/how-it-works/policy-languages')"><strong>Policy Languages</strong><span>Cedar · Rego · Dogwood</span></a>
      <a :href="withBase('/how-it-works/container-images')"><strong>Container Images</strong><span>GHCR · Docker Hub · verified releases</span></a>
      <a :href="withBase('/trust-plane')"><strong>Trust Plane</strong><span>authority continuity · in development</span></a>
    </div>
    <nav class="pgx-pager pgx-pager--next-only" aria-label="Documentation pages">
      <a class="pgx-pager__next" :href="withBase('/how-it-works/install')"><span>Next</span><strong>Install <b aria-hidden="true">→</b></strong></a>
    </nav>
  </section>
</main>
