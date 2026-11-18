---
layout: page
pageClass: pg-page-concepts
title: How Permguard works
description: Authorization leaves the code. Applications and AI agents ask Permguard, and every answer names the policy that decided it.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">How it works</div>
    <h1>Authorization leaves the code.</h1>
    <p>Identity left your applications years ago. Authorization stayed inside them, different in every one. Permguard takes it out, gives it an owner and keeps every decision on record.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The gap</div><h2>Identity moved out. Authorization did not.</h2></div><p>Inside the applications, who may do what is still decided by code.</p></div>
    <div class="pgx-principles">
      <article><span>Then</span><h3>Every application kept its passwords.</h3><p>In its own files and databases. Hashes and salts came later, but each application stayed an island.</p></article>
      <article><span>Later</span><h3>Identity left the application.</h3><p>An Identity Provider and standard protocols. Identity got an owner, a console and an audit.</p></article>
      <article><span>Today</span><h3>Authorization is still in the code.</h3><p>An <code>if</code> here, a role table there, and nobody holds the map. AI agents now act inside applications at machine speed: every forgotten rule is an open door.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The same turn</div><h2>Ask. Decide. Enforce.</h2></div><p>Every application and every AI agent asks Permguard the same question.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="An application or AI agent asks whether a subject may perform an action on a resource, the Policy Decision Point evaluates the published policy, and the application enforces the answer, which names the policy that decided it.">
      <article><small>PEP · ASK</small><strong>May this subject do this action, on this resource?</strong><span>application · AI agent · API</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>PDP · DECIDE</small><strong>Evaluate the published policy</strong><span>Permguard Data Plane</span></article><i>→</i>
      <article><small>PEP · ENFORCE</small><strong>Apply the answer</strong><span>permit or deny, naming its policy</span></article>
    </div>
    <p>The <strong>Policy Enforcement Point</strong> guards an action: it asks and it enforces. The <strong>Policy Decision Point</strong> decides, with the exact policy version it names in the answer.</p>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The structure</div><h2>Govern centrally. Decide close.</h2></div><p>One Permguard Server: a Host and the planes you choose, together or apart.</p></div>
    <div class="pgx-system-map" role="img" aria-label="A Permguard Server Host provides identity, authorization, keys, audit, membership and streams to the Authority, Control and Data planes. Identities stay with your Identity Provider; decisions and audit become signed, chained records; one URL discovers the rest.">
      <div class="pgx-system-map__frame">
        <div class="pgx-system-map__label"><strong>Permguard Server</strong><span>one Host · the planes you deploy</span></div>
        <div class="pgx-system-map__host"><small>SERVER HOST</small><strong>Identity · Authorization · Keys · Audit · Membership · Streams</strong></div>
        <div class="pgx-system-map__bus" aria-hidden="true"></div>
        <div class="pgx-system-map__planes">
          <article><small>AUTHORITY PLANE</small><strong>Admit</strong><span>service accounts · access tokens</span></article>
          <article><small>CONTROL PLANE</small><strong>Publish</strong><span>versioned, signed policy</span></article>
          <article><small>DATA PLANE</small><strong>Decide</strong><span>sidecar · remote · embedded</span></article>
        </div>
      </div>
      <div class="pgx-system-map__protocols">
        <article><small>IDENTITY</small><strong>Your Identity Provider</strong><span>identities stay where they are</span></article>
        <article><small>EVIDENCE</small><strong>Signed records</strong><span>decisions · events · audit</span></article>
        <article><small>DISCOVERY</small><strong>One URL</strong><span>server → plane → interface</span></article>
      </div>
    </div>
    <p class="pgx-system-map__truth">Policies are written once, in the Control Plane: versioned, signed and distributed. The Data Plane decides beside the workload, as a sidecar or a remote service, or inside the process through the engine libraries. The <a :href="withBase('/trust-plane')">Trust Plane</a>, for authority continuity, is in development.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Who does what</div><h2>Authorization gets an owner.</h2></div><p>The rules no longer start in the code.</p></div>
    <div class="pgx-principles">
      <article><span>Security</span><h3>Owns the rules.</h3><p>Application authorization becomes a first-level control, with every decision in view.</p></article>
      <article><span>Compliance</span><h3>Holds the proof.</h3><p>Policies aligned with regulation, decisions recorded and verifiable after the fact.</p></article>
      <article><span>Development</span><h3>Enforces.</h3><p>Only the Policy Enforcement Point, through SDKs for Go, Java, .NET, Node.js, Python and Rust.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The tools</div><h2>One server. Every role.</h2></div><p>The same policies and decisions, from a terminal, a desktop or your code.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <a class="pgx-card" :href="withBase('/command-line')"><span>CLI</span><h3>Permguard CLI</h3><p>Author, validate, test offline and publish policy, from a terminal or a pipeline.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/how-it-works/install#permguard-admin')"><span>Desktop</span><h3>Permguard Admin</h3><p>Ledgers where every change is a commit, decision logs, analytics and export.</p><b aria-hidden="true">→</b></a>
      <article class="pgx-card"><span>Code</span><h3>SDKs</h3><p>The Policy Enforcement Point in your application: Go, Java, .NET, Node.js, Python and Rust.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Observable</div><h2>Every decision, on record.</h2></div><p>The new challenge: make the application security layer observable.</p></div>
    <div class="pgx-principles">
      <article><span>Recorded</span><h3>Who, what, on which resource, under which policy.</h3><p>Permitted or denied. Records are chained and signed, so anyone can verify that nobody touched them.</p></article>
      <article><span>Analysed</span><h3>Into your SIEM.</h3><p>Export decisions as JSON Lines or CSV, beside your firewall logs, and cross them with threat intelligence.</p></article>
      <article><span>Stable</span><h3>The policy stays. The context moves.</h3><p>When the threat changes, the policy is not rewritten: the information in the evaluation context changes.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Mental model</div><h2>From policy to proof.</h2></div><p>Three rules are enough.</p></div>
    <div class="pgx-flow" role="img" aria-label="A policy moves from authoring to the control plane, then to the data plane, where a decision produces evidence.">
      <div class="pgx-flow__track"><i aria-hidden="true"></i></div>
      <div class="pgx-flow__step"><b>01</b><strong>Author</strong><span>policy as code</span></div>
      <div class="pgx-flow__step"><b>02</b><strong>Publish</strong><span>signed head</span></div>
      <div class="pgx-flow__step"><b>03</b><strong>Mirror</strong><span>verify first</span></div>
      <div class="pgx-flow__step"><b>04</b><strong>Decide</strong><span>fail closed</span></div>
      <div class="pgx-flow__step"><b>05</b><strong>Prove</strong><span>evidence</span></div>
    </div>
    <div class="pgx-principles">
      <article><span>Immutable</span><h3>A version never changes.</h3><p>Policies become content-addressed objects. A signed head selects the accepted commit.</p></article>
      <article><span>Local</span><h3>Decisions stay near the workload.</h3><p>The Data Plane already holds the verified policy: a decision never waits for the Control Plane.</p></article>
      <article><span>Traceable</span><h3>An answer leaves evidence.</h3><p>The signer, the decision and the exact policy version remain independently verifiable.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Start</div><h2>See it working.</h2></div><p>The tools first. A real server next.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <a class="pgx-card pgx-card--accent" :href="withBase('/how-it-works/install')"><span>01</span><h3>Install</h3><p>The Permguard CLI and Permguard Admin on your machine.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/container-images')"><span>02</span><h3>Containers</h3><p>The server images, verified before they run.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/getting-started')"><span>03</span><h3>Getting Started</h3><p>Create, test, publish and ask a policy.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Concepts</div><h2>Go one layer deeper.</h2></div></div>
    <div class="pgx-link-grid">
      <a :href="withBase('/how-it-works/architecture')"><strong>Server, Host &amp; Planes</strong><span>compose the architecture</span></a>
      <a :href="withBase('/how-it-works/authority-plane')"><strong>Authority Plane</strong><span>service accounts → access tokens</span></a>
      <a :href="withBase('/how-it-works/access-tokens')"><strong>Access Tokens &amp; Clusters</strong><span>verify · revoke · every plane</span></a>
      <a :href="withBase('/how-it-works/policy-storage')"><strong>Git-like Policy Storage</strong><span>files → objects → immutable history</span></a>
      <a :href="withBase('/how-it-works/bring-your-own-data-plane')"><strong>Bring Your Own Data Plane</strong><span>Permguard policy → your runtime</span></a>
      <a :href="withBase('/how-it-works/policy-lifecycle')"><strong>Policy Lifecycle</strong><span>source → signed version → mirror</span></a>
      <a :href="withBase('/how-it-works/decision-lifecycle')"><strong>Decision Lifecycle</strong><span>request → evaluation → answer</span></a>
      <a :href="withBase('/how-it-works/evidence')"><strong>Evidence &amp; Verification</strong><span>record → chain → proof</span></a>
      <a :href="withBase('/how-it-works/temporal-authorization')"><strong>Temporal Authorization</strong><span>history becomes policy input</span></a>
      <a :href="withBase('/how-it-works/policy-languages')"><strong>Policy Languages</strong><span>Cedar · Rego · Dogwood</span></a>    </div>
    <nav class="pgx-pager pgx-pager--next-only" aria-label="Documentation pages">
      <a class="pgx-pager__next" :href="withBase('/how-it-works/install')"><span>Next</span><strong>Install <b aria-hidden="true">→</b></strong></a>
    </nav>
  </section>
</main>
