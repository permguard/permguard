---
layout: page
pageClass: pg-page-concepts
title: Data Plane
description: Decide beside the workload. Any enforcement point asks the Data Plane, which decides with the policies synced from the Control Plane and syncs its decision logs and events back.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">Data Plane · :7443</div>
    <h1>Decide beside the workload.</h1>
    <p>Any enforcement point asks it: an application, an AI agent, a gateway, an infrastructure component, a tool. It decides with the policies synced from the Control Plane, and syncs its decision logs and events back to it.</p>
    <div class="pgx-hero-visual">
      <div class="pgx-hero-visual__art" role="img" aria-label="The Control Plane holds the policies, the decision logs and the events. The Data Plane on port 7443 syncs the policies from it and verifies their signature before using them, then answers any enforcement point: applications, AI agents, API gateways, infrastructure components, tools and services. Every answer becomes a signed record chained to the one before; the decision logs and the events are synced back to the Control Plane.">
        <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 400" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-dp-wide-flow" gradientUnits="userSpaceOnUse" x1="0" y1="84" x2="0" y2="130"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-dp-wide-flow)" d="M520 84 V130"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M700 196 H780"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M780 240 H700"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M520 290 V318"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M820 358 H840"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="400" y="20" width="240" height="64" rx="14"/>
            <text class="pgx-hv__k" x="520" y="46" text-anchor="middle">CONTROL PLANE</text>
            <text class="pgx-hv__s" x="520" y="68" text-anchor="middle">policies · decision logs · events</text>
          </g>
          <text class="pgx-hv__m" x="532" y="112">policies, synced and verified</text>
          <g class="pgx-hv__node">
            <rect x="340" y="130" width="360" height="160" rx="18"/>
            <text class="pgx-hv__k" x="520" y="158" text-anchor="middle">DATA PLANE · :7443</text>
            <rect class="pgx-hv__pod" x="364" y="174" width="312" height="30" rx="8"/><text class="pgx-hv__p" x="520" y="194" text-anchor="middle">a verified copy of the policy</text>
            <rect class="pgx-hv__pdp" x="364" y="212" width="312" height="30" rx="8"/><text class="pgx-hv__d" x="520" y="232" text-anchor="middle">PDP · DECIDE: PERMIT OR DENY</text>
            <rect class="pgx-hv__pod" x="364" y="250" width="312" height="30" rx="8"/><text class="pgx-hv__p" x="520" y="270" text-anchor="middle">a signed record of the answer</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--sdk">
            <rect x="780" y="150" width="240" height="130" rx="14"/>
            <text class="pgx-hv__k" x="900" y="172" text-anchor="middle">ENFORCEMENT POINTS</text>
            <g class="pgx-hv__lang"><rect x="794" y="182" width="102" height="20" rx="10"/><text x="845" y="196" text-anchor="middle">Applications</text></g>
            <g class="pgx-hv__lang"><rect x="904" y="182" width="102" height="20" rx="10"/><text x="955" y="196" text-anchor="middle">AI agents</text></g>
            <g class="pgx-hv__lang"><rect x="794" y="206" width="102" height="20" rx="10"/><text x="845" y="220" text-anchor="middle">API gateways</text></g>
            <g class="pgx-hv__lang"><rect x="904" y="206" width="102" height="20" rx="10"/><text x="955" y="220" text-anchor="middle">Infrastructure</text></g>
            <g class="pgx-hv__lang"><rect x="794" y="230" width="102" height="20" rx="10"/><text x="845" y="244" text-anchor="middle">Tools</text></g>
            <g class="pgx-hv__lang"><rect x="904" y="230" width="102" height="20" rx="10"/><text x="955" y="244" text-anchor="middle">Any service</text></g>
            <text class="pgx-hv__m" x="900" y="268" text-anchor="middle">each one asks, then obeys</text>
          </g>
          <text class="pgx-hv__m" x="740" y="188" text-anchor="middle">answer</text>
          <text class="pgx-hv__m" x="740" y="258" text-anchor="middle">ask</text>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="20" y="150" width="240" height="130" rx="14"/>
            <text class="pgx-hv__k" x="140" y="178" text-anchor="middle">WHERE IT RUNS</text>
            <text class="pgx-hv__p" x="140" y="206" text-anchor="middle">a sidecar beside your app</text>
            <text class="pgx-hv__p" x="140" y="232" text-anchor="middle">a service your apps call</text>
            <text class="pgx-hv__p" x="140" y="258" text-anchor="middle">inside your own process</text>
          </g>
          <path class="pgx-hv__flow pgx-hv__flow--identity" d="M260 215 H340"/>
          <text class="pgx-hv__k" x="220" y="324">EVIDENCE · SIGNED · CHAINED</text>
          <g class="pgx-hv__chain">
            <path class="pgx-hv__link" d="M310 358 H330 M420 358 H440 M530 358 H550 M640 358 H660 M750 358 H770"/>
            <rect class="pgx-hv__block pgx-hv__block--1" x="220" y="338" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="265" y="363" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--2" x="330" y="338" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="375" y="363" text-anchor="middle">deny</text>
            <rect class="pgx-hv__block pgx-hv__block--3" x="440" y="338" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="485" y="363" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--4" x="550" y="338" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="595" y="363" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--5" x="660" y="338" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="705" y="363" text-anchor="middle">deny</text>
            <rect class="pgx-hv__block pgx-hv__block--6" x="770" y="338" width="50" height="40" rx="8"/><text class="pgx-hv__p" x="795" y="363" text-anchor="middle">…</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--siem">
            <rect x="840" y="326" width="186" height="64" rx="14"/>
            <text class="pgx-hv__k" x="933" y="352" text-anchor="middle">TO THE CONTROL PLANE</text>
            <text class="pgx-hv__s" x="933" y="374" text-anchor="middle">decision logs · events</text>
          </g>
        </svg>
        <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 700" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-dp-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="74" x2="0" y2="110"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-dp-compact-flow)" d="M180 74 V110"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M180 290 V322"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 466 V500"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 590 V612"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="60" y="14" width="240" height="60" rx="14"/>
            <text class="pgx-hv__k" x="180" y="38" text-anchor="middle">CONTROL PLANE</text>
            <text class="pgx-hv__s" x="180" y="60" text-anchor="middle">policies · logs · events</text>
          </g>
          <g class="pgx-hv__node">
            <rect x="16" y="110" width="328" height="180" rx="18"/>
            <text class="pgx-hv__k" x="180" y="138" text-anchor="middle">DATA PLANE · :7443</text>
            <rect class="pgx-hv__pod" x="36" y="154" width="288" height="34" rx="8"/><text class="pgx-hv__p" x="180" y="177" text-anchor="middle">a verified copy of the policy</text>
            <rect class="pgx-hv__pdp" x="36" y="196" width="288" height="34" rx="8"/><text class="pgx-hv__d" x="180" y="219" text-anchor="middle">PDP · PERMIT OR DENY</text>
            <rect class="pgx-hv__pod" x="36" y="238" width="288" height="34" rx="8"/><text class="pgx-hv__p" x="180" y="261" text-anchor="middle">a signed record</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--sdk">
            <rect x="16" y="322" width="328" height="144" rx="14"/>
            <text class="pgx-hv__k" x="180" y="346" text-anchor="middle">ENFORCEMENT POINTS</text>
            <g class="pgx-hv__lang"><rect x="32" y="358" width="144" height="24" rx="12"/><text x="104" y="375" text-anchor="middle">Applications</text></g>
            <g class="pgx-hv__lang"><rect x="184" y="358" width="144" height="24" rx="12"/><text x="256" y="375" text-anchor="middle">AI agents</text></g>
            <g class="pgx-hv__lang"><rect x="32" y="388" width="144" height="24" rx="12"/><text x="104" y="405" text-anchor="middle">API gateways</text></g>
            <g class="pgx-hv__lang"><rect x="184" y="388" width="144" height="24" rx="12"/><text x="256" y="405" text-anchor="middle">Infrastructure</text></g>
            <g class="pgx-hv__lang"><rect x="32" y="418" width="144" height="24" rx="12"/><text x="104" y="435" text-anchor="middle">Tools</text></g>
            <g class="pgx-hv__lang"><rect x="184" y="418" width="144" height="24" rx="12"/><text x="256" y="435" text-anchor="middle">Any service</text></g>
            <text class="pgx-hv__m" x="180" y="458" text-anchor="middle">each one asks, then obeys</text>
          </g>
          <g class="pgx-hv__chain">
            <path class="pgx-hv__link" d="M110 545 H130 M230 545 H250"/>
            <rect class="pgx-hv__block pgx-hv__block--1" x="16" y="500" width="94" height="90" rx="10"/><text class="pgx-hv__p" x="63" y="550" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--2" x="130" y="500" width="100" height="90" rx="10"/><text class="pgx-hv__p" x="180" y="550" text-anchor="middle">deny</text>
            <rect class="pgx-hv__block pgx-hv__block--3" x="250" y="500" width="94" height="90" rx="10"/><text class="pgx-hv__p" x="297" y="550" text-anchor="middle">permit</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--siem">
            <rect x="60" y="612" width="240" height="64" rx="14"/>
            <text class="pgx-hv__k" x="180" y="638" text-anchor="middle">TO THE CONTROL PLANE</text>
            <text class="pgx-hv__s" x="180" y="660" text-anchor="middle">decision logs · events</text>
          </g>
        </svg>
      </div>
      <dl class="pgx-legend">
        <div data-term="cp"><dt><a :href="withBase('/control-plane')">Control Plane</a></dt><dd>Holds the policies the Data Plane decides with, and the decision logs and events it syncs back.</dd></div>
        <div data-term="pdp"><dt><a :href="withBase('/how-it-works/glossary#pdp')">PDP</a></dt><dd>Policy Decision Point: the Data Plane's answer, permit or deny.</dd></div>
        <div data-term="pep"><dt><a :href="withBase('/how-it-works/glossary#pep')">Enforcement point</a></dt><dd>Any application, AI agent, gateway, component or tool that asks, then obeys.</dd></div>
        <div data-term="idp"><dt><a :href="withBase('/how-it-works/bring-your-own-data-plane')">Where it runs</a></dt><dd>Beside your app, as a service, or inside your process.</dd></div>
        <div data-term="evidence"><dt><a :href="withBase('/how-it-works/glossary#evidence')">Evidence</a></dt><dd>Every answer, signed and chained to the one before.</dd></div>
        <div data-term="siem"><dt><a :href="withBase('/control-plane')">Synced back</a></dt><dd>Decision logs and events return to the Control Plane; export them from there to your SIEM.</dd></div>
      </dl>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The idea</div><h2>The answer is already here.</h2></div><p>An enforcement point asks one question; the Data Plane answers it with the policies it already holds.</p></div>
    <div class="pgx-principles">
      <article><span>Verify</span><h3>Only a policy it trusts.</h3><p>It takes the version the <a :href="withBase('/control-plane')">Control Plane</a> signed, checks the signature, and refuses anything that does not verify.</p></article>
      <article><span>Decide</span><h3>Permit or deny, right here.</h3><p>Who, does what, on what: the <a :href="withBase('/how-it-works/glossary#pdp')">PDP</a> answers on the spot, without calling anyone else first.</p></article>
      <article><span>Record</span><h3>Every answer, on record.</h3><p>Each decision becomes a signed record chained to the one before, naming the policy that made it. The decision logs and the events it receives are synced back to the Control Plane.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">In practice</div><h2>One line in your code asks.</h2></div><p>Any enforcement point asks the same way: an SDK in your code, or a gateway or tool calling the HTTP or gRPC API. No answer is a no.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="Your code asks whether a subject may perform an action on a resource; the Data Plane decides with the verified policy and records the decision; your code applies the answer.">
      <article><small>YOUR CODE · ASK</small><strong>May alice read the budget?</strong><span>through the SDK, your PEP</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>DATA PLANE · DECIDE</small><strong>Verified policy, signed record</strong><span>permit or deny, on record</span></article><i>→</i>
      <article><small>YOUR CODE · ENFORCE</small><strong>Apply the answer</strong><span>serve the budget, or refuse</span></article>
    </div>
    <div class="vp-doc pgx-sdk-ask">

<!--@include: ./snippets/sdk-check.md-->

</div>
    <p class="pgx-anatomy__note">The same check in every SDK language. The whole round, from an empty folder to this answer, is in <a :href="withBase('/how-it-works/getting-started')">Getting Started</a>.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Where it runs</div><h2>As close to the workload as you want.</h2></div><p>The same engine and the same answer, in three places.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <article class="pgx-card pgx-card--accent"><span>Sidecar</span><h3>Beside each application.</h3><p>One Data Plane next to each workload: a local call, and the policy already there.</p></article>
      <article class="pgx-card"><span>Service</span><h3>One your applications call.</h3><p>A shared Data Plane over HTTP or gRPC on port <code>7443</code>, for the applications that prefer it.</p></article>
      <a class="pgx-card" :href="withBase('/how-it-works/bring-your-own-data-plane')"><span>In your process</span><h3>Inside your own code.</h3><p>Pull the signed policy and evaluate it with the same engine libraries: no network on the decision path.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Why it matters</div><h2>Fast answers you can prove.</h2></div><p>What each role gets from a decision point beside every workload.</p></div>
    <div class="pgx-principles">
      <article><span>Developers</span><h3>One call, every language.</h3><p>Ask with the SDK for Go, Java, .NET, Node.js, Python or Rust. No rule in your code, and the same answer everywhere.</p></article>
      <article><span>Platform &amp; IT</span><h3>Decisions that do not wait.</h3><p>The policy is already in the Data Plane: deciding never waits for the Control Plane, and keeps going if it is down.</p></article>
      <article><span>Security &amp; CISO</span><h3>Every answer, provable.</h3><p>Every decision names the exact policy and version that made it, in a signed chain you can export to your SIEM and verify later.</p></article>
    </div>
  </section>

  <section class="pgx-section" id="faq">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Questions</div><h2>What people ask first.</h2></div><p>Straight answers.</p></div>
    <div class="pgx-faq">
      <details><summary>What if the Control Plane is down?</summary><p>The Data Plane keeps deciding with the version it already verified. Only new versions wait until the Control Plane is back.</p></details>
      <details><summary>What if the Data Plane does not answer?</summary><p>The SDK returns an error, not a deny. Treat it as a no, as the code above does: fail closed.</p></details>
      <details><summary>Can it decide with a policy nobody signed?</summary><p>No. A version whose signature does not verify is never used.</p></details>
      <details><summary>Is every decision recorded?</summary><p>In the shipped configurations an answer leaves only once its record is durable: signed and chained to the one before. The Data Plane syncs the records, and the events it receives, back to the Control Plane. See <a :href="withBase('/how-it-works/evidence')">Verifiable Evidence</a>.</p></details>
      <details><summary>What can be an enforcement point?</summary><p>Anything that must allow or refuse an action: an application, an AI agent, an API gateway or proxy, an infrastructure component, a tool. It asks over HTTP or gRPC, or through an SDK, and obeys the answer.</p></details>
      <details><summary>Does it decide with what happened before?</summary><p>It can: events you send build a history the policy reads, for rules like "only after a login". See <a :href="withBase('/how-it-works/temporal-authorization')">Temporal Authorization</a>.</p></details>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Go deeper</div><h2>The ideas behind it.</h2></div><p>Each one in plain words.</p></div>
    <div class="pgx-cards pgx-cards--2">
      <a class="pgx-card" :href="withBase('/how-it-works/decision-lifecycle')"><span>Concept</span><h3>Decision Path</h3><p>A question, from your code to the answer.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/evidence')"><span>Concept</span><h3>Verifiable Evidence</h3><p>Why a record cannot be altered unnoticed.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/temporal-authorization')"><span>Concept</span><h3>Temporal Authorization</h3><p>Decisions that depend on what happened before.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/control-plane')"><span>Plane</span><h3>Control Plane</h3><p>Where the version it decides with is published.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>
</main>
