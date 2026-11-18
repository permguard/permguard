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
    <div class="pgx-hero-visual" role="img" aria-label="The Control Plane distributes signed policy to a Policy Decision Point beside every workload, in three clusters. Applications and AI agents ask their PDP through the Permguard SDKs, for Go, Java, .NET, Node.js, Python and Rust, their Policy Enforcement Point; identities come from your Identity Provider. Every decision becomes a signed, chained record, exported to your SIEM.">
      <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 420" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="pgx-hv-wide-flow" gradientUnits="userSpaceOnUse" x1="0" y1="84" x2="0" y2="186"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
        </defs>
        <g class="pgx-hv__flows">
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V120 H349 V186"/>
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V186"/>
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V120 H799 V186"/>
          <path class="pgx-hv__flow pgx-hv__flow--identity" d="M170 212 H200"/>
          <path class="pgx-hv__flow pgx-hv__flow--identity" d="M860 210 H840"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M295 270 V336"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M520 270 V336"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M745 270 V336"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M840 360 H870"/>
        </g>
        <g class="pgx-hv__node pgx-hv__node--cp">
          <rect x="400" y="20" width="240" height="64" rx="14"/>
          <text class="pgx-hv__k" x="520" y="46" text-anchor="middle">CONTROL PLANE</text>
          <text class="pgx-hv__s" x="520" y="68" text-anchor="middle">versioned · signed policy</text>
        </g>
        <g class="pgx-hv__node">
          <rect x="20" y="180" width="150" height="64" rx="14"/>
          <text class="pgx-hv__k" x="95" y="206" text-anchor="middle">IDENTITY</text>
          <text class="pgx-hv__s" x="95" y="228" text-anchor="middle">Your IdP</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="200" y="150" width="190" height="120" rx="16"/>
          <text class="pgx-hv__m" x="216" y="172">cluster · eu-west</text>
          <rect class="pgx-hv__pod" x="216" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="267" y="205" text-anchor="middle">orders · app</text>
          <rect class="pgx-hv__pdp" x="324" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="349" y="205" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="216" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="267" y="245" text-anchor="middle">planner · agent</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--2" x="324" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="349" y="245" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="425" y="150" width="190" height="120" rx="16"/>
          <text class="pgx-hv__m" x="441" y="172">cluster · us-east</text>
          <rect class="pgx-hv__pod" x="441" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="492" y="205" text-anchor="middle">billing · api</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="549" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="574" y="205" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="441" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="492" y="245" text-anchor="middle">support · agent</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--4" x="549" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="574" y="245" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="650" y="150" width="190" height="120" rx="16"/>
          <text class="pgx-hv__m" x="666" y="172">edge</text>
          <rect class="pgx-hv__pod" x="666" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="717" y="205" text-anchor="middle">gateway</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="774" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="799" y="205" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="666" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="717" y="245" text-anchor="middle">worker · agent</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--6" x="774" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="799" y="245" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__node pgx-hv__node--sdk">
          <rect x="860" y="150" width="160" height="120" rx="14"/>
          <text class="pgx-hv__k" x="940" y="170" text-anchor="middle">PEP · SDKS</text>
          <g class="pgx-hv__lang"><title>Go</title><rect x="887" y="178" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/go.svg')" x="893" y="184" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Java</title><rect x="927" y="178" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/java.svg')" x="933" y="184" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>.NET</title><rect x="967" y="178" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/dotnet.svg')" x="973" y="184" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Node.js</title><rect x="887" y="214" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/nodejs.svg')" x="893" y="220" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Python</title><rect x="927" y="214" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/python.svg')" x="933" y="220" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Rust</title><rect x="967" y="214" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/rust.svg')" x="973" y="220" width="20" height="20"/></g>
          <text class="pgx-hv__m" x="940" y="261" text-anchor="middle">in every workload</text>
        </g>
        <text class="pgx-hv__k" x="200" y="326">EVIDENCE · SIGNED · CHAINED</text>
        <g class="pgx-hv__chain">
          <path class="pgx-hv__link" d="M290 360 H310 M400 360 H420 M510 360 H530 M620 360 H640 M730 360 H750"/>
          <rect class="pgx-hv__block pgx-hv__block--1" x="200" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="245" y="365" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--2" x="310" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="355" y="365" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--3" x="420" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="465" y="365" text-anchor="middle">deny</text>
          <rect class="pgx-hv__block pgx-hv__block--4" x="530" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="575" y="365" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--5" x="640" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="685" y="365" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--6" x="750" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="795" y="365" text-anchor="middle">deny</text>
        </g>
        <g class="pgx-hv__node">
          <rect x="870" y="328" width="150" height="64" rx="14"/>
          <text class="pgx-hv__k" x="945" y="354" text-anchor="middle">EXPORT</text>
          <text class="pgx-hv__s" x="945" y="376" text-anchor="middle">Your SIEM</text>
        </g>
      </svg>
      <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 676" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="pgx-hv-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="74" x2="0" y2="332"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
        </defs>
        <g class="pgx-hv__flows">
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 74 V112"/>
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 204 V222"/>
          <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 314 V332"/>
          <path class="pgx-hv__flow pgx-hv__flow--identity" d="M180 424 V440"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 516 V534"/>
          <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 574 V606"/>
        </g>
        <g class="pgx-hv__node pgx-hv__node--cp">
          <rect x="70" y="14" width="220" height="60" rx="14"/>
          <text class="pgx-hv__k" x="180" y="38" text-anchor="middle">CONTROL PLANE</text>
          <text class="pgx-hv__s" x="180" y="60" text-anchor="middle">versioned · signed policy</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="16" y="112" width="328" height="92" rx="16"/>
          <text class="pgx-hv__m" x="32" y="134">cluster · eu-west</text>
          <rect class="pgx-hv__pod" x="32" y="152" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="174" text-anchor="middle">orders</text>
          <rect class="pgx-hv__pdp" x="134" y="152" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="174" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="186" y="152" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="174" text-anchor="middle">planner</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--2" x="288" y="152" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="174" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="16" y="222" width="328" height="92" rx="16"/>
          <text class="pgx-hv__m" x="32" y="244">cluster · us-east</text>
          <rect class="pgx-hv__pod" x="32" y="262" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="284" text-anchor="middle">billing</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="134" y="262" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="284" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="186" y="262" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="284" text-anchor="middle">support</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--4" x="288" y="262" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="284" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__cluster">
          <rect class="pgx-hv__frame" x="16" y="332" width="328" height="92" rx="16"/>
          <text class="pgx-hv__m" x="32" y="354">edge</text>
          <rect class="pgx-hv__pod" x="32" y="372" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="394" text-anchor="middle">gateway</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="134" y="372" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="394" text-anchor="middle">PDP</text>
          <rect class="pgx-hv__pod" x="186" y="372" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="394" text-anchor="middle">worker</text>
          <rect class="pgx-hv__pdp pgx-hv__pdp--6" x="288" y="372" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="394" text-anchor="middle">PDP</text>
        </g>
        <g class="pgx-hv__node pgx-hv__node--sdk">
          <rect x="16" y="440" width="328" height="76" rx="14"/>
          <text class="pgx-hv__k" x="180" y="460" text-anchor="middle">PEP · SDKS IN EVERY WORKLOAD</text>
          <g class="pgx-hv__lang"><title>Go</title><rect x="44" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/go.svg')" x="50" y="476" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Java</title><rect x="92" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/java.svg')" x="98" y="476" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>.NET</title><rect x="140" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/dotnet.svg')" x="146" y="476" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Node.js</title><rect x="188" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/nodejs.svg')" x="194" y="476" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Python</title><rect x="236" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/python.svg')" x="242" y="476" width="20" height="20"/></g>
          <g class="pgx-hv__lang"><title>Rust</title><rect x="284" y="470" width="32" height="32" rx="7"/><image :href="withBase('/permguard/languages/rust.svg')" x="290" y="476" width="20" height="20"/></g>
        </g>
        <g class="pgx-hv__chain">
          <path class="pgx-hv__link" d="M95 554 H109 M173 554 H187 M251 554 H265"/>
          <rect class="pgx-hv__block pgx-hv__block--1" x="31" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="63" y="559" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--2" x="109" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="141" y="559" text-anchor="middle">permit</text>
          <rect class="pgx-hv__block pgx-hv__block--3" x="187" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="219" y="559" text-anchor="middle">deny</text>
          <rect class="pgx-hv__block pgx-hv__block--4" x="265" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="297" y="559" text-anchor="middle">permit</text>
        </g>
        <g class="pgx-hv__node">
          <rect x="90" y="606" width="180" height="56" rx="14"/>
          <text class="pgx-hv__k" x="180" y="628" text-anchor="middle">EXPORT</text>
          <text class="pgx-hv__s" x="180" y="650" text-anchor="middle">Your SIEM</text>
        </g>
      </svg>
    </div>
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
