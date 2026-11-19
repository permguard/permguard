---
layout: page
pageClass: pg-page-concepts
title: Control Plane
description: The center of Permguard. Policies, every version kept and the one in force signed; the decision logs and events every Data Plane sends back.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">Control Plane · :6443</div>
    <h1>The center of Permguard.</h1>
    <p>Everything Permguard governs and everything it produces meets here: your policies, every version kept and the one in force signed, and the decision logs and events that every Data Plane sends back.</p>
    <div class="pgx-hero-visual">
      <div class="pgx-hero-visual__art" role="img" aria-label="A workspace or a CI pipeline publishes a policy change to the Control Plane on port 6443. The Control Plane keeps the catalog of zones and ledgers, every version ever published, and a signed head naming the version in force. Data Planes in every cluster mirror that exact version, verify its signature, and decide with it; their decision records come back to the Control Plane.">
        <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 380" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-cp-wide-flow" gradientUnits="userSpaceOnUse" x1="190" y1="0" x2="800" y2="0"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-wide-flow)" d="M200 176 H330"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-wide-flow)" d="M710 176 H750 V108 H800"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-wide-flow)" d="M710 176 H800"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-wide-flow)" d="M710 176 H750 V244 H800"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M910 290 V336 H520 V300"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="20" y="132" width="180" height="88" rx="14"/>
            <text class="pgx-hv__k" x="110" y="160" text-anchor="middle">YOU PUBLISH</text>
            <text class="pgx-hv__s" x="110" y="184" text-anchor="middle">a workspace</text>
            <text class="pgx-hv__m" x="110" y="204" text-anchor="middle">laptop · CI pipeline</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="330" y="40" width="380" height="260" rx="18"/>
            <text class="pgx-hv__k" x="520" y="72" text-anchor="middle">CONTROL PLANE · :6443</text>
            <rect class="pgx-hv__pod" x="360" y="92" width="320" height="52" rx="10"/>
            <text class="pgx-hv__p" x="380" y="114">Zones &amp; ledgers</text>
            <text class="pgx-hv__m" x="380" y="133">the catalog: where everything belongs</text>
            <rect class="pgx-hv__pod" x="360" y="154" width="320" height="52" rx="10"/>
            <text class="pgx-hv__p" x="380" y="176">Policies, every version</text>
            <text class="pgx-hv__m" x="380" y="195">kept for good · the one in force signed</text>
            <rect class="pgx-hv__pdp" x="360" y="216" width="320" height="56" rx="10"/>
            <text class="pgx-hv__d" x="380" y="240">DECISION LOGS · EVENTS</text>
            <text class="pgx-hv__m" x="380" y="259">sent back by every Data Plane, verified, kept</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="790" y="40" width="230" height="250" rx="16"/>
            <text class="pgx-hv__m" x="806" y="64">Data Planes · every cluster</text>
            <rect class="pgx-hv__pod" x="806" y="88" width="132" height="40" rx="8"/><text class="pgx-hv__p" x="872" y="113" text-anchor="middle">eu-west</text>
            <rect class="pgx-hv__pdp" x="946" y="88" width="58" height="40" rx="8"/><text class="pgx-hv__d" x="975" y="113" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="806" y="156" width="132" height="40" rx="8"/><text class="pgx-hv__p" x="872" y="181" text-anchor="middle">us-east</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="946" y="156" width="58" height="40" rx="8"/><text class="pgx-hv__d" x="975" y="181" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="806" y="224" width="132" height="40" rx="8"/><text class="pgx-hv__p" x="872" y="249" text-anchor="middle">edge</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="946" y="224" width="58" height="40" rx="8"/><text class="pgx-hv__d" x="975" y="249" text-anchor="middle">PDP</text>
          </g>
          <text class="pgx-hv__m" x="265" y="166" text-anchor="middle">apply</text>
          <text class="pgx-hv__m" x="776" y="98" text-anchor="middle">mirror</text>
          <text class="pgx-hv__m" x="715" y="360" text-anchor="middle">decision records come back, signed</text>
        </svg>
        <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 640" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-cp-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="90" x2="0" y2="400"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-compact-flow)" d="M180 90 V122"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-cp-compact-flow)" d="M180 382 V414"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="60" y="14" width="240" height="76" rx="14"/>
            <text class="pgx-hv__k" x="180" y="40" text-anchor="middle">YOU PUBLISH</text>
            <text class="pgx-hv__s" x="180" y="62" text-anchor="middle">a workspace</text>
            <text class="pgx-hv__m" x="180" y="80" text-anchor="middle">laptop · CI pipeline</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="16" y="122" width="328" height="260" rx="18"/>
            <text class="pgx-hv__k" x="180" y="152" text-anchor="middle">CONTROL PLANE · :6443</text>
            <rect class="pgx-hv__pod" x="36" y="170" width="288" height="54" rx="10"/>
            <text class="pgx-hv__p" x="54" y="193">Zones &amp; ledgers</text>
            <text class="pgx-hv__m" x="54" y="213">where everything belongs</text>
            <rect class="pgx-hv__pod" x="36" y="234" width="288" height="54" rx="10"/>
            <text class="pgx-hv__p" x="54" y="257">Policies, every version</text>
            <text class="pgx-hv__m" x="54" y="277">kept · the one in force signed</text>
            <rect class="pgx-hv__pdp" x="36" y="298" width="288" height="62" rx="10"/>
            <text class="pgx-hv__d" x="54" y="323">DECISION LOGS · EVENTS</text>
            <text class="pgx-hv__m" x="54" y="345">sent back, verified, kept</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="16" y="414" width="328" height="196" rx="16"/>
            <text class="pgx-hv__m" x="32" y="440">Data Planes · mirror &amp; verify</text>
            <rect class="pgx-hv__pod" x="32" y="456" width="216" height="38" rx="8"/><text class="pgx-hv__p" x="140" y="481" text-anchor="middle">eu-west</text>
            <rect class="pgx-hv__pdp" x="256" y="456" width="72" height="38" rx="8"/><text class="pgx-hv__d" x="292" y="481" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="32" y="504" width="216" height="38" rx="8"/><text class="pgx-hv__p" x="140" y="529" text-anchor="middle">us-east</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="256" y="504" width="72" height="38" rx="8"/><text class="pgx-hv__d" x="292" y="529" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="32" y="552" width="216" height="38" rx="8"/><text class="pgx-hv__p" x="140" y="577" text-anchor="middle">edge</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="256" y="552" width="72" height="38" rx="8"/><text class="pgx-hv__d" x="292" y="577" text-anchor="middle">PDP</text>
          </g>
          <text class="pgx-hv__m" x="180" y="630" text-anchor="middle">decision records come back, signed</text>
        </svg>
      </div>
      <dl class="pgx-legend">
        <div data-term="idp"><dt><a :href="withBase('/how-it-works/policy-storage')">Workspace</a></dt><dd>Your policy files on disk, versioned like code.</dd></div>
        <div data-term="cp"><dt><a :href="withBase('/how-it-works/glossary#control-plane')">Control Plane</a></dt><dd>Keeps every policy version, signs the one in force, and receives the decision logs and events.</dd></div>
        <div data-term="pdp"><dt><a :href="withBase('/how-it-works/glossary#pdp')">PDP</a></dt><dd>The Data Plane: decides with the version it verified.</dd></div>
      </dl>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The idea</div><h2>One place for everything.</h2></div><p>The Control Plane never decides anything. Rules go out from here; decisions and events come back here.</p></div>
    <div class="pgx-principles">
      <article><span>Organize</span><h3>Zones and ledgers.</h3><p>A <a :href="withBase('/how-it-works/glossary#zone')">zone</a> is a security boundary: a product, a team, a customer. A <a :href="withBase('/how-it-works/glossary#ledger')">ledger</a> holds one set of policies, the way a repository holds code.</p></article>
      <article><span>Policies</span><h3>Every version, signed.</h3><p>Publishing never overwrites: each version is kept as it was, and a <a :href="withBase('/how-it-works/glossary#signed-head')">signed head</a> names the one in force. A Data Plane checks that signature before it uses a single rule.</p></article>
      <article><span>Decision logs &amp; events</span><h3>Everything that happened.</h3><p>Every Data Plane sends its signed <a :href="withBase('/how-it-works/glossary#evidence')">decision records</a> back here, where they are verified and kept; events for history-based rules are stored here too. Read them, verify them, export them.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">In practice</div><h2>Change a rule, the way you change code.</h2></div><p>Three steps, from your laptop or a pipeline to every cluster.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="You apply a change from a workspace. The Control Plane validates it, stores it as a new version and signs it. Every Data Plane mirrors that exact version, verifies it, and decides with it.">
      <article><small>YOU · APPLY</small><strong>Publish a change</strong><span>from a workspace or a pipeline</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>CONTROL PLANE · SIGN</small><strong>Check, keep, sign</strong><span>a new version, never an overwrite</span></article><i>→</i>
      <article><small>DATA PLANES · MIRROR</small><strong>Verify, then decide</strong><span>with exactly that version</span></article>
    </div>
    <div class="vp-doc pgx-anatomy">
      <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>From a workspace</b><span>Connect it to the Control Plane once, pick the ledger, then apply each change with a message, as you would commit code.</span></div>

```bash
permguard remote add origin http://localhost:6443
permguard checkout origin/acme/main-ledger
permguard apply -m "readers may read documents"
```

</div>
    </div>
    <p class="pgx-anatomy__note">The whole round, from an empty folder to a first decision, is in <a :href="withBase('/how-it-works/getting-started')">Getting Started</a>.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">An analogy</div><h2>Think of a publisher's archive.</h2></div><p>Four things you already know, and what each one is here.</p></div>
    <div class="pgx-analogy" role="table" aria-label="A publisher's archive compared with the Control Plane">
      <div class="pgx-analogy__head" role="row"><span role="columnheader">At the publisher</span><span role="columnheader">What it does</span><span role="columnheader">In the Control Plane</span></div>
      <div role="row"><strong role="cell">The catalogue</strong><span role="cell">Which books exist, and on which shelf.</span><a role="cell" :href="withBase('/how-it-works/zones-and-ledgers')">Zones and ledgers</a></div>
      <div role="row"><strong role="cell">The archive</strong><span role="cell">Every edition ever printed, kept as it was.</span><a role="cell" :href="withBase('/how-it-works/policy-storage')">Every version, immutable</a></div>
      <div role="row"><strong role="cell">The seal</strong><span role="cell">Says which edition is the official one.</span><a role="cell" :href="withBase('/how-it-works/glossary#signed-head')">The signed head</a></div>
      <div role="row"><strong role="cell">The bookshops</strong><span role="cell">Receive the sealed edition, and check the seal before they sell it.</span><a role="cell" :href="withBase('/data-plane')">The Data Planes</a></div>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Why it matters</div><h2>Rules with a history and an owner.</h2></div><p>What each role gets from one place that publishes every rule.</p></div>
    <div class="pgx-principles">
      <article><span>Developers</span><h3>Policies ship like code.</h3><p>Write them in files, test them offline, plan and apply. No rule is hidden in a handler, and no deploy is needed to change one.</p></article>
      <article><span>Platform &amp; IT</span><h3>One source for every cluster.</h3><p>Every Data Plane, in every region, receives the same signed version. If the Control Plane is down, they keep deciding with what they already hold.</p></article>
      <article><span>Security &amp; CISO</span><h3>Know what was in force, always.</h3><p>Every version is kept and signed, and every decision names the exact version that made it. Show an auditor the rule that applied on any day.</p></article>
    </div>
  </section>

  <section class="pgx-section" id="faq">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Questions</div><h2>What people ask first.</h2></div><p>Straight answers.</p></div>
    <div class="pgx-faq">
      <details><summary>Does the Control Plane decide anything?</summary><p>No. It publishes policy and keeps the decision logs and events that come back. Decisions are made by the <a :href="withBase('/data-plane')">Data Plane</a>, with the version the Control Plane signed.</p></details>
      <details><summary>What happens if it is down?</summary><p>New versions wait until it is back. Every Data Plane keeps deciding with the version it already mirrored and verified.</p></details>
      <details><summary>Can a published version be changed?</summary><p>No. A change is always a new version; the old one stays as it was, so the history cannot be rewritten.</p></details>
      <details><summary>Which policy languages does it hold?</summary><p>Cedar and Rego, side by side in the same ledger. See <a :href="withBase('/how-it-works/policy-languages')">Policy as Code</a>.</p></details>
      <details><summary>Where does it run?</summary><p>On port <code>6443</code>, for HTTP and gRPC alike: in the all-in-one image beside the other planes, or on its own. See <a :href="withBase('/how-it-works/container-images')">Containers</a>.</p></details>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Go deeper</div><h2>The ideas behind it.</h2></div><p>Each one in plain words.</p></div>
    <div class="pgx-cards pgx-cards--2">
      <a class="pgx-card" :href="withBase('/how-it-works/zones-and-ledgers')"><span>Concept</span><h3>Zones &amp; Ledgers</h3><p>The boundaries your rules live in.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/policy-storage')"><span>Concept</span><h3>Git-like Versioning</h3><p>Why a version never changes.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/policy-lifecycle')"><span>Concept</span><h3>Policy Delivery</h3><p>From your workspace to every Data Plane.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/data-plane')"><span>Plane</span><h3>Data Plane</h3><p>Where the published version decides.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>
</main>
