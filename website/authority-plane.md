---
layout: page
pageClass: pg-page-concepts
title: Authority Plane
description: Who may call Permguard. Every program that talks to Permguard has its own identity, and its short-lived token is checked by every plane on its own.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">Authority Plane · :8443</div>
    <h1>Who may call Permguard.</h1>
    <p>Every program, pipeline and tool that talks to Permguard has its own identity. It trades its key for a short-lived token, and every plane checks that token on its own.</p>
    <div class="pgx-hero-visual">
      <div class="pgx-hero-visual__art" role="img" aria-label="A caller, such as the command line, a pipeline, Permguard Admin or your own service, presents its access key to the Authority Plane on port 8443, which knows its identity and scopes and returns a short-lived access token. The caller presents that token to the Host, the Control Plane and the Data Plane, each of which checks it itself, offline, with the keys and revocation lists the Authority Plane publishes.">
        <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 380" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-ap-wide-flow" gradientUnits="userSpaceOnUse" x1="220" y1="0" x2="790" y2="0"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M230 150 H360"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-ap-wide-flow)" d="M360 200 H230"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-ap-wide-flow)" d="M125 236 V344 H905 V330"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M680 130 H790"/>
          </g>
          <text class="pgx-hv__m" x="295" y="140" text-anchor="middle">1 · access key</text>
          <text class="pgx-hv__m" x="295" y="222" text-anchor="middle">2 · token</text>
          <text class="pgx-hv__m" x="520" y="366" text-anchor="middle">3 · every call carries the token</text>
          <text class="pgx-hv__m" x="735" y="120" text-anchor="middle">keys · revocations</text>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="20" y="110" width="210" height="126" rx="14"/>
            <text class="pgx-hv__k" x="125" y="136" text-anchor="middle">A CALLER</text>
            <text class="pgx-hv__p" x="125" y="162" text-anchor="middle">the command line</text>
            <text class="pgx-hv__p" x="125" y="184" text-anchor="middle">a CI pipeline</text>
            <text class="pgx-hv__p" x="125" y="206" text-anchor="middle">Permguard Admin</text>
            <text class="pgx-hv__p" x="125" y="228" text-anchor="middle">your own service</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="360" y="30" width="320" height="250" rx="18"/>
            <text class="pgx-hv__k" x="520" y="62" text-anchor="middle">AUTHORITY PLANE · :8443</text>
            <rect class="pgx-hv__pod" x="388" y="82" width="264" height="52" rx="10"/>
            <text class="pgx-hv__p" x="406" y="104">Identities</text>
            <text class="pgx-hv__m" x="406" y="123">one per program, never shared</text>
            <rect class="pgx-hv__pod" x="388" y="144" width="264" height="52" rx="10"/>
            <text class="pgx-hv__p" x="406" y="166">Scopes</text>
            <text class="pgx-hv__m" x="406" y="185">what each may do, and where</text>
            <rect class="pgx-hv__pdp" x="388" y="206" width="264" height="56" rx="10"/>
            <text class="pgx-hv__d" x="406" y="230">SHORT-LIVED TOKENS</text>
            <text class="pgx-hv__m" x="406" y="249">revocable at any moment</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="790" y="40" width="230" height="290" rx="16"/>
            <text class="pgx-hv__m" x="806" y="64">each checks the token itself</text>
            <rect class="pgx-hv__pod" x="806" y="88" width="198" height="64" rx="10"/>
            <text class="pgx-hv__p" x="822" y="114">Host</text><text class="pgx-hv__m" x="822" y="136">:5443 · :5444</text>
            <rect class="pgx-hv__pod" x="806" y="164" width="198" height="64" rx="10"/>
            <text class="pgx-hv__p" x="822" y="190">Control Plane</text><text class="pgx-hv__m" x="822" y="212">:6443</text>
            <rect class="pgx-hv__pdp" x="806" y="240" width="198" height="64" rx="10"/>
            <text class="pgx-hv__p" x="822" y="266">Data Plane</text><text class="pgx-hv__m" x="822" y="288">:7443</text>
          </g>
        </svg>
        <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 690" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-ap-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="140" x2="0" y2="450"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M140 140 V180"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-ap-compact-flow)" d="M220 180 V140"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 420 V452"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="16" y="14" width="328" height="126" rx="14"/>
            <text class="pgx-hv__k" x="180" y="40" text-anchor="middle">A CALLER</text>
            <text class="pgx-hv__p" x="180" y="66" text-anchor="middle">the command line · a pipeline</text>
            <text class="pgx-hv__p" x="180" y="90" text-anchor="middle">Permguard Admin</text>
            <text class="pgx-hv__p" x="180" y="114" text-anchor="middle">your own service</text>
          </g>
          <text class="pgx-hv__m" x="132" y="166" text-anchor="end">key</text>
          <text class="pgx-hv__m" x="228" y="166">token</text>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="16" y="180" width="328" height="240" rx="18"/>
            <text class="pgx-hv__k" x="180" y="210" text-anchor="middle">AUTHORITY PLANE · :8443</text>
            <rect class="pgx-hv__pod" x="36" y="228" width="288" height="52" rx="10"/>
            <text class="pgx-hv__p" x="54" y="250">Identities</text>
            <text class="pgx-hv__m" x="54" y="270">one per program</text>
            <rect class="pgx-hv__pod" x="36" y="290" width="288" height="52" rx="10"/>
            <text class="pgx-hv__p" x="54" y="312">Scopes</text>
            <text class="pgx-hv__m" x="54" y="332">what each may do</text>
            <rect class="pgx-hv__pdp" x="36" y="352" width="288" height="52" rx="10"/>
            <text class="pgx-hv__d" x="54" y="374">SHORT-LIVED TOKENS</text>
            <text class="pgx-hv__m" x="54" y="394">revocable</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="16" y="452" width="328" height="214" rx="16"/>
            <text class="pgx-hv__m" x="32" y="478">each checks the token itself</text>
            <rect class="pgx-hv__pod" x="32" y="494" width="296" height="44" rx="10"/><text class="pgx-hv__p" x="48" y="521">Host · :5443 · :5444</text>
            <rect class="pgx-hv__pod" x="32" y="548" width="296" height="44" rx="10"/><text class="pgx-hv__p" x="48" y="575">Control Plane · :6443</text>
            <rect class="pgx-hv__pdp" x="32" y="602" width="296" height="44" rx="10"/><text class="pgx-hv__p" x="48" y="629">Data Plane · :7443</text>
          </g>
        </svg>
      </div>
      <dl class="pgx-legend">
        <div data-term="idp"><dt>A caller</dt><dd>Any program that talks to Permguard itself, Permguard's own tools included.</dd></div>
        <div data-term="cp"><dt><a :href="withBase('/how-it-works/glossary#authority-plane')">Authority Plane</a></dt><dd>Knows each identity and what it may do, and issues its tokens.</dd></div>
        <div data-term="pdp"><dt>Every plane</dt><dd>Checks the token itself, without asking the Authority Plane each time.</dd></div>
      </dl>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The idea</div><h2>A badge for every program.</h2></div><p>Your users keep signing in with your Identity Provider. The Authority Plane is for the programs that talk to Permguard itself.</p></div>
    <div class="pgx-principles">
      <article><span>Identify</span><h3>One identity each.</h3><p>The command line, a pipeline, Permguard Admin, your own service: each one has its own identity, never a shared password.</p></article>
      <article><span>Limit</span><h3>Only what it needs.</h3><p>An identity's scopes say what it may do and where: publish to one ledger, read decisions of another, nothing more.</p></article>
      <article><span>Check</span><h3>Everywhere, on its own.</h3><p>Each one trades its key for a short-lived token. The Host and every plane check it themselves, so no call waits for the Authority Plane.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">In practice</div><h2>A key in, a token out.</h2></div><p>Three steps, every time a program talks to Permguard.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="A caller presents its access key to the Authority Plane, receives a short-lived access token carrying its scopes, and presents that token on every call; each plane checks it.">
      <article><small>CALLER · KEY</small><strong>Present the access key</strong><span>an access key and its secret</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>AUTHORITY PLANE · ISSUE</small><strong>A short-lived token</strong><span>carrying the caller's scopes</span></article><i>→</i>
      <article><small>EVERY PLANE · CHECK</small><strong>Allow what the scopes allow</strong><span>and nothing else</span></article>
    </div>
    <div class="vp-doc pgx-anatomy">
      <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>From the command line</b><span>Tell it where the Authority Plane is, the caller's access key, and a file holding its secret key, readable by you alone: it obtains its token, and renews it, by itself.</span></div>

```bash
permguard --authority-endpoint https://localhost:8443 \
  --access-key <access-key> --secret-key-file secret.key \
  zones list
```

</div>
    </div>
    <p class="pgx-anatomy__note">On its first start the Authority Plane creates the identity <code>admin</code> and writes its access key and secret key, readable by their owner alone, to <code>planes/authority/admin.key</code> on the volume: move it somewhere safe.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">An analogy</div><h2>Think of visitor badges.</h2></div><p>Four things you already know, and what each one is here.</p></div>
    <div class="pgx-analogy" role="table" aria-label="Visitor badges compared with the Authority Plane">
      <div class="pgx-analogy__head" role="row"><span role="columnheader">In the building</span><span role="columnheader">What it does</span><span role="columnheader">In the Authority Plane</span></div>
      <div role="row"><strong role="cell">The contractor</strong><span role="cell">Comes in to do a job, and is known by name.</span><span role="cell">An identity</span></div>
      <div role="row"><strong role="cell">The work order</strong><span role="cell">Which rooms they may enter, and what they may do there.</span><span role="cell">Its scopes</span></div>
      <div role="row"><strong role="cell">The day badge</strong><span role="cell">Shows the work order at every door, and expires tonight.</span><span role="cell">A short-lived token</span></div>
      <div role="row"><strong role="cell">Every door</strong><span role="cell">Reads the badge itself, without phoning reception.</span><span role="cell">Every plane checks the token</span></div>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Why it matters</div><h2>Least privilege, for machines too.</h2></div><p>What each role gets from one authority for every caller.</p></div>
    <div class="pgx-principles">
      <article><span>Developers</span><h3>A key, and nothing else.</h3><p>The command line obtains and renews its token by itself, from a key you keep in a file. No credential lives in a script.</p></article>
      <article><span>Platform &amp; IT</span><h3>One authority per cluster.</h3><p>Every plane checks tokens on its own, with keys the Authority Plane publishes: no extra hop on any call.</p></article>
      <article><span>Security &amp; CISO</span><h3>Every call, attributable.</h3><p>Each caller has its own identity and narrow scopes. Revoke a token, suspend an identity or delete a key, and every plane refuses it at its next refresh.</p></article>
    </div>
  </section>

  <section class="pgx-section" id="faq">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Questions</div><h2>What people ask first.</h2></div><p>Straight answers.</p></div>
    <div class="pgx-faq">
      <details><summary>Does it replace my Identity Provider?</summary><p>No. Your users keep signing in where they do today. The Authority Plane governs the programs that call Permguard itself.</p></details>
      <details><summary>Does it decide what my users may do?</summary><p>No. That is the <a :href="withBase('/data-plane')">Data Plane</a>, with your policies. The Authority Plane only says who may call Permguard, and to do what.</p></details>
      <details><summary>How long does a token last?</summary><p>A short time, by design: it is renewed with the key. A token is an access token in the standard JSON Web Token format for OAuth 2.0 (RFC 9068).</p></details>
      <details><summary>How fast does a revocation reach every plane?</summary><p>At each plane's next refresh of the revocation lists the Authority Plane publishes.</p></details>
      <details><summary>Do I need it to get started?</summary><p>No. The development configurations let anyone call, so the first steps need no credential. Production declares no such grant: every caller has a token.</p></details>
      <details><summary>Where does it run?</summary><p>On port <code>8443</code>, one per cluster: in the all-in-one image beside the other planes, or on its own. See <a :href="withBase('/how-it-works/container-images')">Containers</a>.</p></details>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Go deeper</div><h2>The ideas behind it.</h2></div><p>Each one in plain words.</p></div>
    <div class="pgx-cards pgx-cards--2">
      <a class="pgx-card" :href="withBase('/how-it-works/architecture')"><span>Concept</span><h3>Server, Host &amp; Planes</h3><p>Where the Authority Plane sits.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/glossary#authority-plane')"><span>Reference</span><h3>Glossary</h3><p>Identity, scope, token, in one line each.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/control-plane')"><span>Plane</span><h3>Control Plane</h3><p>Checks the token of whoever publishes.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/data-plane')"><span>Plane</span><h3>Data Plane</h3><p>Checks the token of whoever asks.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>
</main>
