---
layout: page
pageClass: pg-page-concepts
title: Trust Plane
description: "Next on the roadmap: Authority Continuity with formal proof, along a chain of executions, with PIC-X."
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { withBase } from 'vitepress'
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">Trust Plane · next on the roadmap</div>
    <h1>Authority Continuity with formal proof.</h1>
    <p>When an AI agent hands work to a tool, and the tool to a service, the authority the chain started with carries on at every step and, within the protocol itself, never grows. The model behind it is peer-reviewed and its theorems are machine-checked.</p>
    <p class="pgx-hero__status"><em class="pgx-status pgx-status--next">Not served today</em></p>
    <div class="pgx-hero-visual">
      <div class="pgx-hero-visual__art" role="img" aria-label="A chain of executions. alice grants authority to read and comment on the budget. Her AI agent carries the same authority or less; the tool it calls carries the same as the agent or less. A hop that adds authority, deleting the budget, is invalid within the protocol and the next hop does not accept it. Underneath, the Trust Plane with PIC-X, next on the roadmap, checks every hop.">
        <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 330" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-tp-wide-flow" gradientUnits="userSpaceOnUse" x1="220" y1="0" x2="760" y2="0"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-tp-wide-flow)" d="M230 110 H290"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-tp-wide-flow)" d="M500 110 H560"/>
            <path class="pgx-hv__flow pgx-hv__flow--invalid" d="M770 110 H820"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M125 180 V230"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M395 180 V230"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M665 180 V230"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="20" y="40" width="210" height="140" rx="14"/>
            <text class="pgx-hv__k" x="125" y="68" text-anchor="middle">ORIGIN · ALICE</text>
            <rect class="pgx-hv__pod" x="40" y="84" width="170" height="28" rx="8"/><text class="pgx-hv__p" x="125" y="103" text-anchor="middle">read the budget</text>
            <rect class="pgx-hv__pod" x="40" y="120" width="170" height="28" rx="8"/><text class="pgx-hv__p" x="125" y="139" text-anchor="middle">comment on it</text>
            <text class="pgx-hv__m" x="125" y="168" text-anchor="middle">the authority granted</text>
          </g>
          <g class="pgx-hv__node">
            <rect x="290" y="40" width="210" height="140" rx="14"/>
            <text class="pgx-hv__k" x="395" y="68" text-anchor="middle">HOP 1 · HER AGENT</text>
            <rect class="pgx-hv__pod" x="310" y="84" width="170" height="28" rx="8"/><text class="pgx-hv__p" x="395" y="103" text-anchor="middle">read the budget</text>
            <rect class="pgx-hv__pod" x="310" y="120" width="170" height="28" rx="8"/><text class="pgx-hv__p" x="395" y="139" text-anchor="middle">comment on it</text>
            <text class="pgx-hv__m" x="395" y="168" text-anchor="middle">the same, or less</text>
          </g>
          <g class="pgx-hv__node">
            <rect x="560" y="40" width="210" height="140" rx="14"/>
            <text class="pgx-hv__k" x="665" y="68" text-anchor="middle">HOP 2 · A TOOL</text>
            <rect class="pgx-hv__pod" x="580" y="84" width="170" height="28" rx="8"/><text class="pgx-hv__p" x="665" y="103" text-anchor="middle">read the budget</text>
            <text class="pgx-hv__m" x="665" y="168" text-anchor="middle">less: never more</text>
          </g>
          <g class="pgx-hv__invalid">
            <rect x="820" y="40" width="200" height="140" rx="14"/>
            <text class="pgx-hv__k" x="920" y="68" text-anchor="middle">A HOP THAT WIDENS</text>
            <text class="pgx-hv__p" x="920" y="104" text-anchor="middle">+ delete the budget</text>
            <text class="pgx-hv__m" x="920" y="140" text-anchor="middle">invalid within</text>
            <text class="pgx-hv__m" x="920" y="158" text-anchor="middle">the protocol</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="20" y="230" width="750" height="70" rx="16"/>
            <text class="pgx-hv__k" x="395" y="258" text-anchor="middle">TRUST PLANE · PIC-X · NEXT</text>
            <text class="pgx-hv__s" x="395" y="282" text-anchor="middle">checks that every hop carries the origin's authority, or less</text>
          </g>
        </svg>
        <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 700" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-tp-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="140" x2="0" y2="420"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-tp-compact-flow)" d="M180 136 V160"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-tp-compact-flow)" d="M180 282 V306"/>
            <path class="pgx-hv__flow pgx-hv__flow--invalid" d="M180 394 V418"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="16" y="14" width="328" height="122" rx="14"/>
            <text class="pgx-hv__k" x="180" y="40" text-anchor="middle">ORIGIN · ALICE</text>
            <rect class="pgx-hv__pod" x="36" y="54" width="288" height="30" rx="8"/><text class="pgx-hv__p" x="180" y="74" text-anchor="middle">read the budget</text>
            <rect class="pgx-hv__pod" x="36" y="92" width="288" height="30" rx="8"/><text class="pgx-hv__p" x="180" y="112" text-anchor="middle">comment on it</text>
          </g>
          <g class="pgx-hv__node">
            <rect x="16" y="160" width="328" height="122" rx="14"/>
            <text class="pgx-hv__k" x="180" y="186" text-anchor="middle">HOP 1 · HER AGENT · SAME OR LESS</text>
            <rect class="pgx-hv__pod" x="36" y="200" width="288" height="30" rx="8"/><text class="pgx-hv__p" x="180" y="220" text-anchor="middle">read the budget</text>
            <rect class="pgx-hv__pod" x="36" y="238" width="288" height="30" rx="8"/><text class="pgx-hv__p" x="180" y="258" text-anchor="middle">comment on it</text>
          </g>
          <g class="pgx-hv__node">
            <rect x="16" y="306" width="328" height="88" rx="14"/>
            <text class="pgx-hv__k" x="180" y="332" text-anchor="middle">HOP 2 · A TOOL · LESS</text>
            <rect class="pgx-hv__pod" x="36" y="346" width="288" height="30" rx="8"/><text class="pgx-hv__p" x="180" y="366" text-anchor="middle">read the budget</text>
          </g>
          <g class="pgx-hv__invalid">
            <rect x="16" y="418" width="328" height="104" rx="14"/>
            <text class="pgx-hv__k" x="180" y="446" text-anchor="middle">A HOP THAT WIDENS</text>
            <text class="pgx-hv__p" x="180" y="476" text-anchor="middle">+ delete the budget</text>
            <text class="pgx-hv__m" x="180" y="504" text-anchor="middle">invalid within the protocol</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="16" y="560" width="328" height="110" rx="16"/>
            <text class="pgx-hv__k" x="180" y="592" text-anchor="middle">TRUST PLANE · PIC-X · NEXT</text>
            <text class="pgx-hv__s" x="180" y="620" text-anchor="middle">checks every hop:</text>
            <text class="pgx-hv__s" x="180" y="644" text-anchor="middle">the origin's authority, or less</text>
          </g>
        </svg>
      </div>
      <dl class="pgx-legend">
        <div data-term="idp"><dt>The origin</dt><dd>Whoever started the chain, and the authority they granted.</dd></div>
        <div data-term="cp"><dt><a :href="withBase('/how-it-works/glossary#trust-plane')">Trust Plane</a></dt><dd>Next on the roadmap: checks every hop with PIC-X.</dd></div>
      </dl>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The idea</div><h2>Authority carries on, and never grows.</h2></div><p>Today Permguard answers whether one action may happen. The Trust Plane will answer whether a whole chain of actions still holds.</p></div>
    <div class="pgx-principles">
      <article><span>Origin</span><h3>Every chain starts somewhere.</h3><p>A person or a system grants some authority: read the budget, comment on it. That grant is the origin.</p></article>
      <article><span>Continuity</span><h3>Each hop, the same or less.</h3><p>An agent, the tool it calls, the service behind it: each carries the authority of the hop before it, or a part of it, never more.</p></article>
      <article><span>Checked</span><h3>A hop that widens is invalid.</h3><p>Within the protocol itself, a hop that adds authority, or skips a check it was bound to pass, is invalid, and the next hop does not accept it.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Today and next</div><h2>What ships, and what comes.</h2></div><p>Nothing on this page is an interface to build on until it ships.</p></div>
    <div class="pgx-cards pgx-cards--2">
      <article class="pgx-card"><span>Available today</span><h3>May this action happen?</h3><p>The <a :href="withBase('/data-plane')">Data Plane</a> answers permit or deny for one request, with a signed policy version.</p></article>
      <article class="pgx-card"><span>Available today</span><h3>What decided, under which policy?</h3><p>Every answer leaves a signed record chained to the one before. See <a :href="withBase('/how-it-works/evidence')">Verifiable Evidence</a>.</p></article>
      <article class="pgx-card pgx-card--accent"><span>Next · Data Plane</span><h3>May this hand-off cross the boundary?</h3><p>A Trust Anchor: a policy engine for PIC-like protocols, with interfaces of its own, beside the PDP.</p></article>
      <article class="pgx-card pgx-card--accent"><span>Next · Trust Plane</span><h3>Does authority hold along the chain?</h3><p>Authority continuity from the origin to the last hop, with <a href="https://pic-protocol.org/pic-x">PIC-X</a>, on a plane of its own.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Why it matters</div><h2>Agents act for someone.</h2></div><p>When software acts on a person's behalf, what it may do should come from that person, and stop there.</p></div>
    <div class="pgx-principles">
      <article><span>Developers</span><h3>Hand work on safely.</h3><p>An agent or a tool receives only the authority it was given, and passes on only part of it.</p></article>
      <article><span>Platform &amp; IT</span><h3>One rule across systems.</h3><p>The same continuity, checked at every hop, whichever service, cluster or vendor runs it.</p></article>
      <article><span>Security &amp; CISO</span><h3>No silent escalation.</h3><p>A step that grants itself more than it received is refused by the protocol, not discovered later in a log.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint" id="faq">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Questions</div><h2>What people ask first.</h2></div><p>Straight answers.</p></div>
    <div class="pgx-faq">
      <details><summary>Can I use the Trust Plane today?</summary><p>No. It is next on the roadmap: it has no port and no API yet, and no Server advertises it.</p></details>
      <details><summary>Is the signed evidence not enough?</summary><p>Evidence proves what was decided, in which order and under which policy. It cannot say whether the authority a step used came, unexpanded, from where the chain began: that is continuity.</p></details>
      <details><summary>What is PIC-X?</summary><p>The open-source trust-plane component of PIC, which turns the possession of a token into verifiable authority continuity. See <a href="https://pic-protocol.org/pic-x">pic-protocol.org</a>.</p></details>
      <details><summary>Is a Trust Anchor the same thing?</summary><p>No. A Trust Anchor answers for one hand-off at one boundary, in the Data Plane. The Trust Plane keeps authority continuous along the whole chain.</p></details>
      <details><summary>Is it really proven?</summary><p>Yes, as a model. Authority Continuity comes from PIC, Provenance Identity Continuity, published at IEEE NCA 2026 (preprint on <a href="https://arxiv.org/abs/2607.08906">arXiv</a>). Its definitions and theorems are machine-checked in Lean 4: within a valid chain, a step cannot carry authority the origin did not grant.</p></details>
      <details><summary>Can any protocol promise this absolutely?</summary><p>Within the protocol itself, yes: a hop that widens its authority is invalid. Outside it, on a compromised machine for instance, no protocol can promise anything absolute.</p></details>
      <details><summary>What exists today that it builds on?</summary><p>Host identities and keys, signed policy versions, signed decision records, and the <a :href="withBase('/authority-plane')">Authority Plane</a>'s scoped tokens, which narrow an account's scopes and never widen them.</p></details>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Go deeper</div><h2>The ideas around it.</h2></div><p>Each one in plain words.</p></div>
    <div class="pgx-cards pgx-cards--2">
      <a class="pgx-card" href="https://pic-protocol.org/pic-x"><span>External</span><h3>PIC-X</h3><p>The trust-plane component of PIC.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/evidence')"><span>Concept</span><h3>Verifiable Evidence</h3><p>Traceability, available today.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/glossary#trust-anchor')"><span>Reference</span><h3>Glossary</h3><p>Trust Anchor, Trust Plane, PDP.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/authority-plane')"><span>Plane</span><h3>Authority Plane</h3><p>Who may call Permguard, today.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>
</main>
