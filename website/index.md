---
layout: page
pageClass: pg-page-home
title: Permguard Docs
description: The documentation of Permguard, authorization and trust for the agentic era.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { useData, withBase } from 'vitepress'

const { theme } = useData()
</script>

<div class="pg-home">
  <section class="pg-hero">
    <svg v-if="false" class="pg-mesh" viewBox="0 0 720 610" aria-hidden="true" focusable="false">
      <line class="pg-mesh__edge" x1="110" y1="130" x2="290" y2="70"/>
      <line class="pg-mesh__edge" x1="290" y1="70" x2="470" y2="150"/>
      <line class="pg-mesh__edge" x1="470" y1="150" x2="640" y2="90"/>
      <line class="pg-mesh__edge" x1="110" y1="130" x2="210" y2="310"/>
      <line class="pg-mesh__edge" x1="290" y1="70" x2="210" y2="310"/>
      <line class="pg-mesh__edge" x1="470" y1="150" x2="420" y2="330"/>
      <line class="pg-mesh__edge" x1="640" y1="90" x2="610" y2="300"/>
      <line class="pg-mesh__edge" x1="210" y1="310" x2="420" y2="330"/>
      <line class="pg-mesh__edge" x1="420" y1="330" x2="610" y2="300"/>
      <line class="pg-mesh__edge" x1="210" y1="310" x2="320" y2="510"/>
      <line class="pg-mesh__edge" x1="420" y1="330" x2="320" y2="510"/>
      <line class="pg-mesh__edge" x1="420" y1="330" x2="540" y2="490"/>
      <line class="pg-mesh__edge" x1="610" y1="300" x2="540" y2="490"/>
      <line class="pg-mesh__edge" x1="320" y1="510" x2="540" y2="490"/>
      <rect class="pg-mesh__anchor" x="105" y="125" width="10" height="10" transform="rotate(45 110 130)"/>
      <circle class="pg-mesh__point" cx="290" cy="70" r="3"/>
      <rect class="pg-mesh__anchor" x="465" y="145" width="10" height="10" transform="rotate(45 470 150)"/>
      <circle class="pg-mesh__point" cx="640" cy="90" r="3"/>
      <circle class="pg-mesh__point" cx="210" cy="310" r="3"/>
      <rect class="pg-mesh__anchor" x="415" y="325" width="10" height="10" transform="rotate(45 420 330)"/>
      <circle class="pg-mesh__point" cx="610" cy="300" r="3"/>
      <circle class="pg-mesh__point" cx="320" cy="510" r="3"/>
      <rect class="pg-mesh__anchor" x="535" y="485" width="10" height="10" transform="rotate(45 540 490)"/>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M110 130 L290 70" dur="7s" begin="0.0s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="0.0s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="290" cy="70" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="0.0s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="0.0s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M470 150 L420 330" dur="7s" begin="1.4s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="1.4s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="420" cy="330" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="1.4s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="1.4s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M210 310 L320 510" dur="7s" begin="2.8s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="2.8s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="320" cy="510" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="2.8s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="2.8s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M610 300 L540 490" dur="7s" begin="4.2s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="4.2s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="540" cy="490" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="4.2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="4.2s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M290 70 L470 150" dur="7s" begin="5.6s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="5.6s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="470" cy="150" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="5.6s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="5.6s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M420 330 L610 300" dur="7s" begin="0.7s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="0.7s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="610" cy="300" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="0.7s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="0.7s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__policy" r="3"><animateMotion path="M640 90 L610 300" dur="7s" begin="3.5s" repeatCount="indefinite" keyPoints="0;1;1" keyTimes="0;0.4;1" calcMode="linear"/><animate attributeName="opacity" values="0;1;1;0;0" keyTimes="0;0.05;0.36;0.42;1" dur="7s" begin="3.5s" repeatCount="indefinite"/></circle>
      <circle class="pg-mesh__decision" cx="610" cy="300" r="4"><animate attributeName="r" values="4;4;5;16;16" keyTimes="0;0.4;0.42;0.62;1" dur="7s" begin="3.5s" repeatCount="indefinite"/><animate attributeName="opacity" values="0;0;.75;0;0" keyTimes="0;0.4;0.43;0.62;1" dur="7s" begin="3.5s" repeatCount="indefinite"/></circle>
    </svg>
    <svg class="pg-auth-network" viewBox="0 0 720 520" aria-hidden="true" focusable="false">
      <circle class="pg-auth-network__orbit" cx="360" cy="260" r="218"/>
      <path class="pg-auth-network__perimeter" d="M120 118 L360 58 L600 118 L612 392 L360 462 L108 392 Z"/>
      <g class="pg-auth-network__links">
        <path d="M360 260 L120 118"/>
        <path d="M360 260 L360 58"/>
        <path d="M360 260 L600 118"/>
        <path d="M360 260 L612 392"/>
        <path d="M360 260 L108 392"/>
      </g>
      <g class="pg-auth-network__node pg-auth-network__node--agent" transform="translate(120 118)">
        <g class="pg-auth-network__node-float" style="--node-phase: 0s">
          <circle r="25"/>
          <g class="pg-auth-network__icon">
            <path d="M-10 -7 H10 V9 H-10 Z M-4 -11 V-7 M-7 5 H7"/>
            <circle class="pg-auth-network__icon-dot" cx="-4" cy="0" r="1.5"/>
            <circle class="pg-auth-network__icon-dot" cx="4" cy="0" r="1.5"/>
          </g>
          <text y="44">Customer</text><text class="pg-auth-network__role" y="57">AI Agent</text>
        </g>
      </g>
      <g class="pg-auth-network__node pg-auth-network__node--agent" transform="translate(360 58)">
        <g class="pg-auth-network__node-float" style="--node-phase: -0.8s">
          <circle r="25"/>
          <g class="pg-auth-network__icon">
            <path d="M-10 -7 H10 V9 H-10 Z M-4 -11 V-7 M-7 5 H7"/>
            <circle class="pg-auth-network__icon-dot" cx="-4" cy="0" r="1.5"/>
            <circle class="pg-auth-network__icon-dot" cx="4" cy="0" r="1.5"/>
          </g>
          <text y="44">Planner</text><text class="pg-auth-network__role" y="57">AI Agent</text>
        </g>
      </g>
      <g class="pg-auth-network__node pg-auth-network__node--workload" transform="translate(600 118)">
        <g class="pg-auth-network__node-float" style="--node-phase: -1.6s">
          <circle r="25"/>
          <g class="pg-auth-network__icon">
            <rect x="-11" y="-10" width="22" height="8"/><rect x="-11" y="2" width="22" height="8"/>
            <circle class="pg-auth-network__icon-dot" cx="-7" cy="-6" r="1.4"/><circle class="pg-auth-network__icon-dot" cx="-7" cy="6" r="1.4"/>
            <path d="M-2 -6 H7 M-2 6 H7"/>
          </g>
          <text y="44">Products</text><text class="pg-auth-network__role" y="57">API</text>
        </g>
      </g>
      <g class="pg-auth-network__node pg-auth-network__node--workload" transform="translate(612 392)">
        <g class="pg-auth-network__node-float" style="--node-phase: -2.4s">
          <circle r="25"/>
          <g class="pg-auth-network__icon">
            <rect x="-11" y="-10" width="22" height="8"/><rect x="-11" y="2" width="22" height="8"/>
            <circle class="pg-auth-network__icon-dot" cx="-7" cy="-6" r="1.4"/><circle class="pg-auth-network__icon-dot" cx="-7" cy="6" r="1.4"/>
            <path d="M-2 -6 H7 M-2 6 H7"/>
          </g>
          <text y="44">Orders</text><text class="pg-auth-network__role" y="57">Worker</text>
        </g>
      </g>
      <g class="pg-auth-network__node pg-auth-network__node--workload" transform="translate(108 392)">
        <g class="pg-auth-network__node-float" style="--node-phase: -3.2s">
          <circle r="25"/>
          <g class="pg-auth-network__icon">
            <rect x="-11" y="-10" width="22" height="8"/><rect x="-11" y="2" width="22" height="8"/>
            <circle class="pg-auth-network__icon-dot" cx="-7" cy="-6" r="1.4"/><circle class="pg-auth-network__icon-dot" cx="-7" cy="6" r="1.4"/>
            <path d="M-2 -6 H7 M-2 6 H7"/>
          </g>
          <text y="44">Inventory</text><text class="pg-auth-network__role" y="57">Worker</text>
        </g>
      </g>
      <g class="pg-auth-network__signals">
        <circle class="pg-auth-network__signal" r="6">
          <animateMotion dur="10s" repeatCount="indefinite" path="M120 118 L360 260 L360 58 L360 260 L600 118 L360 260 L612 392 L360 260 L108 392 L360 260 L120 118"/>
        </circle>
      </g>
    </svg>
    <div class="pg-hero__copy">
      <div class="pg-kicker">Documentation · {{ theme.docsVersion === 'latest' ? 'latest' : `version ${theme.docsVersion}` }}</div>
      <h1>The security overlay, <span class="pg-hero__accent">documented.</span></h1>
      <p>This is the documentation of <a href="https://permguard.com" target="_blank" rel="noopener noreferrer">Permguard</a>, authorization and trust for the agentic era. Start from the model, then install the CLI and run each plane.</p>
      <div class="pg-actions">
        <a class="pg-btn pg-btn--primary" :href="withBase('/how-it-works')">Read the docs</a>
        <a class="pg-btn pg-btn--ghost" href="https://github.com/permguard/permguard" target="_blank" rel="noopener noreferrer">View on GitHub</a>
      </div>
    </div>
    <div class="pg-hero__brand">
      <a class="pg-hero__core" :href="withBase('/how-it-works')" aria-label="Open the Permguard documentation">
        <img class="pg-logo" :src="withBase('/permguard/symbol.svg')" alt="">
      </a>
      <span class="pg-hero__brand-label">Permguard network</span>
    </div>
  </section>
  <section class="pg-docs">
    <div class="pg-section-inner">
      <div class="pg-section-head">
        <div class="pg-kicker">Start here</div>
        <h2>The documentation</h2>
      </div>
      <div class="pg-docs-grid">
        <a class="pg-doc" :href="withBase('/how-it-works')"><h3>How it works</h3><p>The concepts behind Permguard.</p><span aria-hidden="true">→</span></a>
        <a class="pg-doc" :href="withBase('/how-it-works/install')"><h3>Install</h3><p>CLI, native packages and verified releases.</p><span aria-hidden="true">→</span></a>
        <a class="pg-doc" :href="withBase('/command-line')"><h3>Command Line</h3><p>Integrate and manage Permguard from your terminal.</p><span aria-hidden="true">→</span></a>
        <a class="pg-doc" :href="withBase('/control-plane')"><h3>Control Plane</h3><p>Publish and distribute immutable policy history.</p><span aria-hidden="true">→</span></a>
        <a class="pg-doc" :href="withBase('/data-plane')"><h3>Data Plane</h3><p>Decide embedded, as a sidecar, remotely or at your own edge.</p><span aria-hidden="true">→</span></a>
        <a class="pg-doc" :href="withBase('/trust-plane')"><h3>Trust Plane</h3><p>Authority continuity, clearly marked in development.</p><span aria-hidden="true">→</span></a>
      </div>
    </div>
  </section>
  <section class="pg-product">
    <div class="pg-section-inner pg-product__inner">
      <div>
        <div class="pg-kicker">Permguard</div>
        <h2>Looking for the product?</h2>
        <p>Products, support, pricing and partners live on the Permguard website.</p>
      </div>
      <a class="pg-btn pg-btn--primary" href="https://permguard.com" target="_blank" rel="noopener noreferrer">Visit permguard.com</a>
    </div>
  </section>
</div>
