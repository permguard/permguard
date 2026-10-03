<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { withBase } from 'vitepress'

const year = new Date().getFullYear()
</script>

<!-- The site footer, shared by every page through the theme layout. -->
<template>
  <footer class="pg-footer">
    <div class="pg-section-inner">
      <div class="pg-footer__main">
        <div class="pg-footer__brand">
          <a class="pg-footer__logo" href="https://permguard.com/" target="_blank" rel="noopener noreferrer" aria-label="Permguard website">
            <img :src="withBase('/permguard/nav-wordmark-white.svg')" alt="Permguard" width="170" height="44">
          </a>

          <a class="pg-footer__email" href="mailto:opensource@permguard.com">
            <svg aria-hidden="true" viewBox="0 0 20 20">
              <path d="M3 4a2 2 0 0 0-2 2v1.161l8.441 4.221a1.25 1.25 0 0 0 1.118 0L19 7.162V6a2 2 0 0 0-2-2H3Z" />
              <path d="m19 8.839-7.77 3.885a2.75 2.75 0 0 1-2.46 0L1 8.839V14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V8.839Z" />
            </svg>
            <span>opensource@permguard.com</span>
          </a>

          <div class="pg-footer__social" aria-label="Permguard social links">
            <a href="https://www.permguard.com/" target="_blank" rel="noopener noreferrer" aria-label="Permguard website">
              <svg class="pg-footer__icon--outline" aria-hidden="true" viewBox="2 2 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="9" />
                <path d="M3 12h18M12 3c2.25 2.47 3.4 5.47 3.4 9S14.25 18.53 12 21c-2.25-2.47-3.4-5.47-3.4-9S9.75 5.47 12 3Z" />
              </svg>
            </a>
            <a href="https://x.com/permguard" target="_blank" rel="noopener noreferrer" aria-label="Permguard on X">
              <svg aria-hidden="true" viewBox="0 0 16 16"><path d="M12.6.75h2.454l-5.36 6.142L16 15.25h-4.937l-3.867-5.07-4.425 5.07H.316l5.733-6.57L0 .75h5.063l3.495 4.633L12.601.75Zm-.86 13.028h1.36L4.323 2.145H2.865z" /></svg>
            </a>
            <a href="https://www.linkedin.com/showcase/permguard/" target="_blank" rel="noopener noreferrer" aria-label="Permguard on LinkedIn">
              <svg aria-hidden="true" viewBox="0 0 16 16"><path d="M0 1.146C0 .513.526 0 1.175 0h13.65C15.474 0 16 .513 16 1.146v13.708C16 15.487 15.474 16 14.825 16H1.175C.526 16 0 15.487 0 14.854V1.146Zm4.943 12.248V6.169H2.542v7.225h2.401ZM3.743 5.182c.837 0 1.358-.554 1.358-1.248-.015-.709-.52-1.248-1.342-1.248S2.4 3.226 2.4 3.934c0 .694.521 1.248 1.327 1.248h.016Zm4.908 8.212V9.359c0-.216.016-.432.08-.586.173-.431.568-.878 1.232-.878.869 0 1.216.662 1.216 1.634v3.865h2.401V9.25c0-2.22-1.184-3.252-2.764-3.252-1.274 0-1.845.7-2.165 1.193v.025h-.016l.016-.025V6.169h-2.4c.03.678 0 7.225 0 7.225h2.4Z" /></svg>
            </a>
            <a href="https://github.com/permguard/permguard" target="_blank" rel="noopener noreferrer" aria-label="Permguard on GitHub">
              <svg aria-hidden="true" viewBox="0 0 16 16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.65 7.65 0 0 1 8.02 3.86c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" /></svg>
            </a>
          </div>
        </div>

        <nav class="pg-footer__links" aria-label="Footer navigation">
          <section>
            <h2>Products</h2>
            <ul>
              <li><a href="https://permguard.com/why-we-exist" target="_blank" rel="noopener noreferrer">Why we exist</a></li>
              <li><a href="https://permguard.com/policy-decision-point" target="_blank" rel="noopener noreferrer">Policy Decision Point</a></li>
            </ul>
          </section>

          <section>
            <h2>Documentation</h2>
            <ul>
              <li><a :href="withBase('/')">Community</a></li>
            </ul>
          </section>

          <section>
            <h2>Business</h2>
            <ul>
              <li><a href="https://permguard.com/pricing-support" target="_blank" rel="noopener noreferrer">Support &amp; Pricing</a></li>
              <li><a href="https://permguard.com/partner-network" target="_blank" rel="noopener noreferrer">Partners</a></li>
            </ul>
          </section>

          <section>
            <h2>Useful Links</h2>
            <ul>
              <li><a href="https://www.pic-protocol.org/" target="_blank" rel="noopener noreferrer">PIC Protocol</a></li>
            </ul>
          </section>
        </nav>
      </div>

      <div class="pg-footer__legal-row">
        <p><strong><a href="https://permguard.com/" target="_blank" rel="noopener noreferrer">Permguard</a>® is a registered trademark.</strong></p>
        <p><strong>Brought to you by <a href="https://www.nitroagility.com/" target="_blank" rel="noopener noreferrer">Nitro Agility S.r.l.</a></strong></p>
      </div>
      <p class="pg-footer__copy">© {{ year }} All rights reserved</p>
    </div>
  </footer>
</template>
