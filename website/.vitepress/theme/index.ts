// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { h } from 'vue'
import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import SiteFooter from './SiteFooter.vue'
import CurrentPlane from './CurrentPlane.vue'
import './custom.css'
import './concepts.css'

// A page that needs its own component styles keeps them in `pages/<page>.css`; every such file is
// loaded here, so a new page adds its file and nothing else.
import.meta.glob('./pages/*.css', { eager: true })

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    // The plane in view, named in the bar after the Planes menu (see config.mts, `nav`).
    app.component('PgCurrentPlane', CurrentPlane)

    // The footer rises over the fixed sidebar (custom.css), so the sidebar must end where the
    // footer begins: otherwise its last links sit under the footer, out of reach. The visible
    // height of the footer becomes the sidebar's bottom offset, and the sidebar scrolls inside
    // what is left whenever its links are taller than that.
    if (typeof window !== 'undefined') {
      let frame = 0
      const measure = () => {
        frame = 0
        const footer = document.querySelector('.pg-footer')
        const overlap = footer ? Math.max(0, window.innerHeight - footer.getBoundingClientRect().top) : 0
        document.documentElement.style.setProperty('--pg-footer-overlap', `${Math.round(overlap)}px`)
      }
      const schedule = () => { if (!frame) frame = requestAnimationFrame(measure) }
      window.addEventListener('scroll', schedule, { passive: true })
      window.addEventListener('resize', schedule)
      // A page change swaps the content under the same window: measure once it has rendered.
      new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true })
      schedule()
    }
  },
  Layout: () => h(DefaultTheme.Layout, null, {
    'layout-bottom': () => h(SiteFooter)
  })
} satisfies Theme
