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

      // Code groups follow the reader's language: pick Go once and every group of the site that has
      // a Go tab shows Go, on this page and the next. Policy languages are a choice of their own, so
      // picking Rego never changes the SDK examples. The tab is read from its file name's extension.
      // Groups are switched directly, not by clicking, so the page never scrolls to them.
      const POLICY = new Set(['cedar', 'rego'])
      const keyOf = (ext: string) => (POLICY.has(ext) ? 'pg-policy-language' : 'pg-code-language')
      const extOf = (label: Element) =>
        ((label as HTMLElement).dataset.title || label.textContent || '').trim().split('.').pop()!.toLowerCase()
      const read = (key: string) => { try { return localStorage.getItem(key) } catch { return null } }
      const write = (key: string, value: string) => { try { localStorage.setItem(key, value) } catch { /* private mode */ } }
      const follow = () => {
        const prefs = [read('pg-code-language'), read('pg-policy-language')].filter(Boolean) as string[]
        if (!prefs.length) return
        document.querySelectorAll('.vp-code-group').forEach((group) => {
          const labels = Array.from(group.querySelectorAll('.tabs label'))
          const index = labels.findIndex((label) => prefs.includes(extOf(label)))
          if (index < 0) return
          const inputs = Array.from(group.querySelectorAll<HTMLInputElement>('.tabs input'))
          if (!inputs[index] || inputs[index].checked) return
          inputs[index].checked = true
          const blocks = group.querySelector('.blocks')
          Array.from(blocks?.children ?? []).forEach((block, k) => block.classList.toggle('active', k === index))
        })
      }
      window.addEventListener('click', (event) => {
        const input = event.target as HTMLElement
        if (!(input instanceof HTMLInputElement) || !input.matches('.vp-code-group input')) return
        const label = input.parentElement?.querySelector(`label[for="${CSS.escape(input.id)}"]`)
        if (!label) return
        const ext = extOf(label)
        write(keyOf(ext), ext)
        requestAnimationFrame(follow)
      })
      let following = 0
      new MutationObserver(() => {
        if (!following) following = requestAnimationFrame(() => { following = 0; follow() })
      }).observe(document.documentElement, { childList: true, subtree: true })
      follow()
    }
  },
  Layout: () => h(DefaultTheme.Layout, null, {
    'layout-bottom': () => h(SiteFooter)
  })
} satisfies Theme
