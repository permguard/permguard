// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitepress'
import cedarGrammar from './languages/cedar.tmLanguage.json'
import regoGrammar from './languages/rego.tmLanguage.json'
import dogwoodGrammar from './languages/dogwood.tmLanguage.json'

// Versioned documentation. `scripts/build-versions.sh` builds every version on every deploy and
// passes these in; a plain `npm run docs:dev` or `docs:build` is the `latest` site on its own.
//
//   DOCS_VERSION   the version this build is: `latest`, or `MAJOR.MINOR` such as `0.1`
//   DOCS_VERSIONS  JSON list of every published `MAJOR.MINOR`, newest first, for the menu
//   DOCS_ROOT_URL  absolute URL of the site root, where `latest` lives
//   VITEPRESS_BASE path of this build: the root for `latest`, `<root>/MAJOR.MINOR/` for a version
const version = process.env.DOCS_VERSION || 'latest'
const versions: string[] = JSON.parse(process.env.DOCS_VERSIONS || '[]')
const rootUrl = (process.env.DOCS_ROOT_URL || '').replace(/\/+$/, '')

// GitHub Pages serves the site below the repository path; the deploy script passes it in.
const base = `/${(process.env.VITEPRESS_BASE ?? '').replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/')

// Other versions are other sites under the same root, so they are linked by absolute URL. Without
// a root URL (a local build) only this site exists, and `latest` is its own home page.
// Every plane, in the order a request meets them: who may call, what is published, what decides,
// what continues authority. The menu and the planes' sidebar list the same four.
const planeItem = (name: string, link: string, line: string) => ({
  text: `${name}<small class="pg-menu-line">${line}</small>`,
  link
})

const planesSidebar = [
  {
    text: 'Planes',
    items: [
      {
        text: 'Authority Plane',
        link: '/authority-plane',
        items: [{ text: 'Access Tokens & Clusters', link: '/authority-plane/access-tokens' }]
      },
      { text: 'Control Plane', link: '/control-plane' },
      { text: 'Data Plane', link: '/data-plane' },
      { text: 'Trust Plane', link: '/trust-plane' }
    ]
  }
]

const versionLink = (target: string) => ({
  text: target,
  link: rootUrl ? `${rootUrl}/${target === 'latest' ? '' : `${target}/`}` : '/',
  target: '_self',
  noIcon: true
})

export default defineConfig({
  base,
  title: 'Permguard Docs',
  description: 'The documentation of Permguard: authorization and trust for the agentic era.',
  head: [
    ['link', { rel: 'icon', type: 'image/x-icon', href: `${base}permguard/favicon.ico` }]
  ],
  cleanUrls: true,
  // The policy languages are not in Shiki's bundle; their grammars live in `.vitepress/languages`,
  // with their sources and licences in the README beside them.
  markdown: {
    languages: [
      { ...cedarGrammar, name: 'cedar' },
      { ...regoGrammar, name: 'rego' },
      { ...dogwoodGrammar, name: 'dogwood', aliases: ['dw'] }
    ]
  },
  // A page that moved keeps its old address as a stub whose frontmatter names the new one,
  // `redirect: /authority-plane`; the refresh carries this build's base, so it lands in the same
  // version of the documentation.
  transformHead({ pageData }) {
    const target = pageData.frontmatter.redirect
    if (typeof target !== 'string') return
    const url = `${base}${target.replace(/^\/+/, '')}`
    return [
      ['meta', { 'http-equiv': 'refresh', content: `0; url=${url}` }],
      ['link', { rel: 'canonical', href: url }],
      ['meta', { name: 'robots', content: 'noindex' }]
    ]
  },
  // Dark by default, like permguard.com; the toggle still offers light.
  appearance: 'dark',
  themeConfig: {
    // Read by the home page to say which version it documents.
    docsVersion: version,
    logo: {
      light: '/permguard/nav-wordmark-white.svg',
      dark: '/permguard/nav-wordmark-white.svg',
      alt: 'Permguard'
    },
    siteTitle: '<span class="pg-docs-label">Docs</span>',
    // `Home` is listed first, and the home page hides it (see `pg-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      // A section is a link; its pages are listed by the sidebar of the section, not by a menu.
      { text: 'How it works', link: '/how-it-works', activeMatch: '^/how-it-works' },
      { text: 'Command Line', link: '/command-line' },
      {
        text: 'Planes',
        activeMatch: '^/(authority|control|data|trust)-plane',
        items: [
          planeItem('Authority Plane', '/authority-plane', 'Service accounts, access keys, tokens'),
          planeItem('Control Plane', '/control-plane', 'Zones, ledgers, signed policy'),
          planeItem('Data Plane', '/data-plane', 'Decisions beside the workload'),
          planeItem('Trust Plane', '/trust-plane', 'Authority continuity · PIC-X')
        ]
      },
      // Inside a plane, the bar names it after the menu; elsewhere this renders nothing.
      { component: 'PgCurrentPlane' },
      {
        text: version,
        items: [
          { items: ['latest', ...versions].map(versionLink) },
          { items: [{ text: 'Changelog', link: 'https://github.com/permguard/permguard/blob/main/CHANGELOG.md' }] }
        ]
      }
    ],
    // How it works and the planes carry a sidebar. A key has no trailing slash so that it matches the
    // section's own page, `how-it-works.md` or `authority-plane.md`, as well as every page under it:
    // the overview is a `layout: page`, which VitePress still gives a sidebar.
    sidebar: {
      '/authority-plane': planesSidebar,
      '/control-plane': planesSidebar,
      '/data-plane': planesSidebar,
      '/trust-plane': planesSidebar,
      '/how-it-works': [
        {
          text: 'Start',
          items: [
            { text: 'Overview', link: '/how-it-works' },
            { text: 'Install', link: '/how-it-works/install' },
            { text: 'Containers', link: '/how-it-works/container-images' },
            { text: 'Getting Started', link: '/how-it-works/getting-started' }
          ]
        },
        {
          text: 'Concepts',
          items: [
            { text: 'Server, Host & Planes', link: '/how-it-works/architecture' },
            { text: 'Policy as Code', link: '/how-it-works/policy-languages' },
            { text: 'Zones & Ledgers', link: '/how-it-works/zones-and-ledgers' },
            { text: 'Git-like Versioning', link: '/how-it-works/policy-storage' },
            { text: 'NOTP Protocol', link: '/how-it-works/notp' },
            { text: 'Policy Delivery', link: '/how-it-works/policy-lifecycle' },
            { text: 'Decision Path', link: '/how-it-works/decision-lifecycle' },
            { text: 'Verifiable Evidence', link: '/how-it-works/evidence' },
            { text: 'Bring Your Own Data Plane', link: '/how-it-works/bring-your-own-data-plane' },
            { text: 'Temporal Authorization', link: '/how-it-works/temporal-authorization' }
          ]
        },
        {
          text: 'Reference',
          items: [
            { text: 'Glossary', link: '/how-it-works/glossary' }
          ]
        }
      ]
    },
    search: {
      provider: 'local',
      options: {
        // A page draws its title in its hero, a raw HTML `<h1>` the search index neither anchors nor
        // counts, so a page without a Markdown `#` heading of its own is indexed under its
        // frontmatter title and description, as in the handbook.
        _render(src, env, md) {
          const html = md.render(src, env)
          const { title, description } = env.frontmatter ?? {}
          if (!title || /^#\s/m.test(src)) return html
          return md.render(`# ${title}\n\n${description ?? ''}\n`, {}) + html
        }
      }
    },
    socialLinks: [
      {
        icon: {
          svg: '<svg viewBox="0 0 24 24" style="fill:none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9" style="fill:none"/><path d="M3 12h18M12 3c2.25 2.47 3.4 5.47 3.4 9S14.25 18.53 12 21c-2.25-2.47-3.4-5.47-3.4-9S9.75 5.47 12 3Z" style="fill:none"/></svg>'
        },
        link: 'https://www.permguard.com/',
        ariaLabel: 'Permguard website'
      },
      { icon: 'x', link: 'https://x.com/permguard', ariaLabel: 'Permguard on X' },
      { icon: 'linkedin', link: 'https://www.linkedin.com/showcase/permguard/', ariaLabel: 'Permguard on LinkedIn' },
      { icon: 'github', link: 'https://github.com/permguard/permguard' }
    ]
  }
})
