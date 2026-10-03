// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitepress'

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
  // Dark by default, like permguard.com; the toggle still offers light.
  appearance: 'dark',
  themeConfig: {
    // Read by the home page to say which version it documents.
    docsVersion: version,
    logo: {
      light: '/permguard/nav-wordmark-dark.svg',
      dark: '/permguard/nav-wordmark-white.svg',
      alt: 'Permguard'
    },
    siteTitle: '<span class="pg-docs-label">Docs</span>',
    // `Home` is listed first, and the home page hides it (see `pg-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      {
        text: 'How it works',
        activeMatch: '^/how-it-works',
        items: [
          {
            text: 'Start',
            items: [
              { text: 'Overview', link: '/how-it-works' },
              { text: 'Install', link: '/how-it-works/install' },
              { text: 'Container Images', link: '/how-it-works/container-images' },
              { text: 'Getting Started', link: '/how-it-works/getting-started' }
            ]
          },
          {
            text: 'Concepts',
            items: [
              { text: 'Server, Host & Planes', link: '/how-it-works/architecture' },
              { text: 'Git-like Policy Storage', link: '/how-it-works/policy-storage' },
              { text: 'Bring Your Own Data Plane', link: '/how-it-works/bring-your-own-data-plane' },
              { text: 'Policy Lifecycle', link: '/how-it-works/policy-lifecycle' },
              { text: 'Decision Lifecycle', link: '/how-it-works/decision-lifecycle' },
              { text: 'Evidence & Verification', link: '/how-it-works/evidence' },
              { text: 'Temporal Authorization', link: '/how-it-works/temporal-authorization' },
              { text: 'Policy Languages', link: '/how-it-works/policy-languages' }
            ]
          }
        ]
      },
      { text: 'Command Line', link: '/command-line' },
      { text: 'Control Plane', link: '/control-plane' },
      { text: 'Data Plane', link: '/data-plane' },
      { text: 'Trust Plane', link: '/trust-plane' },
      {
        text: version,
        items: [
          { items: ['latest', ...versions].map(versionLink) },
          { items: [{ text: 'Changelog', link: 'https://github.com/permguard/permguard/blob/main/CHANGELOG.md' }] }
        ]
      }
    ],
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
