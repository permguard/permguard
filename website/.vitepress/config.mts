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
      light: '/permguard/logo-dark-txt.png',
      dark: '/permguard/nav-wordmark-white.svg',
      alt: 'Permguard'
    },
    siteTitle: '<span class="pg-docs-label">Docs</span>',
    // `Home` is listed first, and the home page hides it (see `pg-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      { text: 'How it works', link: '/how-it-works' },
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
      { icon: 'github', link: 'https://github.com/permguard/permguard' }
    ]
  }
})
