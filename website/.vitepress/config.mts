// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitepress'

// The documented release line. Bump it with the release; the nav shows it as `0.1.x`.
const version = '0.1'

// GitHub Pages serves the site below the repository path; the deploy workflow passes it in.
const base = `/${(process.env.VITEPRESS_BASE ?? '').replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/')

export default defineConfig({
  base,
  title: 'Permguard Docs',
  description: 'The documentation of Permguard: authorization and trust for the agentic era.',
  cleanUrls: true,
  // Dark by default, like permguard.com; the toggle still offers light.
  appearance: 'dark',
  themeConfig: {
    logo: '/permguard/symbol.svg',
    siteTitle: 'Permguard Docs',
    // `Home` is listed first, and the home page hides it (see `pg-page-home` in custom.css).
    nav: [
      { text: 'Home', link: '/' },
      { text: 'How it works', link: '/how-it-works' },
      { text: 'Command Line', link: '/command-line' },
      { text: 'Control Plane', link: '/control-plane' },
      { text: 'Data Plane', link: '/data-plane' },
      { text: 'Trust Plane', link: '/trust-plane' },
      {
        text: `${version}.x`,
        items: [
          { text: `${version} (current)`, link: '/' },
          { text: 'Changelog', link: 'https://github.com/permguard/permguard/blob/main/CHANGELOG.md' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/permguard/permguard' }
    ]
  }
})
