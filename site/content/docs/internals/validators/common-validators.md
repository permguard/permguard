---
title: "Common Validators"
slug: "Common Validators"
description: ""
summary: ""
date: 2023-08-15T14:31:58+01:00
lastmod: 2023-08-15T14:31:58+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "common-validators-8b284f0c047942edbe62bebec794e430"
weight: 8301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` implements common validators that are universally used across multiple components

| TYPE | VALIDATION                             | DESCRIPTION                            |
|------|----------------------------------------|----------------------------------------|
| NAME | `^[a-zA-Z][a-zA-Z0-9\-_]*[a-zA-Z0-9]$` | A valid name should satisfy the regex. |
