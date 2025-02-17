---
title: "Built-in Validators"
slug: "Built-in Validators"
description: ""
summary: ""
date: 2023-08-15T14:31:58+01:00
lastmod: 2023-08-15T14:31:58+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "built-in-validators-8b284f0c047942edbe62bebec794e430"
weight: 9301
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** implements built-in validators that are universally applied across multiple components.

---
**simplename**: *a valid simple name must satisfy the regex and cannot begin with the prefix `permguard` (case `lower`, validation `^[a-z][a-z0-9]*[a-z0-9]$`).*

---

**name**: *a valid name must satisfy the regex and cannot begin with the prefix `permguard` (case `lower`, validation `^[a-z][a-z0-9\-\._]*[a-z0-9]$`).*

---
