---
title: "Manifests"
slug: "Manifests"
description: ""
summary: ""
date: 2023-08-21T22:44:09+01:00
lastmod: 2023-08-21T22:44:09+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "manifests-248830bb1a2b45199d54b29a16292d40"
weight: 2303
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
A **Permguard** ledger must be associated with a manifest.

{{< callout context="note" icon="info-circle" >}}
Those manifest files are created automatically when a new workspace is initialized.
{{< /callout >}}

## AuthZ Manifest

This **manifest**  is a mandatory component that represents the authorization (**AuthZ**) model. It allows you to define the following elements:

- **metadata**: Information about the authorization model
- **runtime**: A runtime represents a specific environment that can be used to build and evaluate the authorization model.
- **partition**: A partition defines a specific section of the authorization model, enabling a modular approach to its design.
