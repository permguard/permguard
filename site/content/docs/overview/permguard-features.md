---
title: "PermGuard Features"
slug: "PermGuard Features"
description: ""
summary: ""
date: 2023-08-31T23:53:37+01:00
lastmod: 2023-08-31T23:53:37+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "permguard-features-7a754abe-7a98-45df-8c3a-ff6708d04abc"
weight: 1005
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`PermGuard` is open source and it is distributed under the Apache-2.0 license.
It has been designed to be user-friendly and packed with essential features such as:

- **Multi Accounts:** Ability to manage multiple isolated accounts.
- **Multi Tenants:** Each account can have multiple isolated tenants.
- **Identities:** Ability to manage multiple identities in the form of users or roles for each account.
- **Repositories:** Ability to manage multiple authorization repositories for each account:
  - **Schema:** Creation of the schema to define the authorization model, segmented across multiple domains.
  - **Resources and Actions:** Definition and configuration of resources and actions.
  - **Permissions:** Creation of permissions to define the access control model for each identity.
  - **Configuration Language:** Ability to configure the repository using a code-first approach with either Permscript language or YAML.

{{< inline-svg src="images/overview/permguard-community.svg" width="100%" height="100%" class="svg-inline-custom svg-lightmode" >}}
{{< inline-svg src="images/overview/permguard-community.svg" width="100%" height="100%" style="background-color:#ffffff; border: 4px solid #d53ec6;"  class="svg-inline-custom svg-darkmode" >}}
