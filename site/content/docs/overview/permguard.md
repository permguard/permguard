---
title: "PermGuard"
slug: "PermGuard"
description: ""
summary: ""
date: 2023-08-20T17:14:43+01:00
lastmod: 2023-08-20T17:14:43+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "permguard-24b9ae1383440efb49528d1ecc48ab03"
weight: 1001
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`PermGuard` is an open source Multi-Account and Multi-Tenant Authorization Provider that implements the authorization layer, allowing the application’s authorization logic to be separated from the core application code.

{{< callout context="note" icon="info-circle" >}}
The decoupling between the authorization layer and the application code enables the administration of roles and permissions without requiring any changes to the application code.

Furthermore, it makes it easier to create a central authorization layer for managing all permissions across multiple applications, similar to how modern software solutions manage users in one central place for the authentication layer.
{{< /callout >}}

The platform uses a code-first approach with either the either Permscript language or YAML, both providing the same functionality.

Through the chosen approach, it is possible to specify who or what can access resources through finely detailed permissions.

- `Who`: *Identities (Users and Roles)*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

{{< inline-svg src="images/overview/permguard-flow.svg" width="100%" height="100%" class="svg-inline-custom svg-lightmode" >}}
{{< inline-svg src="images/overview/permguard-flow.svg" width="100%" height="100%" style="background-color:#ffffff; border: 4px solid #d53ec6;"  class="svg-inline-custom svg-darkmode" >}}

Moreover it is possible to define **trusted delegation**, enabling a user to delegate their permissions to another user. This delegation can be restricted for a certain period of time, and it is also possible to narrow down the permissions window by restricting the granted policies.

{{< callout context="note" icon="info-circle" >}}
It's important to note that PermGuard supports tenancy, enabling each account to have multiple isolated tenants, and each tenant can, in turn, have multiple isolated
resources.
{{< /callout >}}

To enforce the access control process, the application can integrate one of the available **SDKs** or manually integrate the native **APIs**.

{{< callout context="tip" icon="rocket" >}}
PermScript language is designed to define policies, specifying actions that can be performed on specific resources. Additionally it is possible to specify identities, permissions associated with identities and trusted delegations.
{{< /callout >}}

<div style="text-align: center">
  <img alt="PermGuard Policies" src="/images/overview/vscode-screenshot.png"/>
</div>
