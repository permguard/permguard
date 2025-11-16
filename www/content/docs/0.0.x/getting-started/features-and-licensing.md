---
title: "Features & Licensing"
slug: "Features & Licensing"
description: ""
summary: ""
date: 2023-08-31T23:53:37+01:00
lastmod: 2023-08-31T23:53:37+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "features-and-licensing-7a754abe-7a98-45df-8c3a-ff6708d04abc"
weight: 1008
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Permguard Community** is an open-source project licensed under the **Apache-2.0 license**. It is designed to be a flexible and powerful **authorization platform**, supporting policies written in different languages.

For more details on legal terms and licenses, visit [Legal & Licenses](/docs/0.0.x/legal-licenses/third-party-technologies).

{{< callout context="caution" icon="alert-triangle" >}}
When reviewing licenses, always check that you are referencing the correct version of the documentation, related websites, or other **Permguard** materials.

These resources may be updated over time to reflect changes or improvements, especially for third-party technologies beyond our control. Ensuring you have the right version helps keep the information aligned with the specific software or materials you are using.

⚠️ **License Notice:**
The **Community Edition** and **Enterprise Edition** of Permguard are released under **different license terms**.
Always verify which edition applies before using or redistributing Permguard components.
{{</callout >}}

## Design Principles and Objectives

`Permguard` aims not only to modernize authorization, but to provide an `AuthZServer` that enables a standardized trust protocol built on Zero Trust principles and on the act-on-behalf-of model.  

The system is language-agnostic: policies and trust logic are not tied to any specific programming language, allowing each component to use the language that best expresses its domain while remaining fully interoperable.

Its design is grounded in policies that are `Transferable and Verifiable`, `Versionable and Immutable`, and `Resilient to Disconnection`.

This foundation enables secure, scalable, and resilient trust and authorization across distributed environments.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d21.webp"/>
</div><br/>
