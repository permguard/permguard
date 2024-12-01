---
title: "Licensing and Features"
slug: "Licensing and Features"
description: ""
summary: ""
date: 2023-08-31T23:53:37+01:00
lastmod: 2023-08-31T23:53:37+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "licensing-features-7a754abe-7a98-45df-8c3a-ff6708d04abc"
weight: 1007
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Permguard** is an open-source project licensed under the **Apache-2.0 license**. Its core objective is to act as a flexible and powerful **authorization provider** that supports policies written in various languages. In addition, it introduces an **opinionated layer** to guide how **schemas** and **models** for authorization (AuthZ) and authentication (AuthN) should be structured.

For more information about legal terms and licenses, please visit [Legal & Licenses](/docs/0.1/legal-licenses).

{{< callout context="caution" icon="alert-triangle" >}}
When reviewing licenses, ensure that you are referencing the correct version of the documentation, related websites, or other materials for Permguard. These resources may change over time, and it is important to verify that the information aligns with the specific version of the software or materials you are using.
{{< /callout >}}

## Key Goals of Permguard

- **Multi-Policy Execution**: Permguard is designed to execute policies written in different languages, enabling flexibility and interoperability across various systems.

- **Opinionated Framework**: It provides a clear and structured layer for designing authorization and authentication models, offering best practices for modern identity and access management.

- **Scalability and Flexibility**: Built with a focus on scalability, Permguard supports multi-account and multi-tenant environments, empowering organizations to manage access control efficiently.

- **Zero Trust Compliance**: By adopting the **Zero Trust Auth*** ([ZTAuth*](https://medium.com/ztauth)) architecture, Permguard implements versionable and composable **Auth*** models that can be replicated in **proximity nodes**. This allows it to overcome the limitations of partially connected devices and ensures seamless policy enforcement across diverse environments.

- **Open Source First**: With its Apache-2.0 license, Permguard is open to the community, encouraging collaboration and innovation in access control and policy management.

---

Permguard aims to redefine how authorization providers operate by combining flexibility with strong opinions on schema and model design, giving organizations the tools they need to implement secure and scalable access control systems.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d5.png"/>
</div>
