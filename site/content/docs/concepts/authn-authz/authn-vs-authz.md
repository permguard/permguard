---
title: "Authn vs Authz"
slug: "Authn vs Authz"
description: ""
summary: ""
date: 2023-08-01T00:17:36+01:00
lastmod: 2023-08-01T00:17:36+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authn-vs-authz-790ad1dfca1124d298179d82f4715ef8"
weight: 2101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Authentication (**authn**) and Authorization (**authz**) are two distinct concepts within the realm of security. They are often confused with each other, but they serve separate purposes.

Authentication verifies the identity of a person or device, ensuring that they are indeed **who or what they claim to be**. This process safeguards data from unauthorized access by ensuring it is only accessible to authenticated entities.
There exist several methods for authenticating individuals or devices, including `Username and Password`, `Multi-Factor Authentication (MFA)`, `Biometric authentication`, and `Public Key Certificate`.

On the other hand, Authorization dictates **what actions an authorized user or device can perform**. The authorization level assigned to a user determines the scope of their permissions, often referred to as **permissions**.

Organizations implement various authorization solutions to govern user actions, permitting or denying access to resources. These solutions typically determine which actions are permissible based on the identity of the user. Consequently, authentication closely intertwines with authorization.
