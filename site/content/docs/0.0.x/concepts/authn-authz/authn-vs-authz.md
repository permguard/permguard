---
title: "AuthN vs AuthZ"
slug: "AuthN vs AuthZ"
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
**Authentication (`AuthN`)** and **Authorization (`AuthZ`)** are two distinct but interconnected security concepts. They are often confused because they work together, but they serve different purposes.

- **`Authentication`** verifies the identity of a person, application, or device, ensuring they are who they claim to be. This protects systems from unauthorized access. Common authentication methods include:
  - Username and Password
  - Multi-Factor Authentication (MFA)
  - Biometric Authentication
  - Public Key Certificates

  Authentication acts as a gatekeeper, allowing only verified entities to access protected systems.

{{< callout context="note" icon="info-circle" >}}
**Identity Management**: **Permguard** follows the **Bring Your Own Identity (BYOI)** model for `AuthN`.
{{< /callout >}}

- **`Authorization`** determines what actions an authenticated user or device can perform. It defines permissions for users, devices, or systems, controlling access to specific resources or operations. Authorization can be **role-based** or **policy-based**, assigning different permission levels based on identity or attributes.

Organizations use strong authorization solutions to enforce access controls, ensuring that resources are only accessed by those with the right permissions. These systems rely on authentication to verify identity before making real-time access decisions. While separate, **authentication and authorization must work together**, authorization has no value without verified authentication.
