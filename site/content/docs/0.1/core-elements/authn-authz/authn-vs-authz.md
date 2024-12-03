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
Authentication (`AuthN`) and Authorization (`AuthZ`) are two distinct but interconnected concepts within the realm of security, often confused with one another due to their complementary roles. However, they serve separate and critical purposes.

`Authentication` verifies the identity of a person, application, or device, ensuring they are who or what they claim to be. This process is vital for safeguarding data and systems from unauthorized access. Common authentication methods include Username and Password, Multi-Factor Authentication (MFA), Biometric Authentication, and Public Key Certificates. Authentication acts as the gatekeeper, allowing only verified entities to access protected systems.

{{< callout context="note" icon="info-circle" >}}
Identity Management: Permguard adopts the **Bring Your Own Identity (BYOI)** model for the AuthN, syncing seamlessly with external identity sources for streamlined and secure management.
{{< /callout >}}

`Authorization`, on the other hand, determines what actions an authenticated user or device is allowed to perform. It defines the scope of permissions for a user, device, or system and dictates access to specific resources or operations. Authorization is role or policy-based, assigning different levels of permissions depending on the user's identity or attributes.

Organizations employ robust authorization solutions to enforce access controls, ensuring resources are accessed and actions performed only by those with the proper permissions. These systems typically rely on the user's identity (established during authentication) to make real-time decisions about access and actions. While distinct, authentication and authorization are deeply intertwined, as authorization is meaningless without verified authentication.
