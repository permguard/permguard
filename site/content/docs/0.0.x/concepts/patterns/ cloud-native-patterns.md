---
title: "Cloud Native Patterns"
slug: "Cloud Native Patterns"
description: ""
summary: ""
date: 2023-08-21T22:42:17+01:00
lastmod: 2023-08-21T22:42:17+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "cloud-native-patterns-ff808103155aea16d2022dd1284416bf"
weight: 2501
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

A common use case for **Permguard** is in the context of cloud-native applications, where an identity can initiate an action via an API. This action can then be split into events that are dispatched and processed by multiple microservices.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d2.webp"/>
</div>

Permguard focuses on [AuthN](/docs/0.0.x/concepts/authn-authz/authn-vs-authz/) therefore it does not provide any authentication mechanism. It is assumed that the user is already authenticated and the JWT token is available.

{{< callout context="note" icon="info-circle" >}}
Identity Management: Permguard adopts the **Bring Your Own Identity (BYOI)** model for the AuthN, syncing seamlessly with external identity sources for streamlined and secure management.
{{< /callout >}}

## Use Case: Api Endpoint

One use case involves sending a JWT token to an API endpoint, where the token can contain various metadata such as permission actors and scopes. However, this approach presents several drawbacks:

- **Increased JWT Size**: Including numerous permissions within the JWT can lead to its size growing, resulting in increased network overhead when transmitting the token.
- **Synchronization Challenges**: If the metadata, such as permissions, undergoes changes, the JWT must be reissued to reflect these modifications. Otherwise, there's a risk of permissions becoming out of sync, leading to potential security issues.
- **Code Duplication**: Each application that receives the JWT token needs to read its metadata and implement logic to check permissions. This duplication of code across different parts of the application can lead to maintenance challenges and potential inconsistencies in permission enforcement.

Below a sample JWT Token:

```json
{
  "iss": "https://your-domain.example.com/",
  "sub": "example|123456789",
  "iat": 1516239022,
  "exp": 1516325422,
  "scope": "openid profile email",
  "permissions": ["read:inventory"],
  "actors": ["pharmacist"]
}
```

**Permguard** does not require the JWT token to contain any permission or actor, as it has a copy of the applicative users and know exactly which permissions are attached to each user.
With this approach the previous drawbacks are mitigated:

- **Increased JWT Size**: This problem is fixed as there is no need to add extra fields in the JWT token.
- **Synchronization Challenges**: This problem is fixed as permissions are up to date.
- **Code Duplication**: This problem is fixed as the application does not need to implement any logic to evaluate the permissions, as the policies evaluation is delegated to **Permguard**.

## Use Case: Asynchronous Operations and Revoked Permissions

In the context of asynchronous operations, there is no guarantee about when the operations will be executed. This can result in a scenario where permissions are revoked after the operation has already been initiated.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d3.webp"/>
</div>

By leveraging **Permguard**, if the operation has been revoked, the policy evaluation will return false, resulting in the denial of the operation. Consequently, the operation will not be executed, contributing to a higher level of security within the application.

## Use Case: Securing Asynchronous Operations and Tempered Events

In scenarios involving asynchronous operations, it's typical for an application not to receive an authorization token as input.
Storing tokens in events can pose security risks, and there's also a high likelihood that the token would expire before it's consumed.

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d4.webp"/>
</div>

It is possible to publish a signed event and subsequently validate the event and finally perform permission checks with **Permguard**.
