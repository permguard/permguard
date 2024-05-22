---
title: "Common Use Cases"
slug: "Common Use Cases"
description: ""
summary: ""
date: 2023-08-21T22:42:17+01:00
lastmod: 2023-08-21T22:42:17+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "common-use-cases-ff808103155aea16d2022dd1284416bf"
weight: 1004
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

A common use case for `PermGuard` is in the context of cloud-native applications, where an identity can initiate an action via an API. This action can then be split into events that are dispatched and processed by multiple microservices.

{{< inline-svg src="images/overview/permguard-cloud-native-architecture.svg.svg" width="100%" height="100%" class="svg-inline-custom svg-lightmode" >}}
{{< inline-svg src="images/overview/permguard-cloud-native-architecture.svg.svg" width="100%" height="100%" style="background-color:#ffffff; border: 4px solid #d53ec6;"  class="svg-inline-custom svg-darkmode" >}}

PermGuard focuses on [Authz](/docs/concepts/authn-authz/authn-vs-authz/) therefore it does not provide any authentication mechanism. It is assumed that the user is already authenticated and the JWT token is available.

## Use Case: Api Endpoint

One use case involves sending a JWT token to an API endpoint, where the token can contain various metadata such as permission roles and scopes. However, this approach presents several drawbacks:

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
  "permissions": [
    "read:car"
  ],
  "roles": [
    "customer"
  ]
}
```

`PermGuard` does not require the JWT token to contain any permission or role, as it has a copy of the applicative users and know exactly which permissions are attached to each user.
With this approach the previous drawbacks are mitigated:

- **Increased JWT Size**: This problem is fixed as there is no need to add extra fields in the JWT token.
- **Synchronization Challenges**: This problem is fixed as permissions are up to date.
- **Code Duplication**: This problem is fixed as the application does not need to implement any logic to evaluate the permissions, as the policies evaluation is delegated to `PermGuard`.

```python
has_permissions = permguard.check(jwt.sub, "car-rental/1.0.0", "ListCars", "car")

if has_permissions:
    print("Role can list cars")
else:
    print("Role can not list cars")
```

## Use Case: Asynchronous Operations and Revoked Permissions

In the context of asynchronous operations, there is no guarantee about when the operations will be executed. This can result in a scenario where permissions are revoked after the operation has already been initiated.

{{< inline-svg src="images/overview/usecase-async-revoked-permissions.svg" width="100%" height="100%" class="svg-inline-custom svg-lightmode" >}}
{{< inline-svg src="images/overview/usecase-async-revoked-permissions.svg" width="100%" height="100%" style="background-color:#ffffff; border: 4px solid #d53ec6;"  class="svg-inline-custom svg-darkmode" >}}

By leveraging `PermGuard`, if the operation has been revoked, the policy evaluation will return false, resulting in the denial of the operation. Consequently, the operation will not be executed, contributing to a higher level of security within the application.

## Use Case: Securing Asynchronous Operations and Tempered Events

In scenarios involving asynchronous operations, it's typical for an application not to receive an authorization token as input.
Storing tokens in events can pose security risks, and there's also a high likelihood that the token would expire before it's consumed.

{{< inline-svg src="images/overview/usecase-securing-async-operations.svg" width="100%" height="100%" class="svg-inline-custom svg-lightmode" >}}
{{< inline-svg src="images/overview/usecase-securing-async-operations.svg" width="100%" height="100%" style="background-color:#ffffff; border: 4px solid #d53ec6;"  class="svg-inline-custom svg-darkmode" >}}

It is possible to publish a signed event and subsequently validate the event and finally perform permission checks with `PermGuard`.

```python
signedMessage = permguard.sign(jwt.sub, message)
publish(signedMessage)
```

## Use Case: Identity Delegation

Another common use case involves scenarios where a user needs to temporarily delegate their identity to another user.

By leveraging the `PermGuard`, users can indeed implement this by granting the necessary permissions to the delegated identity.
This allows actions to be performed on behalf of the user. However, it's important to note that the auditing process would track the operation as being executed by another user.

```python
ajwt = permguard.create_token(jwt.sub, delegated_uur, { "delegation": true })
make_call_to_service(ajwt)
```

Despite this, it still leads to a clean and secure solution.
