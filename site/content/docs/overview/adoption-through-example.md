---
title: "Adoption Through Example"
slug: "Adoption Through Example"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "adoption-through-example-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` is an `Authorization Provider` and it implements the authorization layer.
## Infrastructure

PermGuard can be runninig either in a virtual machine or a container orchestration system like Kubernetes.

## Administration

PermGuard expose gRPC endpoints for the administration. This includes the ability to create and manage the following:

- Tenants
- Identities
- Schemas where domains, resources, and actions can be explicitly defined
- Policies
- Permissions.

## Identities

Since PermGuard lacks an authentication layer, it's essential to federate it with an Authentication Provider. This can be achieved by importing Users from the Authentication Provider using either the provided APIs and SDKs or through manual processes.

Additionally, the application has the capability to create and manage users on-the-fly using the available APIs and SDKs.

Additionaly it is possible to create and manage roles.

## Integration

Integration of PermGuard can be carried out in any type of application, whether it runs on a **server**, **container** or **serverless** environment; there are no limitations on the type of application that can utilize PermGuard.

This is primarily because the application needs to make a request to the `Policy Decision Point` via gRPC. To facilitate smooth and easy integration, SDKs are available for various programming languages.

{{< callout context="note" icon="info-circle" >}}
It's important to note that a Policy Decision Point can run in proximity to the node, for instance, as a sidecar container.
These proximity services synchronize from the remote PermGuard instance, allowing for low latency and high availability.
A `permission evaluation` can be executed in `approximately 1ms`.
{{< /callout >}}

There are mainly two uses cases where this integration is necessary:

- **API**: An endpoint is provided to accept an authentication token, such as a JWT token, as input. This endpoint evaluates whether the operations can be performed by the identity associated to the authentication token.
- **Background**: A background process, such as a job or a long-running worker, evaluates whether the operations can be performed by the identity associated with the requested action.
                  In the context of a distributed system reading messages from a broker, this identity could be included within the message being processed.

## A quick example

For the sake of the simplicity let's consider a `Car Rental` use case where an identity which represents a customer want to list the available cars.

The initial step involves creating a policy and associating it with the role by specifying the necessary permissions.

{{< tabs "policies-and-permissions" >}}
{{< tab "authz" >}}

```text
# Policy to list all cars.
policy ListCars {
    resources = uur:581616507495:default:car-rental:renting:car/*,
    actions = ra:car:ListCars
}

# Defines permissions to read all cars.
permission CarReadAll {
    permit = [ListCars],
    forbid = []
}

# Defines a role for the rental agent which in charge of the rental of the cars.
role RentalAgent {
  permissions = [CarReadAll]
}
```

{{< /tab >}}
{{< /tabs >}}

Once the policy has been created and associated with the role by specifying the required permissions, the next and final step is to perform the permission evaluation within the application.

```python
has_permissions = permguard.check("uur:581616507495:permguard:identities:iam:role/rental-agent", "car-rental/1.0.0", "ListCars", "car")

if has_permissions:
    print("Role can list cars")
else:
    print("Role can not list cars")
```
