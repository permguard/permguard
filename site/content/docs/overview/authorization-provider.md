---
title: "Authorization Provider"
slug: "Authorization Provider"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "authorization-provider-8c89ddc8339f83444fc4b97264bd5c45"
weight: 1003
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
`Permguard` is a modern `Authorization Provider` that implements an advanced authorization layer. It delivers dynamic access control by managing user permissions, roles, and policies, ensuring secure and efficient authorization across diverse systems and applications.

## Infrastructure

Permguard can be deployed in various environments, ranging from virtual machines to container orchestration systems like Kubernetes and beyond.

## Administration

Permguard exposes gRPC endpoints for administrative functions, including the ability to create and manage:

- Accounts
- Tenants
- Identity Sources and Identities
- Schema (definitions for domains, resources, and actions)
- Policies
- Permissions.

## Identities

Since Permguard does not include an authentication layer, it is crucial to integrate it with an Authentication Provider. This integration can be accomplished by importing users from the Authentication Provider using the available APIs and SDKs, or through manual processes via the Permguard CLI.

Additionally, the application provides the capability to create and manage users on-the-fly through the available APIs and SDKs. It also supports the creation and management of roles.

## Policy as a Code

Permguard adopts a `Policy as Code` approach, enabling users to define and manage policies through code. This method ensures that all configurations are versioned, reviewed, and tested, while also centralizing policy management externally for enhanced security, compliance, and scalability.

## Integration

Permguard integrates seamlessly with any application, whether deployed on **servers**, **containers**, or in **serverless** environments. Integration is facilitated through gRPC requests to the `Policy Decision Point`, and SDKs are available for various programming languages to ensure smooth implementation.

{{< callout context="note" icon="info-circle" >}}
A Policy Decision Point can be deployed close to the node, such as in a sidecar container. These proximity services synchronize with the remote Permguard instance, ensuring low latency and high availability. `Permission evaluation` is performed in `approximately 1ms`.

{{< /callout >}}

There are two primary use cases for this integration:

- **API**: An endpoint accepts an authentication token (e.g., JWT) and evaluates if the associated identity has the necessary permissions for the requested operations.
- **Background**: A background process, such as a job or long-running worker, checks if the identity linked to the action has the required permissions. In a distributed system, this identity might be included in the message being processed.

For additional use cases, see [here](/docs/overview/patterns-through-use-cases).
