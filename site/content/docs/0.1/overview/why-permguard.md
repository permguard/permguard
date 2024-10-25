---
title: "Why Permguard"
slug: "Why Permguard"
description: ""
summary: ""
date: 2024-09-26T11:32:26+02:00
lastmod: 2024-09-26T11:32:26+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "why-permguard-62e42298f99ff7b907d6173b43e4d355"
weight: 1002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

## Why Keycloak, Okta, and Auth0 are not Competitors to Permguard

A common question that arises is how `Permguard` compares to `Keycloak`, `Okta`, and `Auth0`, especially since all these solutions seem to deal with access control. While it’s true that these products include some authorization capabilities, their primary focus and the depth of their functionality differ significantly from what Permguard offers. Here's a breakdown:

### Primary Function

  - `Keycloak, Okta, and Auth0` are primarily `Identity and Access Management (IAM)` solutions. Their main responsibility is to authenticate users and manage identities (e.g., providing `Single Sign-On (SSO)`, federating identities, and supporting `OAuth2` or `SAML`).
  - `Permguard`, by contrast, is designed to manage `permissions` and `authorization policies` at a deeper, more granular level. It focuses on `Policy-as-Code`, enabling precise and scalable control over who can do what within an application or across multiple environments (multi-account, multi-tenant). While it can map identities from external IAM providers, Permguard leaves identity management entirely to these external tools.

### Authentication vs Authorization

  - `Keycloak, Okta, and Auth0` focus primarily on `authentication` (proving who the user is).
  - `Permguard`, however, manages `authorization` (deciding what an authenticated user is allowed to do). With `eventual consistency` and `real-time policy enforcement`, Permguard ensures that policies are synchronized and enforced efficiently across any infrastructure, including `Kubernetes`, `serverless environments`, `VMs`, `IoT`, and `edge nodes`.

### Scalability and Policy Management

  - `Permguard` provides a robust infrastructure for managing policies at scale. Its architecture supports `multi-account` and `multi-tenant` environments, allowing enterprises to centralize policy management across distributed systems. With `Git-like immutable storage`, it ensures security and consistency when managing policy updates.
  - Additionally, `Permguard’s proximity nodes` allow real-time permission evaluation close to where they are needed, reducing latency and improving performance, especially in distributed and edge computing scenarios.

### Managing Complex Enterprise Environments

  - `Permguard` is purpose-built for `enterprise-grade complexity`, providing governance and compliance controls essential for large-scale operations. It handles the intricacies of modern cloud-native environments and ensures that authorizations are applied with precision, whether applications run in `containerized`, `serverless`, or `edge` architectures.

### Why are they not competitors?
While `Keycloak, Okta, and Auth0` focus on authentication and identity management, their `authorization features` are generally basic and not designed to handle the advanced, scalable needs of a complex, multi-environment enterprise. `Permguard`, on the other hand, is built specifically for `advanced authorization management`, offering granular control, real-time evaluation, and enterprise-level scalability. This makes Permguard the ideal solution for organizations that require detailed authorization governance across a distributed infrastructure—something IAM providers are not equipped to deliver on their own.

## Centralized Policy Management and Distributed Enforcement

`Permguard` centralizes policy management but ensures policies are distributed efficiently across all your applications. This means each service can enforce authorization rules independently, without the latency typically introduced by relying on a single enforcement point, like at the front door.

What makes this possible is our approach of deploying `proximity nodes` near the applications. These nodes come with the `policy engine embedded`, eliminating the need to integrate policy checks into the application's code. Policies are evaluated `locally and in real-time`, significantly reducing latency.

Policies are distributed using a `Git-like approach` that ensures `immutability` and maintains a `Zero Trust` focus, with the necessary checks applied at each layer.

In practical terms, this means there’s `no need to modify your application code` to enforce policies. Rules are applied consistently across all applications, whether at a service endpoint, microservice, or any other resource. And with `centralized management`, you have a `single point of control` to audit and manage policies across the entire environment.

This combination enables `fast, scalable, and cross-app policy enforcement` without the complexity or overhead often associated with distributed authorization systems.
