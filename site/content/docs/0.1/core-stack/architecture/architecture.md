---
title: "Architecture"
slug: "Architecture"
description: ""
summary: ""
date: 2023-08-15T14:31:58+01:00
lastmod: 2023-08-15T14:31:58+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "architecture-3d21ce1c1c77ac6959efbd27f652a69e"
weight: 8101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** consists of several services, which can be deployed either on a single instance using the `all-in-one` distribution, or individually using separate distributions for each service."

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d6.png"/>
</div>

## Application Administration Point (AAP)

The `Application Administration Point (AAP)` serves as the central repository for managing application information and configurations. Furthermore, it provides an administration API.

## Policy Administration Point (PAP)

The `Policy Administration Point (PAP)`  serves as the central repository for managing the application policies. Furthermore, it provides an administration API.

## Policy Information Point (PIP)

The `Policy Information Point (PIP)` is the service responsible for providing additional information to the `Policy Decision Point (PDP)` to make informed decisions.

## Policy Decision Point (PDP)

The `Policy Decision Point (PDP)` is the service responsible for evaluating policies and making decisions based on them. It can be deployed as either a `remote service` or a `proximity service`.

The key difference lies in the fact that the `remote service` returns consistent decisions to the caller but may experience high latency or interruption and unavailability because of network partitioning. In contrast, `proximity service`s are deployed in proximity to the caller, providing low latency as they operate on an eventual consistent basis. This ensures faster decision returns as they synchronize policies. It's important to note that this service can be out of sync, especially in the event of network partitioning.
