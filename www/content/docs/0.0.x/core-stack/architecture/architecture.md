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
weight: 10101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

**Permguard** consists of several services, which can be deployed either on a single instance using the `all-in-one` distribution, or individually using separate distributions for each service."

<div style="text-align: center">
  <img alt="Permguard Policies" src="/images/diagrams/d6.webp"/>
</div>

## Zone Administration Point (ZAP)

The `Zone Administration Point (ZAP)` serves as the central repository for managing zone information and configurations. Furthermore, it provides an administration API.

## Policy Administration Point (PAP)

The `Policy Administration Point (PAP)`  serves as the central repository for managing the zone policies. Furthermore, it provides an administration API.

## Policy Information Point (PIP)

The `Policy Information Point (PIP)` is the service responsible for providing additional information to the `Policy Decision Point (PDP)` to make informed decisions.

## Policy Decision Point (PDP)

The `Policy Decision Point (PDP)` is the component responsible for evaluating policies and producing authorization decisions.  
It can operate either as a `remote data-plane` or as a `proximity data-plane`:

- A `remote data-plane` returns fully consistent decisions, but its availability and latency depend on network connectivity.  
Network partitions, congestion, or outages can introduce delays or make the PDP temporarily unreachable, or
- A `proximity data-plane`, instead, is deployed close to the caller and operates in an eventually consistent model.  
It provides faster and more resilient decisions because it evaluates policies locally, synchronizing updates asynchronously.  
This also means that, during network partitions, a proximity PDP may operate with slightly outdated policies until connectivity is restored.
