<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Kubernetes

```sh
helm install permguard ./charts/permguard --namespace permguard --create-namespace
```

For a baseline production shape:

```sh
helm install permguard ./charts/permguard \
  --namespace permguard \
  --create-namespace \
  --values charts/permguard/values-production.yaml
```

The defaults deploy the **two planes separately**, which is how they are meant to run: they scale for
different reasons — the data plane with request volume, the control plane with administration — and a
single deployment can only be sized for one of them.

```sh
# the single-process runtime instead, for a small installation or a test environment
helm install permguard ./charts/permguard \
  --set allInOne.enabled=true \
  --set controlPlane.enabled=false \
  --set dataPlane.enabled=false
```

The chart accepts exactly four shapes — both planes (the default), either plane alone, or the
all-in-one alone — and refuses the rest **at template time**: the all-in-one beside a standalone
plane, and the values file that enables nothing. The two runtime shapes are mutually exclusive: the all-in-one *is* both
planes in one process, so enabling it beside a standalone plane is refused with an error naming the
fix — never discovered as two issuers fighting in a cluster.

## What it creates

| Object | Per plane | Why |
| --- | --- | --- |
| `Deployment` | one | `maxUnavailable: 0`, so a rollout never removes a serving replica before its replacement is ready |
| `Service` | one | the public surface: HTTP, and gRPC when it is on a separate port |
| `Service` (telemetry) | one | **separate on purpose** — see below |
| `ConfigMap` | one | the plane's configuration, hashed into the pod annotations so a change rolls the pods |
| `PodDisruptionBudget` | one | a node drain cannot take the last replica |
| `HorizontalPodAutoscaler` | optional | `autoscaling.enabled` |
| `PersistentVolumeClaim` | optional | `persistence.enabled` |
| `NetworkPolicy` | one | default-on: ingress only on the served ports; `networkPolicy.public.from` and `networkPolicy.telemetry.from` narrow who reaches each surface, and an empty list means any peer |
| `ServiceMonitor` | optional | `metrics.serviceMonitor.enabled`, needs the Prometheus Operator |
| `PrometheusRule` | optional | `metrics.prometheusRule.enabled`, needs the Prometheus Operator |

**Two services per plane** is the decision worth understanding. The public service is what callers
reach; the telemetry service is what Prometheus and the kubelet reach. Keeping them apart is what lets
a NetworkPolicy, an ingress or a mesh allow one without allowing the other — and the probes point at
the telemetry port for the same reason a load balancer's health check should not share a connection
limit with client traffic: under load, the first thing to fail would be the check that says whether
anything is wrong.

## Two defaults to look at before production

**`autogenerate: false`.** A plane with autogeneration on mints its own certificate authority and
signing keys when it finds none. That is exactly right on a laptop and exactly wrong in a cluster,
where the material should come from something that manages it. The chart therefore ships it off.

**`persistence.enabled: false`.** Each pod keeps its keys and its audit trail in an `emptyDir`, so a
restart starts from nothing. Fine for a test environment; wrong for anything issuing tokens somebody
else verifies, and wrong for an audit trail that has to survive a rollout. `helm install` prints this
as a note rather than leaving it to be discovered.

`charts/permguard/values-production.yaml` turns persistence on, renders a `ServiceMonitor` and
`PrometheusRule`, tightens anti-affinity, adds topology spread, and narrows the example
NetworkPolicy to application and monitoring namespaces. The namespace names and resource sizes are
still deployment inputs, not product constants.

## What every pod is not allowed to do

The images were built for this, so it is the default rather than a hardening guide: a static binary
from `scratch`, running as `65532`, with a read-only root filesystem, every capability dropped,
`allowPrivilegeEscalation: false`, the `RuntimeDefault` seccomp profile, and no Kubernetes API token
mounted — nothing here talks to the API server, so a credential for it would be a credential in a
container for no reason.

`terminationGracePeriodSeconds: 30` is the drain: on `SIGTERM` readiness goes false immediately,
routing stops, and connections in flight are given that long to finish.

## Both registries

```sh
helm install permguard ./charts/permguard --set image.registry=ghcr.io
```

Docker Hub and the GitHub Container Registry carry the same digests. One `--set` moves all four
images, so a cluster that mirrors one of them does not have to override each name.

## Checking it

```sh
kubectl --namespace permguard port-forward svc/permguard-control-plane 7556:7556 &
kubectl --namespace permguard port-forward svc/permguard-data-plane 7656:7656 &
permguard inspect
```

`inspect` reports each plane as `ready`, `degraded`, `unhealthy` or `unreachable` — the same
distinction the probes make, from outside the cluster. See [the command line](cli.md).
