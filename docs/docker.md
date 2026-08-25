<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Containers

Every release publishes the same four images to **both** Docker Hub and the GitHub Container
Registry, from one tag:

| Image | Docker Hub | GitHub Container Registry |
| --- | --- | --- |
| CLI | `permguard/cli` | `ghcr.io/permguard/cli` |
| All-in-one | `permguard/all-in-one` | `ghcr.io/permguard/all-in-one` |
| Control plane | `permguard/control-plane` | `ghcr.io/permguard/control-plane` |
| Data plane | `permguard/data-plane` | `ghcr.io/permguard/data-plane` |

Tags are the version (`0.1.0`), the minor series (`0.1`), and `latest`.

```sh
docker pull permguard/all-in-one:latest
docker pull ghcr.io/permguard/all-in-one:latest    # the same image, the other registry
```

Run the all-in-one runtime, and call it with the CLI image:

```sh
docker run --rm --name permguard \
  -p 127.0.0.1:7556:7556 -p 127.0.0.1:7656:7656 -p 127.0.0.1:7558:7558 \
  -v "$PWD/crates/permguard-all-in-one/config.docker.yml:/etc/permguard/config.yml:ro" \
  permguard/all-in-one:latest

# On Linux the CLI container can share the host's network:
docker run --rm --network host permguard/cli:latest inspect

# On macOS and Windows, name the host instead:
docker run --rm permguard/cli:latest \
  --control-endpoint http://host.docker.internal:7556 \
  --data-endpoint http://host.docker.internal:7656 \
  inspect
```

The CLI image keeps its configuration under `/var/lib/permguard`, so a volume there makes
`config set` outlive the container:

```sh
docker run --rm -v permguard-cli:/var/lib/permguard permguard/cli:latest \
  config set control-plane.endpoint http://host.docker.internal:7556
docker run --rm -v permguard-cli:/var/lib/permguard permguard/cli:latest config show
```

It runs as an unprivileged user from `scratch`, and carries a certificate bundle because it is the
one Permguard image that dials out: a public TLS endpoint has to be checked against something.

## The compose lab

The lab is profile-driven, so the same file serves three different situations:

| Command | What starts |
| --- | --- |
| `task lab:up` | both planes, Prometheus, Grafana, Loki |
| `task lab:all` | the all-in-one runtime **instead of** the two planes (mutually exclusive — combining the profiles fails at the port bind) |
| `task lab:observability` | **only** Prometheus, Grafana and Loki — to watch planes you started with `task run:all` |
| `task lab:clean` | stop everything and discard the stored metrics and logs |

```sh
task lab:up                  # or: make lab-up
task lab:logs SERVICE=grafana
task lab:down                # stop, keep the data
task lab:clean               # stop AND discard the data — dashboards start empty
```

Prometheus is configured for the compose services **and** for the host at the same time, so nothing
needs reconfiguring when you switch between running the planes in containers and running them from
your editor. See [Observability](observability.md) for the dashboards, every metric, and the
`host.docker.internal` detail.

Under the covers it is `docker compose -f docker-compose.lab.yml --profile <profile> up`; the tasks
exist so the profile names do not have to be remembered. Because every service now belongs to a
profile, `docker compose up` with no profile starts nothing — which is deliberate: it is the only way
one file can hold both "the whole lab" and "the monitoring only".

Published ports, all on loopback and all overridable:

| Service | Port | Variable |
| --- | ---: | --- |
| Grafana | `7590` | `PERMGUARD_GRAFANA_PORT` |
| Prometheus | `7591` | `PERMGUARD_PROMETHEUS_PORT` |
| Loki | `7592` | `PERMGUARD_LOKI_PORT` |
| Control plane | `7556` | `PERMGUARD_CONTROL_HTTP_PORT` |
| Data plane | `7656` | `PERMGUARD_DATA_HTTP_PORT` |

The lab's planes are built from source by `docker-compose.lab.yml`, not pulled: it is for testing what
is in the working tree. The images in the table above are what a release publishes.
