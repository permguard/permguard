<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Running the planes

```sh
make cli
make run-control
make run-data
make run-all
```

Default local ports:

| Plane | Public API surface | Telemetry |
| --- | ---: | ---: |
| Control | `127.0.0.1:7556` | `127.0.0.1:7558` |
| Data | `127.0.0.1:7656` | `127.0.0.1:7658` |

The public API surface can serve HTTP routes, gRPC routes, or both. The default configs run HTTP and
gRPC on the same address. To split them, set different `controlPlane.public.http.addr` and
`controlPlane.public.grpc.addr` values, and the same shape under `dataPlane`. To serve only one
protocol, set the other protocol's `enabled` value to `false`.

TLS is configured per plane and per protocol. If an endpoint omits `tls`, it inherits the optional
process-level `public.tls`; if it sets `tls.enabled: false`, that endpoint is plain even when another
endpoint uses TLS. Add `client_ca` to an endpoint TLS block to require mTLS, and `crl` to revoke
client certificates before they expire.

Example: plain HTTP plus mTLS gRPC for the control plane:

```yaml
controlPlane:
  public:
    http:
      enabled: true
      addr: 0.0.0.0:7556
      tls:
        enabled: false
    grpc:
      enabled: true
      addr: 0.0.0.0:7557
      tls:
        cert: tls/grpc-server.pem
        key: tls/grpc-server.key
        client_ca: tls/grpc-clients.pem
        crl: tls/grpc-clients.crl
        min_version: "1.3"
```

When HTTP and gRPC share the same address, they must also share the same TLS policy. Use separate
addresses when one protocol is plain and the other is TLS/mTLS.

Each plane's HTTP routes expose:

- `GET /`
- `GET /version`
- `GET /health`

Each plane's gRPC routes expose:

- gRPC `GetInfo`
- gRPC `GetHealth`

Run the all-in-one runtime:

```sh
task run:all
# or
make run-all
```

Then, from another shell, call the control plane over HTTP:

```sh
curl -fsS http://127.0.0.1:7556/version
curl -fsS http://127.0.0.1:7556/health
```

Call the data plane over HTTP:

```sh
curl -fsS http://127.0.0.1:7656/version
curl -fsS http://127.0.0.1:7656/health
```

Call the control plane over gRPC:

```sh
grpcurl -plaintext \
  -import-path crates/permguard-control-plane/proto \
  -proto permguard/control/v1/control_plane.proto \
  -d '{}' \
  127.0.0.1:7556 \
  permguard.control.v1.ControlPlane/GetInfo
```

Ask it for a decision — the reason the plane exists (the ledger must be
mirrored first, which is what `dataPlane.mirrors` does):

```sh
curl -fsS http://127.0.0.1:7656/.well-known/authzen-configuration
curl -fsS -X POST http://127.0.0.1:7656/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{"zone":"acme","ledger":"main-ledger",
       "subject":{"type":"User","id":"alice"},
       "action":{"name":"read"},
       "resource":{"type":"Document","id":"budget-2026"}}'
# {"decision":true,…}   — and a deny is the same 200 with `false`
```

Call the data plane over gRPC:

```sh
grpcurl -plaintext \
  -import-path crates/permguard-data-plane/proto \
  -proto permguard/data/v1/data_plane.proto \
  -d '{}' \
  127.0.0.1:7656 \
  permguard.data.v1.DataPlane/GetInfo
```

## Developing

```sh
make build
make check
make test
```

The same workflows are available through `Taskfile.yml`, and VS Code launch/tasks are configured for
the CLI, the two standalone planes, and the all-in-one runtime.

## What a surface refuses to spend

Every listener — HTTP, gRPC and telemetry alike — serves inside the same set of bounds, applied in
one place so no surface can be added without them. Each has a default; each can be set in the
`limits:` block of the configuration file or by the matching `PERMGUARD_LIMITS_*` environment
variable.

| Setting | Default | What it stops |
| --- | ---: | --- |
| `connections` | 1024 | opening thousands of sockets and leaving them |
| `connections_per_peer` | 256 | one address holding the whole pool; `0` disables, `peer_exempt` lists addresses or CIDR blocks that skip it |
| `handshake_timeout` | 10s | starting a TLS handshake and never finishing it |
| `header_timeout` | 10s | sending a request head a byte at a time (slowloris) |
| `request_timeout` | 30s | a request, or a handler, that never ends |
| `concurrent_requests` | 256 | arriving faster than they can be served — beyond it, `503` rather than a queue |
| `body_bytes` | 1M | announcing a megabyte and sending a gigabyte |
| `connection_lifetime` | unbounded | a connection becoming permanent; set it to rotate connections behind a balancer |
| `write_stall_timeout` | 30s | a client that stops reading its response |

Idle HTTP/2 connections are pinged every thirty seconds, so a peer whose TCP died without a FIN is
reclaimed in under a minute rather than in hours. Refusals are counted in
`permguard_surface_connections_refused_total`, labelled with which bound said no.

One honest caveat: behind a load balancer the peer address is the balancer's, so the per-address
bound becomes a de-facto global one. There, exempt the balancer's block or set the bound to `0` and
count at the ingress. And none of this is a rate limiter — that needs a notion of who a client *is*
over time, which belongs in front of these planes.
