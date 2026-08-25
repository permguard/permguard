<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quick start

Three profiles, one command each. Every profile below is shown three ways — the installed binary,
`task`, and `make` — so whichever of the three a developer has, they can start a runtime and call it.

## Install the CLI

```sh
cargo install --locked --path crates/permguard-cli    # from this checkout
docker pull permguard/cli:latest                      # or a container, see Docker below
```

A tagged release also ships CLI archives and `deb`/`rpm`/`apk` packages — see [Releasing](release.md).

## Plain HTTP

```sh
task run:all          # or: make run-all
```

Then, from another shell:

```sh
permguard inspect                 # installed binary
task cli -- inspect               # through Taskfile
make cli ARGS=inspect             # through Make
```

```text
control plane
  endpoint: http://127.0.0.1:7556
  status:   ready
  product:  Permguard
  health:   live=true ready=true
  latency:  0ms
...
2 of 2 planes ready, 2 reachable
```

## TLS

The runtime mints its own authority and certificate on first start, under
`.volume/all-in-one-tls/tls`:

```sh
task run-as-tls:all   # or: make run-as-tls-all
```

```sh
permguard --control-endpoint https://127.0.0.1:7556 \
          --data-endpoint https://127.0.0.1:7656 \
          --tls-ca-file .volume/all-in-one-tls/tls/ca.pem \
          inspect

task cli -- --control-endpoint https://127.0.0.1:7556 --data-endpoint https://127.0.0.1:7656 \
            --tls-ca-file .volume/all-in-one-tls/tls/ca.pem inspect

make cli ARGS="--control-endpoint https://127.0.0.1:7556 --data-endpoint https://127.0.0.1:7656 \
               --tls-ca-file .volume/all-in-one-tls/tls/ca.pem inspect"
```

Typing that once is enough — state it and then call bare:

```sh
permguard config set control-plane.endpoint https://127.0.0.1:7556
permguard config set data-plane.endpoint https://127.0.0.1:7656
export PERMGUARD_TLS_CA_FILE="$PWD/.volume/all-in-one-tls/tls/ca.pem"

permguard inspect
```

## Mutual TLS

TLS on HTTP, mutual TLS on gRPC:

```sh
task run-as-mtls:all  # or: make run-as-mtls-all
```

| Surface | Address | Policy |
| --- | ---: | --- |
| control HTTP | `127.0.0.1:7556` | TLS |
| control gRPC | `127.0.0.1:7557` | mutual TLS |
| data HTTP | `127.0.0.1:7656` | TLS |
| data gRPC | `127.0.0.1:7657` | mutual TLS |

That split is deliberate. HTTP is what an operator, a `curl` and a load-balancer probe reach, and
demanding a client certificate from those turns every operator into a certificate holder. gRPC is
what an SDK reaches — a service talking to a service, which is the caller a client certificate can
actually identify. Because the two protocols now carry different TLS policies they need different
addresses: one address serves one policy.

`inspect` speaks HTTP, so it reaches the TLS surface:

```sh
permguard --control-endpoint https://127.0.0.1:7556 \
          --data-endpoint https://127.0.0.1:7656 \
          --tls-ca-file .volume/all-in-one-mtls/tls/ca.pem \
          inspect

task cli -- --control-endpoint https://127.0.0.1:7556 --data-endpoint https://127.0.0.1:7656 \
            --tls-ca-file .volume/all-in-one-mtls/tls/ca.pem inspect
```

The gRPC surface demands a certificate back, and the runtime generated one to test with:

```sh
grpcurl -cacert .volume/all-in-one-mtls/tls/ca.pem \
        -cert .volume/all-in-one-mtls/tls/client.pem \
        -key .volume/all-in-one-mtls/tls/client.key \
        -import-path crates/permguard-control-plane/proto \
        -proto permguard/control/v1/control_plane.proto \
        -d '{}' 127.0.0.1:7557 permguard.control.v1.ControlPlane/GetInfo
```

The same call without `-cert`/`-key` never reaches the application: the handshake is refused. When a
Permguard endpoint asks the CLI for a certificate it does not have, the report says so by name —
`tls_client_certificate_required` — rather than as a network error.

## One plane at a time

Each profile also runs a single plane, which is how the planes are deployed in anger:

```sh
task run:control          task run-as-tls:control          task run-as-mtls:control
task run:data             task run-as-tls:data             task run-as-mtls:data
```

Make has the same six: `run-control`, `run-data`, `run-as-tls-control`, `run-as-tls-data`,
`run-as-mtls-control`, `run-as-mtls-data`. Standalone planes keep their own working directories, so
the control plane's authority is under `.volume/control-plane-tls/tls` and the data plane's under
`.volume/data-plane-tls/tls` — a certificate from one is not the certificate of the other. With only
one plane running, `inspect` reports the other as `unreachable` and exits `2`, which is exactly what
"up, but not all of it" should look like.
