<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The command line

```sh
task cli -- version
task cli -- config show
task cli -- inspect
```

Every command takes the same global flags:

| Flag | Meaning |
| --- | --- |
| `-o, --output` | `terminal`, `json`, or `yaml` (`yml`) |
| `-v, --verbose` | narrate what is being done, on stderr |
| `-w, --workdir` | directory relative paths are resolved against (default `.`) |
| `--config` | configuration file to use instead of `~/.permguard/config.yml` |
| `--control-endpoint` | where the control plane is reached |
| `--data-endpoint` | where the data plane is reached |
| `--tls-ca-file` | authority the endpoint's certificate is checked against (PEM) |
| `--tls-cert-file` | our own certificate, for mutual TLS (PEM) |
| `--tls-key-file` | the key belonging to that certificate (PEM) |
| `--tls-server-name` | name to check the certificate against, when it is not the endpoint's host |
| `--tls-skip-verify` | accept any server certificate — insecure, development only |

A command's output is the command's answer: the product banner appears only where identity is the
point — the bare `permguard`, `--help`, and `version`. Every other command prints its report and
nothing else, so `$(permguard config get …)` captures something usable and a listing starts at the
first line. Narration goes to stderr, so `permguard inspect -o json --verbose | jq` works.

## Configuration

Settings are resolved through four layers. A value is taken from the first that states it:

1. a **flag**, which is what the operator just typed;
2. the **environment**, which is how a deployment or a CI job states a context;
3. the **configuration file**, which is how a person states their own context once;
4. the **default** compiled in, which is a local development runtime.

```sh
task cli -- config show                                          # every setting, and where it came from
task cli -- config get control-plane.endpoint                    # one value, bare
task cli -- config set control-plane.endpoint https://control.example.com:7556
task cli -- config reset control-plane.endpoint                  # or reset, for all of them
```

| Setting | Environment variable | Default |
| --- | --- | --- |
| `control-plane.endpoint` | `PERMGUARD_CONTROL_PLANE_ENDPOINT` | `http://127.0.0.1:7556` |
| `data-plane.endpoint` | `PERMGUARD_DATA_PLANE_ENDPOINT` | `http://127.0.0.1:7656` |

The file is `~/.permguard/config.yml`, created by the first `config` command in a directory only the
user can read. It holds only what was set: a setting nobody stated is absent rather than pinned to
today's default, so a default that changes in a later release reaches a file written by an earlier
one. `config show` reports which layer each value came from — the question an operator actually has
when a command talks to the wrong server is not what the value is, but where it comes from.

`config reset` resets the *file*. A value that comes from the environment goes on coming from the
environment, and the report says so.

## TLS and mutual TLS

The endpoint's scheme carries the transport: `http://` is plain, `https://` is TLS. Mutual TLS is not
a third scheme — it is `https://` plus a certificate of our own:

```sh
# TLS, against a private authority
task cli -- config set control-plane.endpoint https://control.example.com:7556
permguard --tls-ca-file ca.pem inspect

# mutual TLS
permguard --tls-ca-file ca.pem --tls-cert-file client.pem --tls-key-file client.key inspect

# a development runtime with a self-signed certificate
permguard --control-endpoint https://127.0.0.1:7556 --tls-skip-verify inspect
```

Without `--tls-ca-file` the certificate is checked against the platform's trust store. A certificate
that is valid but names a different host than the endpoint — reaching a server by IP address — is
what `--tls-server-name` is for, and it keeps verification on; `--tls-skip-verify` turns verification
off entirely and says so on stderr every time.

## Inspect

`inspect` probes every plane and reports each one, whether it answers or not: a plane that is down is
a line in the report, not a failure of the command. A plane that answers is asked for `/health` as
well as `/version`, so a plane that is listening is not therefore reported as serving.

| Status | Meaning | What an operator does |
| --- | --- | --- |
| `ready` | answers, and is willing to be sent work | nothing |
| `degraded` | answers, and is not willing to be sent work: starting up, draining, or unable to say | wait |
| `unhealthy` | answers, and reports itself wedged | restart it |
| `unreachable` | did not answer | start it, or fix the endpoint |

A status other than `ready` carries a stable `reason` code alongside the sentence: `not_ready`,
`not_live`, `health_unreadable`, `connection_refused`, `timeout`, `resolve_failed`, `connect_failed`,
`transport_failed`, `http_status`, `malformed_response`, `decode_failed`, `tls_expected`,
`tls_handshake_failed`, `tls_client_certificate_required`, `tls_material_unreadable`,
`tls_no_trust_anchors`, `tls_client_identity_incomplete`, `tls_server_name_invalid`. The sentence is
free to be reworded; the code is an interface, so a runbook branches on the code.

Every entry also carries `latency_ms`, and the report carries the UTC `checked_at` — a report worth
attaching to an incident says when it looked and how long it waited. `--timeout` bounds each request,
in seconds, and bounds connecting as well as reading.

## Asking for a decision

`permguard check` asks a data plane whether something is allowed. A document,
or the flags that describe one:

```sh
permguard check -f request.json                                        # the profile's payload
cat request.json | permguard check -f -                                # from a pipe
permguard check --subject user:alice --action read --resource document:budget
permguard check -f request.json --zone acme --ledger main-ledger -o json
permguard check -f request.json --ignore-workspace                     # send it exactly as written
```

Which store the question is about follows one rule, shared with every command
that needs it: **flags win, then the workspace, then the document's own
`zone`/`ledger`**. Inside a checked-out ledger, `check` asks about that ledger —
`--ignore-workspace` turns that off. The endpoint follows the ordinary layers,
from `--data-endpoint` down to `http://127.0.0.1:7656`.

A **deny exits 0**: it is an answer, and a script branches on `decision` rather
than on an exit code that could not tell a deny from a PDP that is down. Only a
request that could not be evaluated is a failure. See
[Answering decisions](authorization-check.md) for the contract and the request
shape.

## Reading what was decided

`permguard decisions` reads the decision log a data plane recorded and a
control plane keeps.

```sh
permguard decisions list --zone acme --ledger main-ledger        # a page, oldest first
permguard decisions tail --follow                                # as they arrive
permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d                         # one decision, in full
permguard decisions export --from <offset> -o json               # bulk, resumable
permguard decisions list --verify --keys data-plane.jwks         # check it yourself
permguard decisions list --pdp data-plane-eu-1 --instance 0193…  # one producer's whole stream
permguard decisions list --control-endpoint grpc://control:7557  # either transport
```

**The position belongs to you.** The control plane keeps no cursor: the offset
a page returns is opaque, and presenting it is how you continue. Two people
tailing the same ledger do not interfere, and no reader can back-pressure the
plane that is deciding. An offset is **bound to the scope that issued it** — one
from `acme` presented under another zone is refused rather than reinterpreted.

**Falling behind retention is answered, not discovered.** An offset older than
what the store still holds fails with `offset_expired` and names the oldest
offset available, so a consumer returning from a long outage learns that it lost
records and where the remaining ones begin, instead of resuming from the wrong
place and reporting a clean run.

**What `--verify` checks, and which proof it uses.** The proof is chosen by the
scope, because only one of the two applies:

| Scope | Proof | Why |
| --- | --- | --- |
| a producer stream (`--pdp/--instance`) | the **chain** | a contiguous history, so `prev(N) = digest(N−1)` verifies across it |
| one tenant (`--zone/--ledger`) | **inclusion paths** | the page is a subsequence — the records in between are another tenant's — so a chain check would report arithmetic as tampering |

With `--keys` (the producer's published set from its `/data-plane/keys`, saved
to a file) it also checks that the batches were signed by a key that set
publishes, which is what makes the answer independent of the server that served
it. The report always states which of the two ran and whether signatures were
checked: a "verified" that quietly skipped them would be worse than no
verification at all.

Scope resolution is the shared rule — flags, then the workspace — and
`--pdp`/`--instance` reads one producer's whole stream instead, which is every
tenant's decisions and the only scope a producer chain verifies end to end
from.

## Reclaiming space in a workspace

The mirror under `.permguard/objects` only grows: an interrupted pull leaves
objects no checkpoint names, a snapshot nobody applied leaves a tree, an edit
leaves the version the head has moved past.

```sh
permguard objects prune --dry-run          # what would go, and how much it weighs
permguard objects prune                    # take it
permguard objects prune --dry-run -o json  # for a script
```

It keeps everything the **tracked checkpoint** or the **staged snapshot**
reaches, and removes the rest. There is no grace period and none is needed: a
mutating command holds the workspace lock, so a fetch in flight and a prune
cannot look at the same mirror at once. If a closure has a hole — something
referenced and missing — the prune is refused and points at `permguard verify`:
a walk that cannot be completed cannot tell "unreachable" from "unreachable
*from here*".

Nothing is lost either way: every object here is a verified copy of something
the remote holds, and the next pull fetches back whatever a checkout needs. The
server keeps its own ledgers tidy on a schedule — see
[Git-like storage](gitlike-object-model.md).

## Exit statuses

They are an interface, and they are tested:

| Status | Meaning |
| ---: | --- |
| `0` | the command succeeded, and every plane it asked about is ready |
| `1` | no plane answered — there was nothing to inspect |
| `2` | planes answered, and not all of them are ready |
| `64` | the command line, or something it named, was wrong (`EX_USAGE`) |
| `70` | the command failed for an internal reason (`EX_SOFTWARE`) |

The distinction between `1` and `2` is what makes `inspect` usable as a deployment gate: waiting for
`0` waits for a runtime that is actually serving, and tells "not up yet" apart from "up, still
draining" while it waits.

```sh
until permguard inspect >/dev/null; do sleep 1; done
```

## Zones and ledgers

> **Why `ledgers` is flat, and what the old CLI did.** The Go CLI split the word in two:
> `authz ledgers` (plural) managed the *remote* resource, while a bare `ledger` (singular) listed
> what the *local workspace* tracked — two meanings a single `s` apart. Here `ledgers` is the remote
> resource, full stop, at the top level like `zones`. When the workspace arrives, its local views
> will live in workspace vocabulary (`remote`, `status`-style commands, as git does) — never in a
> near-homonym of the resource name.

A **zone** is the isolation boundary — the tenant. A **ledger** is a named container inside a zone;
what a ledger holds is a design still being made, so today it is identity only. Both live on the
control plane, which serves them identically over HTTP (`/v1/zones…`) and gRPC
(`permguard.control.v1.ZoneCatalog`).

```sh
permguard zones create acme
permguard zones list                             # everything
permguard zones list --page 2 --size 50          # one page at a time
permguard zones update acme --name acme-eu
permguard zones delete acme-eu

permguard completion zsh > "${fpath[1]}/_permguard"   # shell completion: bash, zsh, fish

permguard ledgers create --zone acme-eu policies
permguard ledgers list   --zone acme-eu
permguard ledgers delete --zone acme-eu policies
```

Everything that refers to an existing zone or ledger accepts **the name or the id** (`--zone-id` is
accepted as an alias of `--zone`, for hands trained on the Go CLI): ids are GUIDs
minted by the server and permanent; names are yours and free to change. The two never collide,
because a name shaped like a GUID is refused at creation.

Names are strict on purpose: `a-z`, `0-9`, `-` and `_`, starting with a letter, ending alphanumeric,
3–63 characters — every character unreserved in a URL, so a name never needs encoding anywhere.
Uppercase is refused rather than converted. Zone names are unique across the deployment; ledger
names are unique within their zone.

Every refusal, on every API and both protocols, is the same three fields:

```json
{ "class": "conflict", "code": "name_taken", "message": "the name `acme` is already taken…" }
```

The **class** is the closed set a client switches on (`validation`, `conflict`, `not_found`,
`unavailable`, `internal`) and decides the HTTP status and the gRPC code by itself; the **code** is
the stable name of the exact condition; the **message** is for a person and free to be reworded.
Over gRPC the class and code also ride as metadata (`x-permguard-error-class`,
`x-permguard-error-code`). The CLI exits `64` for anything the operator can fix — validation,
conflicts, lookups — and `70` for the rest. Deleting a zone that still holds ledgers is refused;
delete the ledgers first.

How much an `internal` error says about the inside follows `public.error_detail` (`full` or
`minimal`); unset, `development_mode` decides. The server's own log always carries the full detail.
