---
pageClass: pg-page-concepts
title: Server Operations
description: Discover and inspect the Planes, operate a Server Host through its listener, and restore, migrate and verify a stopped Server's volume with the permguard CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Run and repair the Servers.</h1>
  <p>Find the Planes, operate a Server Host through its listener, and work on a stopped Server's volume offline.</p>
</div>

These are the operator's commands.
`discover` and `inspect` find out what is running; the `host` family works on a Server Host through its listener at `--host-endpoint`, or offline on its volume at `--volume`.
`restore`, `migrate` and `backup verify` work only on a stopped Server's volume, and `gc` and `reclaim` free storage through the Host listener.

## version

Reports this CLI's version and the build it came from; `-V` and `--version` say the same.

```sh
permguard version [OPTIONS]
```

```sh
permguard version -o json
```

## completion

Prints shell completions for `bash`, `elvish`, `fish`, `powershell` or `zsh`; add them to your shell's configuration to complete commands and flags.

```sh
permguard completion [OPTIONS] <SHELL>
```

```sh
permguard completion zsh > "${fpath[1]}/_permguard"
permguard completion bash >> ~/.bashrc
```

## discover

Walks the discovery chain from one address: the process, each Plane, each interface.

```sh
permguard discover [OPTIONS] <URL>
```

| Argument or flag      | Meaning                                                        |
| --------------------- | -------------------------------------------------------------- |
| `<URL>`               | the address to start from, `scheme://host:port`, HTTP or HTTPS |
| `--timeout <SECONDS>` | how long to wait for one request; 5 by default                 |

```sh
permguard discover http://127.0.0.1:5443
permguard discover https://control.example:6443 -o json
```

## inspect

Reports what each Permguard Plane is, and whether it is willing to be sent work.
It asks the Control Plane and the Data Plane the CLI is configured with.

```sh
permguard inspect [OPTIONS]
```

| Flag                  | Meaning                                        |
| --------------------- | ---------------------------------------------- |
| `--timeout <SECONDS>` | how long to wait for one request; 5 by default |

```sh
permguard inspect
```

`inspect` exits 0 when every Plane is ready, 2 when a Plane answered and is not ready, and 1 when none answered.

## host

Works on a Server Host: its identity, keys, members, audit, streams and plans, and offline its volume.
Most subcommands reach the Host listener; the ones marked volume work offline, on a stopped Server's volume named by `--volume`.

| Subcommand                             | Reaches       | What it governs                                                    |
| -------------------------------------- | ------------- | ------------------------------------------------------------------ |
| `host status`, `host config`           | Host listener | the phase of the Host, every Plane and service; its configuration  |
| `host identity show` `verify` `rotate` | Host listener | the Host identity and its key                                      |
| `host identity pin`                    | local         | the local pre-enrollment pin store                                 |
| `host identity provision` `reset`      | volume        | provisioning and emergency reset                                   |
| `host grants`                          | volume        | the Host's one recovery principal                                  |
| `host members`                         | Host listener | membership enrollment, approval and lifecycle                      |
| `host keys`                            | Host listener | key rings, rotation, revocation and the verification bundle        |
| `host audit`                           | Host listener | audit trails, signed checkpoints and exports                       |
| `host streams`                         | Host listener | the streams the Host produces and consumes                         |
| `host plans`                           | Host listener | plan receipts and the countersignature dual control requires       |
| `host backup`                          | Host listener | application-consistent backups                                     |
| `host holds`                           | volume        | legal and incident holds that keep ledgers from garbage collection |

Every `host` subcommand also takes `--server-config <FILE>`: the server's configuration file, read with the environment as the server reads them, which says where the volume's keys are kept and how they are opened.
Without it they are the `development` custody's plaintext files.

## Plan, then run

What cannot be undone happens in two steps.

<div class="pgx-cli-steps" role="img" aria-label="A destructive operation in two steps: plan writes what would change to a new owner-only file and changes nothing; where dual control requires it, a second principal approves the plan with host plans approve; run then carries out exactly that plan from its confirm file.">
  <article><b>01</b><strong>Plan</strong><span><code>… plan --out &lt;file&gt;</code>: nothing changes</span></article>
  <article class="pgx-cli-steps__warm"><b>02</b><strong>Approve</strong><span><code>host plans approve</code> where dual control requires it</span></article>
  <article class="pgx-cli-steps__accent"><b>03</b><strong>Run</strong><span><code>… run --confirm-file &lt;file&gt;</code></span></article>
</div>

`host identity reset`, `host members revoke`, `host keys revoke`, `restore`, `migrate` and `gc objects` work this way.
The plan is written to a new file only its owner reads, and `restore`, `migrate` and `host identity reset` refuse a run when the volume moved since its plan.
A principal never approves its own plan.

## host status and config

`host status` prints the phase of the Host, every Plane and every service, with reasons, and the assurance profile with its added controls and relaxations.
`host config show --effective` prints the configuration the Host runs with, each value with the layer it came from, secrets masked.

```sh
permguard host status [OPTIONS]
permguard host config show [OPTIONS] --effective
```

```sh
permguard --host-endpoint grpcs://host.example:9443 host status -o json
permguard host config show --effective -o yaml
```

## host identity

The Host identity: its id, subject, epoch and fingerprints.

```sh
permguard host identity show [OPTIONS]
permguard host identity verify [OPTIONS] --fingerprint <FINGERPRINT> <URL>
permguard host identity rotate [OPTIONS] --expected-epoch <EXPECTED_EPOCH>
permguard host identity pin add [OPTIONS] --host-id <HOST_ID> --fingerprint <FINGERPRINT> <URL>
permguard host identity pin list [OPTIONS]
permguard host identity pin remove [OPTIONS] --host-id <HOST_ID> <URL>
permguard host identity provision [OPTIONS]
permguard host identity reset plan [OPTIONS] --reason <REASON> --out <FILE>
permguard host identity reset run [OPTIONS]
```

| Command      | What it does                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| `show`       | prints the identity; the witness is printed at provisioning only                                       |
| `verify`     | proves a peer Host's identity and compares its first fingerprint with the one expected out of band     |
| `rotate`     | rotates the identity key to the next epoch: the current key signs the succession                       |
| `pin add`    | adds, or exactly replays, one endpoint and Host identity pin                                           |
| `pin list`   | lists the local pins                                                                                   |
| `pin remove` | removes one exact endpoint and Host identity pin                                                       |
| `provision`  | offline: required before the first start from the `production` profile up; written once                |
| `reset plan` | offline, in an emergency only: every live membership and what the reset does to it, written to `--out` |
| `reset run`  | offline: runs the reset the plan in `--confirm-file` describes, refused when the volume moved since    |

| Flag                          | Meaning                                                                                 |
| ----------------------------- | --------------------------------------------------------------------------------------- |
| `--fingerprint <FINGERPRINT>` | `verify`: the SHA-256 fingerprint expected; `pin add`: the pinned epoch-1 fingerprint   |
| `--expected-epoch <N>`        | `rotate`: the epoch `show` printed; a rotation from another is refused                  |
| `--host-id <HOST_ID>`         | `pin`: the peer Host identity UUID                                                      |
| `--suite <SUITE>`             | `provision`: the identity key's suite; `pg-ed25519-sha256-v1` by default                |
| `--if-missing`                | `provision`: provisions only a volume with no identity yet, what an init container runs |
| `--reason <REASON>`           | `reset plan`: why, kept in the plan                                                     |

```sh
permguard host identity show
permguard host identity rotate --expected-epoch 1
permguard host identity verify https://peer.example:9443 --fingerprint sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
permguard host identity provision --volume /var/lib/permguard
```

`provision` prints the witness to keep outside the volume and give the server as `host.identity.witness`.

## host grants

Commits the Host's one recovery principal, offline, by the SHA-256 fingerprint of its certificate.
That certificate holds the per-Host operations on its own Host API.

```sh
permguard host grants bootstrap [OPTIONS] --fingerprint <FINGERPRINT>
```

| Flag                          | Meaning                                                              |
| ----------------------------- | -------------------------------------------------------------------- |
| `--fingerprint <FINGERPRINT>` | the certificate fingerprint, 64 hex characters, optionally `sha256:` |

```sh
permguard host grants bootstrap --volume /var/lib/permguard --fingerprint sha256:ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
```

It is written once: a second bootstrap naming the same fingerprint is the first, one naming another is refused.

## host members

Membership enrollment, approval and lifecycle on the Host listener: a coordinator invites, a member joins, and the coordinator approves.

```sh
permguard host members invite create [OPTIONS] --selector <SELECTOR> --tasks <FILE>
permguard host members invite list [OPTIONS]
permguard host members invite revoke [OPTIONS] <ID>
permguard host members join [OPTIONS] <COORDINATOR_URL>
permguard host members pending [OPTIONS]
permguard host members approve [OPTIONS] --expected-revision <EXPECTED_REVISION> <ID>
permguard host members reject [OPTIONS] --expected-revision <EXPECTED_REVISION> --reason <REASON> <ID>
permguard host members record [OPTIONS] --expected-revision <EXPECTED_REVISION> <ID>
permguard host members list [OPTIONS]
permguard host members get [OPTIONS] <ID>
permguard host members sync [OPTIONS] <ID>
permguard host members suspend [OPTIONS] --expected-revision <EXPECTED_REVISION> --reason <REASON> <ID>
permguard host members resume [OPTIONS] --expected-revision <EXPECTED_REVISION> --reason <REASON> <ID>
permguard host members fence [OPTIONS] --expected-revision <EXPECTED_REVISION> --reason <REASON> <ID>
permguard host members revoke plan [OPTIONS] --reason <REASON> --out <FILE> <ID>
permguard host members revoke run [OPTIONS] --confirm-file <FILE> <ID>
permguard host members sessions [OPTIONS] [ID]
permguard host members verify [OPTIONS] <ID>
```

| Command                        | What it does                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------- |
| `invite create`                | creates a one-time invitation and prints its private handoff once                     |
| `invite list`, `invite revoke` | lists invitations without their tokens; revokes an unused one                         |
| `join`                         | on the member: joins a coordinator with the invitation handoff file                   |
| `pending`                      | lists pending enrollment requests                                                     |
| `approve`, `reject`            | approves, and optionally narrows, or rejects a pending membership                     |
| `record`                       | renames a member or changes its groups                                                |
| `list`, `get`                  | lists memberships; gets one                                                           |
| `sync`                         | on the member: fetches the coordinator's manifests, activating an approved membership |
| `suspend`, `resume`, `fence`   | suspends or resumes a membership; fences it and all its sessions                      |
| `revoke plan`, `revoke run`    | revokes a membership in two steps                                                     |
| `sessions`                     | lists live task sessions, for one member or for all                                   |
| `verify`                       | proves a member now, or schedules its next inbound proof                              |

| Flag                               | Meaning                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| `--selector <SELECTOR>`            | `invite create`: the maximum resource selector the member may receive           |
| `--tasks <FILE>`                   | `invite create`: a closed JSON array of membership tasks                        |
| `--expires <EXPIRES>`              | `invite create`: the invitation's expiry, RFC 3339                              |
| `--expect-fingerprint <FP>`        | `invite create`: the member's epoch-1 fingerprint expected out of band          |
| `--min-assurance <PROFILE>`        | `invite create`: the minimum assurance profile the member must prove            |
| `--coordinator-address <URL>`      | `invite create`: where members reach this Host, when not where this command did |
| `--pin-fingerprint <FP>`           | `join`: the coordinator's epoch-1 fingerprint received out of band              |
| `--name <NAME>`, `--group <GROUP>` | the member's name, `a-z`, `0-9`, `-`, `_`, `.`; a group, repeated for several   |
| `--narrow <FILE>`                  | `approve`: a closed JSON `NarrowView` file                                      |
| `--assurance-result <FILE>`        | `approve`: a closed JSON `AssuranceOffer` file                                  |
| `--expected-revision <N>`          | the membership revision the operator read                                       |
| `--reason <REASON>`                | the accountable reason for the transition                                       |

```sh
permguard host members invite create --selector zone/acme/ledger/main --tasks tasks.json
permguard --token-file invitation.json host members join https://coordinator.example:9443 --pin-fingerprint sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
permguard host members pending
permguard host members approve 0198f2aa-0000-7000-8000-000000000002 --expected-revision 1
permguard host members revoke plan 0198f2aa-0000-7000-8000-000000000002 --reason retired --out revoke.json
permguard host members revoke run 0198f2aa-0000-7000-8000-000000000002 --confirm-file revoke.json
```

Without `--pin-fingerprint`, `join` requires an exact local pin for the coordinator's URL and Host id: see `host identity pin add`.

A Host started with `PERMGUARD_HOST_JOIN_INVITATION_FILE` and `PERMGUARD_HOST_JOIN_PIN_FINGERPRINT` joins on its own when it starts, with `PERMGUARD_HOST_JOIN_NAME` and `PERMGUARD_HOST_JOIN_GROUPS` when the invitation leaves them open.
The pinned fingerprint proves the coordinator's identity, and the Host listeners' TLS still has to hold beneath it: each Host checks the other's certificate.
The member checks the coordinator's server certificate under its own `admin.tls.client_ca`, and the coordinator checks the member's client certificate under its own `admin.tls.client_ca`.
With `autogenerate` each Host makes its own authority, so both need a bundle of the two:

```sh
cat coordinator/tls/ca.pem member/tls/ca.pem > hosts-ca.pem
```

```yaml
admin:
  tls:
    cert: tls/server.pem
    key: tls/server.key
    client_ca: hosts-ca.pem
```

The autogenerated server certificate names only `localhost` and `127.0.0.1`: Hosts on other machines or containers present certificates issued for the names they are reached by.
A join that fails on this trust logs `host.join_retry` with a `hint` naming the side whose authority is not trusted and the setting to change.

## host keys

The Host's key rings: their keys, epochs and bindings, rotation, revocation and the verification bundle.

```sh
permguard host keys list [OPTIONS]
permguard host keys show [OPTIONS] <RING>
permguard host keys rotate [OPTIONS] --expected-epoch <EXPECTED_EPOCH> <RING>
permguard host keys revoke plan [OPTIONS] --reason <REASON> --out <FILE> <RING> <KID>
permguard host keys revoke run [OPTIONS] --confirm-file <FILE> <RING>
permguard host keys bundle export [OPTIONS] --resource <RESOURCE> --out <FILE>
```

| Command         | What it does                                                                                         |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| `list`          | lists the key rings the Host composes, with their epochs and key counts                              |
| `show`          | prints one ring's public keys, epoch and binding                                                     |
| `rotate`        | rotates a ring: its next key is prepublished, then activated                                         |
| `revoke plan`   | plans a key's revocation, a terminal compromise transition, and writes its private confirmation file |
| `revoke run`    | runs a planned key revocation                                                                        |
| `bundle export` | writes a resource's signed verification bundle, every page at one frontier, to a new owner-only file |

| Flag                         | Meaning                                                          |
| ---------------------------- | ---------------------------------------------------------------- |
| `--expected-epoch <N>`       | the ring's epoch the operator read; a ring that moved is refused |
| `--reason <REASON>`          | `revoke plan`: why the key is revoked                            |
| `--compromised-at <INSTANT>` | `revoke plan`: since when the key is held compromised, RFC 3339  |
| `--resource <RESOURCE>`      | `bundle export`: the resource, in the Host API's grammar         |

```sh
permguard host keys list
permguard host keys show host.operations
permguard host keys rotate host.operations --expected-epoch 3
permguard host keys revoke plan data.attest 9f2c… --reason compromise --compromised-at 2026-10-01T00:00:00Z --out revoke.json
permguard host keys bundle export --resource plane/control/zone/z1 --out bundle.json
```

The bundle is the shape `ledgers import --bundle` and `backup verify --bundle` read.

## host audit

The Host's audit trails: records, signed checkpoints and fixed-frontier exports.

```sh
permguard host audit query [OPTIONS] --class <CLASS> --resource <RESOURCE>
permguard host audit checkpoints [OPTIONS] --class <CLASS> --resource <RESOURCE>
permguard host audit export [OPTIONS] --class <CLASS> --resource <RESOURCE> --out <FILE>
```

| Command       | What it does                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------- |
| `query`       | prints one page of a trail's records, its gaps and the cursor of the next page                    |
| `checkpoints` | prints a trail's signed checkpoints and the keys that cover them                                  |
| `export`      | writes a trail's export, every page at one frontier with its verification metadata, to a new file |

| Flag                    | Meaning                                                                     |
| ----------------------- | --------------------------------------------------------------------------- |
| `--class <CLASS>`       | the trail's class: `security`, `operations` or `access`                     |
| `--resource <RESOURCE>` | the trail's resource, in the Host API's grammar, such as `host`             |
| `--from`, `--to`        | `query`: the earliest and latest record time, RFC 3339, inclusive           |
| `--cursor`, `--limit`   | `query`: where the page starts; how many records, 1 to 1000                 |
| `--period <YYYY-MM-DD>` | `checkpoints`: one UTC day; every day when left out                         |
| `--frontier <N>`        | `export`: the sequence the export stops before; the trail's next by default |

```sh
permguard host audit query --class security --resource host
permguard host audit checkpoints --class security --resource host --period 2026-10-01 -o json
permguard host audit export --class security --resource host --out audit.json
```

## host streams

The streams the Host produces and consumes, read through the Host listener.

```sh
permguard host streams list [OPTIONS]
permguard host streams frontier [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
permguard host streams signers [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
permguard host streams runs [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
permguard host streams subscriptions [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
permguard host streams gaps [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
permguard host streams anchors [OPTIONS] --resource <RESOURCE> <PLANE> <STREAM_TYPE>
```

| Command         | What it prints                                                                           |
| --------------- | ---------------------------------------------------------------------------------------- |
| `list`          | the declared streams, each resource's state and the retention class                      |
| `frontier`      | the producer's and the consumers' frontiers of one stream                                |
| `signers`       | the key spans each run of one stream is signed under                                     |
| `runs`          | each run, open or ended, how far it was sealed and acknowledged, and what it still holds |
| `subscriptions` | who one stream is shipped to and how far each subscription acknowledged                  |
| `gaps`          | the durable gaps: each run whose prefix retention deleted                                |
| `anchors`       | the retained prefix anchors of one stream                                                |

`<PLANE>` and `<STREAM_TYPE>` are named as `host streams list` names them, and `--resource` is in the Host API's grammar, such as `plane/data/zone/<zone>/ledger/<ledger>`.

```sh
permguard host streams list
permguard host streams frontier data decisions --resource plane/data/zone/z1/ledger/l1
permguard host streams gaps data events --resource plane/data/zone/z1/ledger/l1 -o json
```

## host plans

The plan receipts of two-step changes, and the countersignature dual control requires.

```sh
permguard host plans list [OPTIONS]
permguard host plans approve [OPTIONS] <PLAN_ID>
```

| Flag                | Meaning                                                        |
| ------------------- | -------------------------------------------------------------- |
| `--status <STATUS>` | `list`: only plans `pending`, `ready`, `consumed` or `expired` |

```sh
permguard host plans list --status pending -o json
permguard host plans approve 0123456789abcdef0123456789abcdef
```

`list` shows the plans whose operation the caller may do, with their approvals.

## host backup

Application-consistent backups through the Host listener.

```sh
permguard host backup prepare [OPTIONS] --token-out <FILE>
permguard host backup finalize [OPTIONS] --backup-token-file <FILE> --snapshot-id <SNAPSHOT_ID>
permguard host backup abort [OPTIONS] --backup-token-file <FILE>
permguard host backup list [OPTIONS]
```

| Command    | What it does                                                                                                    |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| `prepare`  | mutations stop, the volume is flushed, the signed manifest is printed, the snapshot token written to a new file |
| `finalize` | records the storage driver's snapshot of a prepared backup, and resumes mutations                               |
| `abort`    | aborts a prepared backup, and resumes mutations                                                                 |
| `list`     | lists the backups this Host knows, each with its manifest                                                       |

```sh
permguard host backup prepare --token-out backup.token
permguard host backup finalize --backup-token-file backup.token --snapshot-id snap-2026-10-25
```

`--backup-token-file` is the file `prepare` wrote, not `--token-file`, the bearer the command line authenticates with.

## host holds

Legal and incident holds that keep a ledger, or every ledger of a zone, from garbage collection; offline, on a stopped server's volume.

```sh
permguard host holds add [OPTIONS] --resource <RESOURCE> --owner <OWNER> --reason <REASON> <--expires-at <INSTANT>|--review-at <INSTANT>>
permguard host holds list [OPTIONS]
permguard host holds release [OPTIONS] <ID>
```

| Flag                     | Meaning                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `--resource <RESOURCE>`  | `plane/control/zone/<id>/ledger/<id>`, or `plane/control/zone/<id>` for a whole zone |
| `--owner <OWNER>`        | who answers for the hold                                                             |
| `--reason <REASON>`      | why the hold is taken                                                                |
| `--expires-at <INSTANT>` | when the hold stops keeping, RFC 3339                                                |
| `--review-at <INSTANT>`  | when the hold is due for review, RFC 3339; it keeps past it                          |

```sh
permguard host holds add --volume ./volume --resource plane/control/zone/01a0…/ledger/01a1… --owner legal@acme --reason "litigation 2026-17" --review-at 2027-01-01T00:00:00Z
permguard host holds list --volume ./volume
```

`list` shows each hold as `active`, `review_due` or `expired`; `release` returns what it kept to the garbage collection's rules.

## backup verify

Checks a snapshot at `--volume` against its signed manifest, offline.

```sh
permguard backup verify [OPTIONS] --manifest <FILE> --bundle <FILE> --pin <PIN>
```

| Flag                | Meaning                                                                                                           |
| ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `--manifest <FILE>` | the snapshot's manifest: its COSE_Sign1 bytes, or their base64url text as `host backup prepare` prints them       |
| `--bundle <FILE>`   | the Host's verification bundle, as `host keys bundle export --resource host` writes it, kept outside the snapshot |
| `--pin <PIN>`       | the Host identity's fingerprint the operator pinned                                                               |

```sh
permguard backup verify --volume /mnt/snapshot --manifest manifest.cose --bundle bundle.json --pin sha256:ab12…
```

It reports `consistent` when every file is the one the manifest binds, and `crash_consistent`, exit 2, when any differs.

## restore

Restores a Server Host's volume from a snapshot, offline.

```sh
permguard restore plan [OPTIONS] --mode <MODE> --reason <REASON> --out <FILE>
permguard restore run [OPTIONS] --mode <MODE>
```

| Mode       | What it does                                |
| ---------- | ------------------------------------------- |
| `dr`       | keeps the Host and starts a new incarnation |
| `forensic` | is never served                             |
| `clone`    | makes a new Host of the snapshot's data     |

```sh
permguard restore plan --volume /var/lib/permguard --mode dr --reason "region lost" --out restore.plan
permguard restore run --volume /var/lib/permguard --mode dr --confirm-file restore.plan
```

`plan` proves the fence, scans the volume and opens its keys; `run` is refused when the volume or its claim moved since, or when its `--mode` is not the plan's.

## migrate

Migrates a stopped server's volume to the current layout, offline, one subsystem at a time.

```sh
permguard migrate plan [OPTIONS] --subsystem <SUBSYSTEM> --backup <BACKUP> --out <FILE>
permguard migrate run [OPTIONS]
permguard migrate status [OPTIONS]
permguard migrate rollback [OPTIONS] --subsystem <SUBSYSTEM>
```

| Command    | What it does                                                                                   |
| ---------- | ---------------------------------------------------------------------------------------------- |
| `plan`     | plans one subsystem's migration with the external backup taken before it                       |
| `run`      | runs the migration the plan in `--confirm-file` describes                                      |
| `status`   | lists every subsystem on the volume: its version, generation and where its migration stands    |
| `rollback` | returns a committed migration to its old generation, when the new one is as the commit left it |

| Flag                      | Meaning                                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `--subsystem <SUBSYSTEM>` | `plan`: `keys`, `audit`, `decisions` or `events`; `rollback`: as `migrate status` names it                  |
| `--backup <BACKUP>`       | the external backup taken before the migration, as the operator names it                                    |
| `--legacy <LOCATION>`     | where legacy data moved: `<ring>=<directory>` for `keys`, repeated; a directory for `audit` and `decisions` |

```sh
permguard migrate status --volume /var/lib/permguard
permguard migrate plan --volume /var/lib/permguard --subsystem audit --backup snap-2026-10-25 --out migrate.plan
permguard migrate run --volume /var/lib/permguard --confirm-file migrate.plan
```

## gc

Runs the Control Plane's object sweep on demand, through the Host listener: what no ref, transfer, hold or grace keeps.

```sh
permguard gc objects plan [OPTIONS] --out <FILE>
permguard gc objects run [OPTIONS] --confirm-file <FILE>
```

| Flag                | Meaning                                     |
| ------------------- | ------------------------------------------- |
| `--zone <ZONE>`     | `plan`: only this zone, by id               |
| `--ledger <LEDGER>` | `plan`: only this ledger of the zone, by id |

```sh
permguard gc objects plan --zone 0198f3bb-0000-7000-8000-000000000002 --out gc.plan
permguard gc objects run --confirm-file gc.plan
```

`plan` changes nothing and prints the candidates, their bytes, and what is kept and why.
`run` is bounded, serialized with the background pass, and audited even when it removes nothing; it prints what was removed and kept, and the receipt.

## reclaim

Reclaims the storage of Data Plane replicas removed from a group, once each is drained: one pass, on Kubernetes.

```sh
permguard reclaim run [OPTIONS] --selector <SELECTOR> --job-template <FILE>
```

| Flag                       | Meaning                                                                                |
| -------------------------- | -------------------------------------------------------------------------------------- |
| `--selector <SELECTOR>`    | the label selector of the group's workloads and their claims                           |
| `--job-template <FILE>`    | the drain Job manifest, JSON, with `__CLAIM__`, `__JOB__` and `__ORDINAL__` to fill in |
| `--namespace <NAMESPACE>`  | the namespace; the ServiceAccount's own when absent                                    |
| `--kube-api <URL>`         | the Kubernetes API, when not the cluster this runs in                                  |
| `--kube-token-file <FILE>` | the bearer token for `--kube-api`                                                      |
| `--kube-ca <FILE>`         | the CA `--kube-api` is verified against                                                |

```sh
permguard --host-endpoint https://pg-permguard-control-plane-host:5444 reclaim run \
  --selector app.kubernetes.io/instance=pg,app.kubernetes.io/component=data-plane,permguard.com/group=billing \
  --job-template /etc/permguard-reclaim/job.json
```

Each removed replica's storage is drained first, and deleted only on proof.

<nav class="pgx-pager pgx-pager--previous-only" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./authority"><span>Previous</span><strong><b aria-hidden="true">←</b> Authority</strong></a>
</nav>
