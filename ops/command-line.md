<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The command inventory

Every command the `permguard` command line answers, and every command its specification names that it does not answer yet, one row each.
The test `test_the_command_tree_is_the_inventory` of `crates/permguard-cli/src/args.rs` reads these tables and walks the command tree against them: a command added, removed or renamed on either side fails it, so this page is the inventory rather than a count.

The **Command** cell is the command's path, without its arguments.
The **Grant** cell is the operation the Host checks for it, as the Host names its operations (`keys.admin` where the specification says `keys.manage`, for instance), or that it needs none of the Host's: `public`, `local` (the command line's own state), `transport` (the connection's proof alone), `offline` (a stopped server's volume), `—` (a workspace command whose plane checks its own grants).
`host holds` works offline on a stopped server's volume (WP-7.3c); the catalog's online `holds` commands wait for a catalog route.
The **State** cell is one of:

- `present`: the command line answers it;
- `server`: an offline tool of each server binary, not of this command line;
- `absent`: a later package adds it, named in **Why**;
- `blocked`: no package can add it yet, for the reason in **Why**.

## Workspace

| Command         | Grant               | State   | Why |
| --------------- | ------------------- | ------- | --- |
| `init`          | —                   | present |     |
| `remote add`    | —                   | present |     |
| `remote list`   | —                   | present |     |
| `remote remove` | —                   | present |     |
| `clone`         | —                   | present |     |
| `checkout`      | —                   | present |     |
| `pull`          | —                   | present |     |
| `refresh`       | —                   | present |     |
| `validate`      | —                   | present |     |
| `plan`          | —                   | present |     |
| `apply`         | —                   | present |     |
| `test`          | —                   | present |     |
| `history`       | —                   | present |     |
| `status`        | —                   | present |     |
| `verify`        | —                   | present |     |
| `objects list`  | —                   | present |     |
| `objects cat`   | —                   | present |     |
| `objects prune` | —                   | present |     |
| `check`         | `decision.evaluate` | present |     |

## Catalog

| Command              | Grant           | State   | Why                                                                                                  |
| -------------------- | --------------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `zones create`       | `catalog.write` | present |                                                                                                      |
| `zones list`         | `catalog.read`  | present |                                                                                                      |
| `zones get`          | `catalog.read`  | present |                                                                                                      |
| `zones update`       | `catalog.write` | present |                                                                                                      |
| `zones delete`       | `catalog.write` | present |                                                                                                      |
| `ledgers create`     | `catalog.write` | present |                                                                                                      |
| `ledgers list`       | `catalog.read`  | present |                                                                                                      |
| `ledgers get`        | `catalog.read`  | present |                                                                                                      |
| `ledgers update`     | `catalog.write` | present |                                                                                                      |
| `ledgers delete`     | `catalog.write` | present |                                                                                                      |
| `ledgers archive`    | `catalog.write` | present |                                                                                                      |
| `ledgers restore`    | `catalog.write` | present |                                                                                                      |
| `holds add`          | `catalog.hold`  | blocked | the catalog serves no holds route and `catalog.hold` is no operation yet; `host holds` works offline |
| `holds list`         | `catalog.hold`  | blocked | the catalog serves no holds route and `catalog.hold` is no operation yet; `host holds` works offline |
| `holds release`      | `catalog.hold`  | blocked | the catalog serves no holds route and `catalog.hold` is no operation yet; `host holds` works offline |
| `tombstones list`    | `catalog.read`  | blocked | the catalog serves no tombstones route yet                                                           |
| `host holds add`     | offline         | present |                                                                                                      |
| `host holds list`    | offline         | present |                                                                                                      |
| `host holds release` | offline         | present |                                                                                                      |

## Evidence

| Command             | Grant           | State   | Why |
| ------------------- | --------------- | ------- | --- |
| `decisions list`    | `evidence.read` | present |     |
| `decisions tail`    | `evidence.read` | present |     |
| `decisions get`     | `evidence.read` | present |     |
| `decisions signers` | `evidence.read` | present |     |
| `decisions export`  | `evidence.read` | present |     |
| `decisions verify`  | offline         | present |     |
| `events list`       | `evidence.read` | present |     |
| `events tail`       | `evidence.read` | present |     |
| `events get`        | `evidence.read` | present |     |
| `events signers`    | `evidence.read` | present |     |
| `events export`     | `evidence.read` | present |     |
| `events verify`     | offline         | present |     |
| `evidence anchors`  | `streams.read` | present |     |

## Host identity

| Command                    | Grant            | State   | Why |
| -------------------------- | ---------------- | ------- | --- |
| `host identity provision`  | offline          | present |     |
| `host identity show`       | transport        | present |     |
| `host identity verify`     | transport        | present |     |
| `host identity pin add`    | local            | present |     |
| `host identity pin list`   | local            | present |     |
| `host identity pin remove` | local            | present |     |
| `host identity rotate`     | `identity.admin` | present |     |
| `host identity reset plan` | `identity.admin` | present |     |
| `host identity reset run`  | `identity.admin` | present |     |

## Membership

| Command                      | Grant              | State   | Why |
| ---------------------------- | ------------------ | ------- | --- |
| `host members invite create` | `membership.admin` | present |     |
| `host members invite list`   | `membership.admin` | present |     |
| `host members invite revoke` | `membership.admin` | present |     |
| `host members join`          | `membership.admin` | present |     |
| `host members pending`       | `membership.read`  | present |     |
| `host members approve`       | `membership.admin` | present |     |
| `host members reject`        | `membership.admin` | present |     |
| `host members list`          | `membership.read`  | present |     |
| `host members get`           | `membership.read`  | present |     |
| `host members sync`          | `membership.admin` | present |     |
| `host members suspend`       | `membership.admin` | present |     |
| `host members resume`        | `membership.admin` | present |     |
| `host members fence`         | `membership.admin` | present |     |
| `host members revoke plan`   | `membership.admin` | present |     |
| `host members revoke run`    | `membership.admin` | present |     |
| `host members sessions`      | `membership.read`  | present |     |
| `host members verify`        | `membership.read`  | present |     |

## Keys and secrets

| Command                       | Grant            | State   | Why                                                                                           |
| ----------------------------- | ---------------- | ------- | --------------------------------------------------------------------------------------------- |
| `host keys list`              | `keys.read`      | present |                                                                                               |
| `host keys show`              | public           | present |                                                                                               |
| `host keys rotate`            | `keys.admin`     | present |                                                                                               |
| `host keys revoke plan`       | `keys.admin`     | present |                                                                                               |
| `host keys revoke run`        | `keys.admin`     | present |                                                                                               |
| `host keys bundle export`     | `keys.read`      | present |                                                                                               |
| `keys export`                 | offline          | server  |                                                                                               |
| `host secrets list`           | `secrets.read`   | blocked | the Host API serves no secrets route: its request and answer are not fixed by any package yet |
| `host secrets witness verify` | `secrets.read`   | blocked | the Host API serves no secrets route: its request and answer are not fixed by any package yet |
| `host secrets rotate`         | `secrets.manage` | blocked | the Host API serves no secrets route: its request and answer are not fixed by any package yet |

## Grants

| Command                   | Grant         | State   | Why |
| ------------------------- | ------------- | ------- | --- |
| `host grants list`        | `authz.admin` | present |     |
| `host grants issue`       | `authz.admin` | present |     |
| `host grants revoke plan` | `authz.admin` | present |     |
| `host grants revoke run`  | `authz.admin` | present |     |
| `host grants bootstrap`   | offline       | present |     |

## Audit

| Command                  | Grant        | State   | Why |
| ------------------------ | ------------ | ------- | --- |
| `host audit query`       | `audit.read` | present |     |
| `host audit checkpoints` | `audit.read` | present |     |
| `host audit export`      | `audit.read` | present |     |
| `audit verify`           | offline      | server  |     |

## Streams

| Command                      | Grant          | State   | Why                                                           |
| ---------------------------- | -------------- | ------- | ------------------------------------------------------------- |
| `host streams list`          | `streams.read` | present |                                                               |
| `host streams frontier`      | `streams.read` | present |                                                               |
| `host streams signers`       | `streams.read` | present |                                                               |
| `host streams runs`          | `streams.read` | present |                                                               |
| `host streams subscriptions` | `streams.read` | present |                                                               |
| `host streams gaps`          | `streams.read` | present |                                                               |
| `host streams anchors`       | `streams.read` | present |                                                               |
| `streams verify`             | offline        | blocked | no package of this plan schedules the offline stream verifier |

## Configuration and discovery

| Command                 | Grant         | State   | Why |
| ----------------------- | ------------- | ------- | --- |
| `inspect`               | transport     | present |     |
| `discover`              | transport     | present |     |
| `host config show`      | `config.read` | present |     |
| `host config revisions` | `config.read` | present |     |
| `config show`           | local         | present |     |
| `config get`            | local         | present |     |
| `config set`            | local         | present |     |
| `config reset`          | local         | present |     |
| `version`               | local         | present |     |
| `completion`            | local         | present |     |

## Lifecycle

| Command                  | Grant                                                                                 | State   | Why                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `host status`            | `lifecycle.read`                                                                      | present |                                                                                                   |
| `host drain`             | `lifecycle.manage`                                                                    | blocked | the Host API serves no drain route: its request and answer are not fixed by any package yet       |
| `host maintenance enter` | `lifecycle.manage`                                                                    | blocked | the Host API serves no maintenance route: its request and answer are not fixed by any package yet |
| `host maintenance exit`  | `lifecycle.manage`                                                                    | blocked | the Host API serves no maintenance route: its request and answer are not fixed by any package yet |
| `host plans list`        | grant of the planned operation                                                        | present |                                                                                                   |
| `host plans approve`     | grant of the planned operation                                                        | present |                                                                                                   |
| `reclaim run`            | `membership.read`, `streams.read` on the coordinator; the namespace's Kubernetes Role | present |                                                                                                   |

## Backup, restore and migration

| Command                | Grant             | State   | Why |
| ---------------------- | ----------------- | ------- | --- |
| `host backup prepare`  | `backup.manage`   | present |     |
| `host backup finalize` | `backup.manage`   | present |     |
| `host backup abort`    | `backup.manage`   | present |     |
| `host backup list`     | `backup.read`     | present |     |
| `backup verify`        | offline           | present |     |
| `restore plan`         | recovery operator | present |     |
| `restore run`          | recovery operator | present |     |
| `migrate plan`         | recovery operator | present |     |
| `migrate run`          | recovery operator | present |     |
| `migrate status`       | recovery operator | present |     |
| `migrate rollback`     | recovery operator | present |     |
| `ledgers export`       | `catalog.read`    | present |     |
| `ledgers import`       | `policy.push`     | present |     |
| `zones export`         | `catalog.read`    | present |     |
| `zones import`         | `policy.push`     | present |     |

## Garbage collection and pressure

| Command              | Grant          | State   | Why                                                                                           |
| -------------------- | -------------- | ------- | --------------------------------------------------------------------------------------------- |
| `gc objects plan`    | `gc.manage`    | present |                                                                                               |
| `gc objects run`     | `gc.manage`    | present |                                                                                               |
| `gc mirrors plan`    | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `gc mirrors run`     | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `gc imports plan`    | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `gc imports run`     | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `gc streams plan`    | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `gc streams run`     | `gc.manage`    | blocked | the Host serves no such gc job: its sweep runs in the background only                         |
| `storage quota show` | `storage.read` | blocked | the Host API serves no storage route: its request and answer are not fixed by any package yet |
| `storage probe`      | `storage.read` | blocked | the Host API serves no storage route: its request and answer are not fixed by any package yet |
