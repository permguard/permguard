---
pageClass: pg-page-concepts
title: Configuration
description: Global flags, environment variables, the configuration file, the token cache, output formats and exit codes of the permguard CLI.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Configure once, override anywhere.</h1>
  <p>Every command reads the same settings: where each Plane is reached, the TLS material, the credentials and the output format.</p>
</div>

A setting comes from the first layer that states it: a flag, then an environment variable, then the configuration file, then the default compiled in.
The global flags below are accepted by every command, before or after its name.
The last two sections say what a command prints and the status it exits with, which is what a script depends on.

## Where a value comes from

<div class="pgx-cli-steps" role="img" aria-label="A setting is read from the first layer that states it: a flag, then a PERMGUARD environment variable, then the configuration file at ~/.permguard/config.yml, then the compiled default.">
  <article class="pgx-cli-steps__accent"><b>01</b><strong>Flag</strong><span>what you typed: always wins</span></article>
  <article><b>02</b><strong>Environment</strong><span><code>PERMGUARD_*</code> for a deployment or a CI job</span></article>
  <article><b>03</b><strong>Configuration file</strong><span>your own context, once</span></article>
  <article><b>04</b><strong>Default</strong><span>a local development runtime</span></article>
</div>

`permguard config show` lists every setting, its value and the layer it came from.
The compiled defaults point the Control Plane at `http://127.0.0.1:6443` and the Data Plane at `http://127.0.0.1:7443`; the Host listener, the Authority Plane, the TLS files and the credentials have no default, and a command that needs one of them refuses to run without it.

## Global flags

| Flag                             | Environment                        | What it sets                                                                        |
| -------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------- |
| `-o, --output <OUTPUT>`          |                                    | `terminal` (default), `json` or `yaml`                                              |
| `-v, --verbose`                  |                                    | narrates what is being done, on stderr                                              |
| `-w, --workdir <DIR>`            |                                    | the directory relative paths are resolved against; `.` by default                   |
| `--config <FILE>`                | `PERMGUARD_CONFIG`                 | the configuration file, instead of `~/.permguard/config.yml`                        |
| `--control-endpoint <URL>`       | `PERMGUARD_CONTROL_PLANE_ENDPOINT` | where the Control Plane is reached                                                  |
| `--data-endpoint <URL>`          | `PERMGUARD_DATA_PLANE_ENDPOINT`    | where the Data Plane is reached                                                     |
| `--host-endpoint <URL>`          | `PERMGUARD_HOST_ENDPOINT`          | where the Host listener is reached                                                  |
| `--volume <DIR>`                 |                                    | a Server Host's volume, its `working_dir`, for the offline commands: server stopped |
| `--token-file <FILE>`            | `PERMGUARD_TOKEN_FILE`             | a bearer token file, readable by its owner only, sent over verified TLS only        |
| `--access-key <KEY>`             | `PERMGUARD_ACCESS_KEY`             | the access key the CLI obtains its tokens with                                      |
| `--secret-key-file <FILE>`       | `PERMGUARD_SECRET_KEY_FILE`        | the file holding that key's secret key, readable by its owner only                  |
| `--authority-endpoint <URL>`     | `PERMGUARD_AUTHORITY_ENDPOINT`     | where the Authority Plane is reached, for tokens and the `authority` commands       |
| `--authority-tls-ca-file <FILE>` | `PERMGUARD_AUTHORITY_TLS_CA_FILE`  | the CA the Authority Plane is checked against, when it is not the Planes'           |
| `--tls-ca-file <FILE>`           | `PERMGUARD_TLS_CA_FILE`            | the CA an endpoint's certificate is checked against (PEM)                           |
| `--tls-cert-file <FILE>`         | `PERMGUARD_TLS_CERT_FILE`          | the client certificate, for an endpoint that asks for mutual TLS (PEM)              |
| `--tls-key-file <FILE>`          | `PERMGUARD_TLS_KEY_FILE`           | the private key of that certificate (PEM)                                           |
| `--tls-server-name <NAME>`       | `PERMGUARD_TLS_SERVER_NAME`        | the name the certificate is checked against, when it is not the endpoint's host     |
| `--tls-skip-verify`              | `PERMGUARD_TLS_SKIP_VERIFY`        | accepts any server certificate: insecure, for development only                      |
| `-V, --version`                  |                                    | prints the CLI's version and build                                                  |

A relative path to a TLS file or a token file is resolved against `--workdir` when a flag or a variable gives it, and against the file's own directory when the configuration file does.

## Targets

Each command reaches one target, and a flag that names another target is refused as a usage error: a command never falls back from one Plane or Host to another.

| Target          | Selected by                                  | Commands                                                                    |
| --------------- | -------------------------------------------- | --------------------------------------------------------------------------- |
| local           | nothing; `-w` names the workspace            | `init` `refresh` `validate` `test` `plan` `status` `history` `objects`      |
| local           | nothing                                      | `version` `completion` `config` `discover` `host identity pin`              |
| Control Plane   | the workspace's remote, `--control-endpoint` | `zones` `ledgers` `remote` `clone` `checkout` `pull` `apply` `verify`       |
| Control Plane   | `--control-endpoint`                         | `decisions` `events`                                                        |
| Data Plane      | `--data-endpoint`                            | `check` `test --remote`                                                     |
| both Planes     | `--control-endpoint`, `--data-endpoint`      | `inspect`                                                                   |
| Authority Plane | `--authority-endpoint`                       | `authority`                                                                 |
| Host listener   | `--host-endpoint`                            | `host` (online), `evidence`, `gc`, `reclaim`                                |
| volume          | `--volume`, the server stopped               | `restore` `migrate` `backup` `authority admin-key`, `host` offline commands |

`decisions` and `events` read the evidence through the Control Plane endpoint, not the Data Plane's.
Which `host` subcommands work online and which offline is listed on [Server Operations](./operations#host).

## TLS and credentials

Plain `http://` endpoints are the local development defaults.
Against TLS, give the CA, and for mutual TLS the client certificate and key; the key can also be named by reference in the configuration, `tls.key_ref` as `env:NAME` or `file:PATH`.

```sh
permguard --control-endpoint https://permguard.example:6443 \
  --tls-ca-file ca.pem --tls-cert-file operator.pem --tls-key-file operator.key \
  zones list
```

A command authenticates in one of two ways:

| Credential          | Given by                                                         | What the CLI does                                                                          |
| ------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| a bearer token file | `--token-file`, or `auth.token_file`                             | sends the token as it is; the file is readable by its owner only                           |
| an access key       | `--secret-key-file` (and `--access-key`), `--authority-endpoint` | obtains a token at the Authority Plane, keeps it, and sends it when no token file is given |

A kept token lives under `~/.permguard/tokens/`, in a file only its owner reads, and is reused until a minute before it expires.
`auth.client.scope` (`PERMGUARD_CLIENT_SCOPE`) narrows the operations the token asks for; unset, it asks for all of the account's.
`permguard authority token forget` drops the kept token, and `permguard authority token revoke` revokes it on every Plane: see [Authority](./authority#tokens).

```sh
permguard --authority-endpoint https://permguard.example:8443 --secret-key-file ./billing.key \
  --data-endpoint https://data-plane.example:7443 \
  check -f request.json --zone <zone-id> --ledger <ledger-id>
```

## The configuration file

The file is `~/.permguard/config.yml`, or the one `--config` or `PERMGUARD_CONFIG` names.
The `config` commands read and write it; they never contact a server.

```sh
permguard config show [OPTIONS]
permguard config get [OPTIONS] <KEY>
permguard config set [OPTIONS] <KEY> <VALUE>
permguard config reset [OPTIONS] [KEY]
```

| Command        | What it does                                                         |
| -------------- | -------------------------------------------------------------------- |
| `config show`  | shows every setting, its value, and which layer that value came from |
| `config get`   | prints one setting's value, and nothing else                         |
| `config set`   | writes one setting into the configuration file                       |
| `config reset` | takes a setting back out of the file; every setting when no key      |

```sh
permguard config set control-plane.endpoint https://permguard.internal:6443
permguard config set data-plane.endpoint https://permguard.internal:7443
permguard config show -o json | jq '.settings[].origin'
```

These are the keys the file holds:

| Key                              | Environment                               | Default                 | What it is                                                          |
| -------------------------------- | ----------------------------------------- | ----------------------- | ------------------------------------------------------------------- |
| `control-plane.endpoint`         | `PERMGUARD_CONTROL_PLANE_ENDPOINT`        | `http://127.0.0.1:6443` | where the Control Plane is reached                                  |
| `data-plane.endpoint`            | `PERMGUARD_DATA_PLANE_ENDPOINT`           | `http://127.0.0.1:7443` | where the Data Plane is reached                                     |
| `host.endpoint`                  | `PERMGUARD_HOST_ENDPOINT`                 |                         | where the Host listener is reached                                  |
| `tls.ca_file`                    | `PERMGUARD_TLS_CA_FILE`                   |                         | the CA an endpoint's certificate is checked against (PEM)           |
| `tls.cert_file`                  | `PERMGUARD_TLS_CERT_FILE`                 |                         | the operator's client certificate, for mutual TLS (PEM)             |
| `tls.key_file`                   | `PERMGUARD_TLS_KEY_FILE`                  |                         | the private key of that certificate (PEM)                           |
| `tls.key_ref`                    | `PERMGUARD_TLS_KEY_REF`                   |                         | that key by reference instead: `env:NAME` or `file:PATH`            |
| `tls.server_name`                | `PERMGUARD_TLS_SERVER_NAME`               |                         | the name a certificate is checked against, when not its host        |
| `workspace.one_policy_per_file`  | `PERMGUARD_WORKSPACE_ONE_POLICY_PER_FILE` | `false`                 | whether `validate` refuses a file holding more than one policy      |
| `auth.token_file`                | `PERMGUARD_TOKEN_FILE`                    |                         | the operator's bearer token file, readable by its owner only        |
| `auth.client.access_key`         | `PERMGUARD_ACCESS_KEY`                    |                         | the access key the CLI obtains its tokens with                      |
| `auth.client.secret_file`        | `PERMGUARD_SECRET_KEY_FILE`               |                         | the file holding that key's secret key, readable by its owner only  |
| `auth.client.authority_endpoint` | `PERMGUARD_AUTHORITY_ENDPOINT`            |                         | where the Authority Plane is reached: `https://` or `grpcs://`      |
| `auth.client.tls_ca_file`        | `PERMGUARD_AUTHORITY_TLS_CA_FILE`         |                         | the CA the Authority Plane is checked against, when not the Planes' |
| `auth.client.scope`              | `PERMGUARD_CLIENT_SCOPE`                  |                         | the operations a token asks for, narrowing the account's            |

## Output

`-o terminal` is written for people; `-o json` and `-o yaml` render the same report for a script.
The report goes to standard output; the narration of `-v` and every failure go to standard error, so a pipe receives only the report.

```sh
permguard zones list -o json | jq '.zones[].name'
permguard history -o json | jq '.commits[].commit'
```

A failure carries a class, a stable code and a message.
In the terminal it reads `error: <message> (<code>)`; under `-o json` or `-o yaml` it is one document with the fields `class`, `code` and `message`.
A refusal for authentication or authorization, `unauthenticated` or `forbidden`, has no class, as on the wire: only `code` and `message`.

## Exit codes

| Exit | Meaning                                                                                                           |
| ---: | ----------------------------------------------------------------------------------------------------------------- |
|    0 | success; a `deny` from `check` is an answer and exits 0                                                           |
|    1 | `inspect` only: no Plane answered                                                                                 |
|    2 | the command ran and its subject did not pass: a failed test, a verification that does not hold, a Plane not ready |
|   64 | usage: the command line, or something it named, is wrong                                                          |
|   69 | unavailable: the target did not answer, or refused for now; retrying later is reasonable                          |
|   70 | internal: the command failed for a reason of its own                                                              |

`--help` and `--version` exit 0; a command line the parser refuses exits 64.
`backup verify` exits 2 when a snapshot is only `crash_consistent`, and `inspect` exits 2 when a Plane answered but is not ready.

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="../command-line"><span>Previous</span><strong><b aria-hidden="true">←</b> Command Line</strong></a>
  <a class="pgx-pager__next" href="./workspaces"><span>Next</span><strong>Workspaces &amp; Policies <b aria-hidden="true">→</b></strong></a>
</nav>
