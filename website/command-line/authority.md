---
pageClass: pg-page-concepts
title: Authority
description: Identities, scopes, access keys and tokens on the Authority Plane, with the permguard authority commands.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero pgx-cli-hero">
  <div class="pgx-kicker">Command Line</div>
  <h1>Accounts, keys and tokens.</h1>
  <p>The <code>authority</code> commands manage who may call Permguard itself: identities, their scopes and access keys, and the tokens they obtain.</p>
</div>

The `authority` commands talk to the Authority Plane at `--authority-endpoint`, port 8443 in the shipped configurations.
A secret is never printed: it is written once, to a new file only its owner reads.
[Authority Plane](../authority-plane) explains the model; this page is the commands.

## Connecting

| Flag                             | Environment                       | Meaning                                                               |
| -------------------------------- | --------------------------------- | --------------------------------------------------------------------- |
| `--authority-endpoint <URL>`     | `PERMGUARD_AUTHORITY_ENDPOINT`    | where the Authority Plane is reached, `https://` or `grpcs://`        |
| `--authority-tls-ca-file <FILE>` | `PERMGUARD_AUTHORITY_TLS_CA_FILE` | the CA its certificate is checked against, when it is not the Planes' |
| `--secret-key-file <FILE>`       | `PERMGUARD_SECRET_KEY_FILE`       | the access key's secret key, readable by its owner only               |
| `--access-key <KEY>`             | `PERMGUARD_ACCESS_KEY`            | the access key the CLI obtains its tokens with                        |
| `--token-file <FILE>`            | `PERMGUARD_TOKEN_FILE`            | a bearer token to use as it is, instead of obtaining one              |

The same settings live in the configuration file under `auth.client.*` and `auth.token_file`; see [Configuration](./configuration#tls-and-credentials).

## service-accounts

Lists, shows, creates, updates, suspends, resumes and deletes identities; the command keeps its name, `service-accounts`.

```sh
permguard authority service-accounts list [OPTIONS]
permguard authority service-accounts get [OPTIONS] <NAME>
permguard authority service-accounts create [OPTIONS] <NAME>
permguard authority service-accounts update [OPTIONS] --description <DESCRIPTION> <NAME>
permguard authority service-accounts suspend [OPTIONS] <NAME>
permguard authority service-accounts resume [OPTIONS] <NAME>
permguard authority service-accounts delete [OPTIONS] <NAME>
```

| Command   | What it does                                                                  |
| --------- | ----------------------------------------------------------------------------- |
| `list`    | lists the accounts with their status, keys and scopes                         |
| `get`     | shows one account                                                             |
| `create`  | creates an account, with its first scopes                                     |
| `update`  | changes an account's description                                              |
| `suspend` | suspends an account: it obtains no token, and every token it holds is refused |
| `resume`  | resumes a suspended account                                                   |
| `delete`  | deletes an account, its keys and every token of it; `admin` is never deleted  |

| Flag                          | Meaning                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| `<NAME>`                      | `create`: lower case letters, digits and `-`, unique                               |
| `--description <DESCRIPTION>` | what the account is for, in a few words                                            |
| `--scope <OPS@SELECTOR>`      | `<operations>@<selector>`, the operations comma separated; repeated for each scope |

```sh
permguard authority service-accounts create billing --scope decision.evaluate,event.submit@plane/data/*
permguard authority service-accounts create pusher --description "CI policy push" --scope policy.push@plane/control/zone/<zone-id>/*
permguard authority service-accounts suspend billing
```

## scopes

Reads an account's scopes, or replaces them whole.

```sh
permguard authority scopes get [OPTIONS] <NAME>
permguard authority scopes set [OPTIONS] <NAME>
```

| Flag                     | Meaning                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| `--scope <OPS@SELECTOR>` | `set`: one scope; repeated for each, the whole set replaced                |
| `--revoke-tokens`        | `set`: revokes the account's live tokens too, so a narrowing holds at once |

```sh
permguard authority scopes get billing -o json
permguard authority scopes set billing --scope decision.evaluate@plane/data/zone/<zone-id>/* --revoke-tokens
```

## keys

Lists, creates and deletes an account's access keys; a secret is written once to a new file, never printed.

```sh
permguard authority keys list [OPTIONS] <NAME>
permguard authority keys create [OPTIONS] --secret-out <FILE> <NAME>
permguard authority keys delete [OPTIONS] <NAME> <ACCESS_KEY>
```

| Command  | What it does                                                       |
| -------- | ------------------------------------------------------------------ |
| `list`   | an account's access keys, never a secret                           |
| `create` | a new access key, its secret written once to a new owner-only file |
| `delete` | deletes an access key, `pgak_…`, and every token it obtained       |

| Flag                  | Meaning                                                                      |
| --------------------- | ---------------------------------------------------------------------------- |
| `--secret-out <FILE>` | `create`: the new file the access key and its secret key are written to      |
| `--expires <EXPIRES>` | `create`: when the key stops serving, RFC 3339; it never expires when absent |

```sh
permguard authority keys create billing --secret-out billing.key --expires 2027-01-01T00:00:00Z
permguard authority keys list billing
permguard authority keys delete billing pgak_ABCDEFGHIJKLMNOPQRST
```

## Tokens

`whoami` shows the token in use; `token` writes a token for the configured client to a file, or forgets or revokes the one it keeps; `tokens` lists and revokes the tokens issued.

```sh
permguard authority whoami [OPTIONS]
permguard authority token [OPTIONS] --out <FILE>
permguard authority token forget [OPTIONS]
permguard authority token revoke [OPTIONS]
permguard authority tokens list [OPTIONS]
permguard authority tokens revoke [OPTIONS] <JTI>
```

| Command         | What it does                                                                                       |
| --------------- | -------------------------------------------------------------------------------------------------- |
| `whoami`        | the token in use: its account, access key, scopes, `jti` and expiry; never the token               |
| `token --out`   | a token for the configured client, written to a new file only its owner reads                      |
| `token forget`  | drops the kept token: it stays valid until it expires, and the next command obtains another        |
| `token revoke`  | revokes the token in use, `--token-file`'s or the kept one, on every Plane, and drops it           |
| `tokens list`   | the tokens issued, never a token                                                                   |
| `tokens revoke` | revokes a token by its `jti`: `INVALID` in its status list, refused everywhere at the next refresh |

| Flag                   | Meaning                                                                          |
| ---------------------- | -------------------------------------------------------------------------------- |
| `--scope <SCOPE>`      | `token`: the operations asked, comma or space separated, narrowing the account's |
| `--lifetime <SECONDS>` | `token`: seconds, within the profile's maximum; an hour when absent              |
| `--account <ACCOUNT>`  | `tokens list`: only the tokens of this account                                   |
| `--status <STATUS>`    | `tokens list`: only `valid`, `invalid` or `suspended` tokens                     |

```sh
permguard authority whoami
permguard authority token --scope decision.evaluate --lifetime 600 --out token.jwt
permguard authority tokens list --account billing
permguard authority tokens revoke 0198f2aa-0000-7000-8000-000000000001
```

A bearer may always revoke its own token.

## admin-key

Makes a new access key for `admin`, offline, the server stopped: the way in when every key is lost.

```sh
permguard authority admin-key [OPTIONS] --secret-out <FILE>
```

| Flag                  | Meaning                                                                   |
| --------------------- | ------------------------------------------------------------------------- |
| `--volume <DIR>`      | the stopped Server's volume, its `working_dir`                            |
| `--secret-out <FILE>` | the new file the access key and its secret key are written to, owner-only |

```sh
permguard authority admin-key --volume /var/lib/permguard --secret-out admin.key
```

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="./decisions"><span>Previous</span><strong><b aria-hidden="true">←</b> Decisions &amp; Evidence</strong></a>
  <a class="pgx-pager__next" href="./operations"><span>Next</span><strong>Server Operations <b aria-hidden="true">→</b></strong></a>
</nav>
