<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# CBOR label registries

Every signed or canonical CBOR artifact whose labels the code and the normative documents already fix has a registry here, one JSON file per artifact family.
A registry names each map's labels with their types and cardinalities, and each tuple's positions.
Another implementation reads these files instead of the Rust source to produce the same bytes.

`crates/permguard-conformance/tests/cbor_registries.rs` keeps them true.
It builds a value of every root through the owning crate's public API, decodes the bytes and checks them against the registry.
An unregistered label, a missing required label or a value of another type fails.
The test then adds one unknown label to every closed map, and one trailing element to every tuple, and requires the owning decoder to refuse the result.
A new file in this directory must be wired into that test, or the test fails.

## Format

```json
{
  "artifact": "human name",
  "authority": "the normative document anchor and the code that fix the labels",
  "encoding": "deterministic CBOR (RFC 8949 core deterministic), integers in the signed 64-bit range",
  "maps": {
    "<map name>": {
      "keys": "int",
      "fields": [{ "label": 1, "name": "kind", "type": "uint", "occurs": "required", "note": "optional prose" }]
    }
  },
  "arrays": { "<tuple name>": [{ "position": 0, "name": "label", "type": "text" }] },
  "root": "<map or tuple name, or a list of them>"
}
```

`keys` is `int` for integer labels and `text` for text keys; a text-keyed map lists the key itself as its `label`.
`occurs` is `required` when the writer always emits the field and `optional` when it emits the field only when it has a value.
`root` is a list when one file holds several top-level artifacts, such as the three object kinds or the NOTP messages.

| Type           | Meaning                                                      |
| -------------- | ------------------------------------------------------------ |
| `uint`         | an integer from 0 to 2^63-1                                  |
| `int`          | an integer in the signed 64-bit range                        |
| `text`         | a UTF-8 text string                                          |
| `bytes`        | a byte string                                                |
| `bool`         | `true` or `false`                                            |
| `digest`       | text `sha256:` followed by 64 lowercase hex characters       |
| `array<T>`     | an array whose every element is a `T`                        |
| `map<text,T>`  | a map with text keys chosen by the author, every value a `T` |
| `map:<name>`   | the registered map `<name>` of the same file                 |
| `array:<name>` | the registered tuple `<name>` of the same file               |
| `cbor:<T>`     | a byte string holding the canonical encoding of a `T`        |
| `const:<json>` | exactly this JSON value: a text, an integer or a boolean     |
| `scalar`       | a text, an unsigned integer or a boolean                     |

## Compatibility rule

A label, once registered, keeps its name, its type and its meaning for as long as the artifact's version exists.
A new field is a new label, never a reinterpretation of an existing label.
A removed field retires its label, and a retired label is never reused.
A change that cannot follow these rules is a new artifact version, with a new media type, format string or KDF label.

## Unknown-field policy

Every registered map that a reader decodes is closed: it refuses a label it does not know, at any depth, rather than skipping it.
The sealing contexts are associated data that the code builds and never parses: they are closed on the writing side only.
A field a later writer adds may change what is enforced, so a reader that cannot honour it must not act on the rest.
A tuple is closed the same way: another length is refused.
Forward compatibility is carried by versions, never by silently ignored fields.

## Frozen registries

| File                  | Artifact                                        | Roots                                                                                              |
| --------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `objects.json`        | blob, tree and commit                           | `blob`, `tree`, `commit`                                                                           |
| `manifest.json`       | ledger manifest blob payload                    | `manifest`                                                                                         |
| `head-statement.json` | today's signed head statement                   | `cose_sign1`                                                                                       |
| `notp.json`           | NOTP bodies and the `GET ref` answer            | one per message                                                                                    |
| `sealed-key.json`     | sealed private key and its two sealing contexts | `sealed_key`, `content_context`, `wrap_context`                                                    |
| `key-set.json`        | key-set digest input                            | `key_set`                                                                                          |
| `kdf.json`            | HKDF `info` tuples                              | `host_local_info`, `zone_root_info`, `zone_use_info`                                               |
| `grant.json`          | Host API grant record and its transitions       | `grant_record`, `transition`                                                                       |
| `layout.json`         | layout manifest, migration intent and commit    | `layout_manifest`, `migration_intent`, `migration_commit`                                          |
| `audit.json`          | audit record and trail metadata                 | `audit_record`, `trail_meta`                                                                       |
| `mutation.json`       | security mutation journal entries and snapshot  | `mutation_intent`, `mutation_commit`, `mutation_failed`, `mutation_projected`, `mutation_snapshot` |

`notp.json` also registers `ref_answer`, the `GET …/refs/{name}` body that the control plane writes inline and the client reads with a private closed decoder.
The `statement` members of the NOTP bodies are the COSE_Sign1 bytes that `head-statement.json` registers.

## Not frozen: blocked

These artifacts have no normative byte shape yet, so no labels can be frozen for them.
Each one is owned by the phase that designs it, and WP-0.7 writes no golden vector for it until then.

| Artifact                                          | Open question                                                                                                                                                                        |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Host identity document                            | no byte shape: which members, their labels, types and cardinalities                                                                                                                  |
| Host proof transcript `permguard.host.session.v1` | member names only (`1-architecture/2-architecture-server-host-identity.md`); no labels, types or cardinalities, and `membership_id?` and `task?` have no stated encoding when absent |
| succession record                                 | no byte shape                                                                                                                                                                        |
| ring binding                                      | no byte shape                                                                                                                                                                        |
| membership manifest                               | no byte shape                                                                                                                                                                        |
| lease                                             | no byte shape                                                                                                                                                                        |
| grant record                                      | member names only (`GrantRecord` in `1-architecture/1-architecture-server.md`); no labels, types, cardinalities or encoding of `selector` and `constraints`                          |
| operation plan `permguard.operation.plan.v1`      | no byte shape: the bound members are named in prose only                                                                                                                             |
| snapshot manifest                                 | no byte shape                                                                                                                                                                        |
| ledger export manifest                            | no byte shape                                                                                                                                                                        |
| stream run                                        | no byte shape                                                                                                                                                                        |
| audit checkpoint `permguard.audit.checkpoint.v1`  | member names only; no labels, types or cardinalities                                                                                                                                 |
| target NOTP head statement                        | labels and types of the added `authority_host_id`, `ref_digest`, `ring_epoch` and `key_set_digest`, and whether the statement moves to a new content type                            |
| `RefState`                                        | labels, types and cardinality of `head`, `counter` and `previous_ref_digest` inside `ref_digest`; today a ref is stored as JSON and has no CBOR form                                 |
| manifest partition `interfaces`                   | the integer label of the new partition key and the type of its entries                                                                                                               |
