<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Golden vectors

`evidence.json` freezes today's evidence, stream and statement formats: the bytes a deployed Permguard writes and reads.

| Section           | Artifact                                                            | Reproduced by                      |
| ----------------- | ------------------------------------------------------------------- | ---------------------------------- |
| `decision_record` | decision record digest under `permguard.decision.v1\n`              | `permguard-decisions`              |
| `decision_batch`  | today's decision batch: flattened JWS, protected `{alg, kid}`       | `permguard-decisions`              |
| `input_tag`       | keyed input tag under `permguard.input.v1\n`                        | `permguard-decisions`              |
| `event_digests`   | event record, occurrence and history digests                        | `permguard-events`                 |
| `event_batch`     | today's event batch: compact JWS, protected `{alg, typ, kid}`       | `permguard-events`                 |
| `merkle`          | RFC 6962 batch roots                                                | `permguard-decisions`, `-stream`   |
| `cursor_v1`       | today's cursor and its filter digest                                | `permguard-stream`                 |
| `pseudonym`       | today's audit pseudonym                                             | `permguard-std`                    |
| `head_statement`  | today's signed NOTP head statement, COSE_Sign1                      | `permguard-objects`                |
| `key_set_digest`  | a pointer to the WP-0.4 vectors in `permguard-objects`              | `permguard-objects`                |

## How the values were computed

`generate.py` computes every value with Python's standard library and the `cryptography` package, from the published rules, without calling the Rust codecs.
Each codec crate's `tests/evidence_vectors.rs` reproduces the same bytes, so a passing test means two implementations agree.
Signatures use the RFC 8032 section 7.1 test 1 key, so they are deterministic, and its `kid` is the RFC 7638 thumbprint of RFC 8037 appendix A.3.

## Rules

A vector changes only with a protocol version: a codec that stops reproducing one is a codec that changed a format.
Running `generate.py` again must print `evidence.json` unchanged, and it is never edited to make a test pass: `task check:vectors` (or `make check-vectors`) compares the two.
The generator needs Python 3 and the `cryptography` package (`pip install cryptography`; the vectors were computed with version 50).
Target formats are not here: each is frozen by the package that designs it, as `status.md` lists under "Deferred format freezes".
