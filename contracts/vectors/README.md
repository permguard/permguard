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

`identity.json` freezes the Host identity's records (WP-2.2): the identity document at epochs 1 and 2, the succession between them, `INIT`, its external witness and `BOOT`.
`identity.py` computes them under the owner decisions of 2026-10-08, with the RFC 8032 section 7.1 test 1 and test 2 keys for the two epochs; `crates/permguard-host/tests/identity_vectors.rs` reproduces them.
Each envelope's `kid` is its signing epoch in decimal ASCII.

`session.json` freezes a peer Host session (WP-2.3): `hello`, `challenge`, their digests, the transcript as each side signs it and the two proofs.
`session.py` computes them under the owner decisions of 2026-10-08, with the RFC 8032 section 7.1 test 1, 2 and 3 keys for Hosts A, B and C.
Its `refused` cases are proofs a verifier must refuse against the transcript it expects: a replay, a relay, a reflection and an unknown-key share; `crates/permguard-host/tests/session_vectors.rs` reproduces the bytes and refuses each case.

`secrets.json` freezes the secrets and zone derivations (WP-3.3): a root's witness, a Host-local key and audit pseudonym, a cursor key, a zone root, the distributed keys of a zone, and the shared pseudonym and input tag under them.
`secrets.py` computes them with the standard library alone, HKDF-SHA256 over the closed CBOR tuples of the keys architecture; `crates/permguard-host/tests/secrets_vectors.rs` reproduces them.

## How the values were computed

`generate.py` computes every value with Python's standard library and the `cryptography` package, from the published rules, without calling the Rust codecs.
Each codec crate's `tests/evidence_vectors.rs` reproduces the same bytes, so a passing test means two implementations agree.
Signatures use the RFC 8032 section 7.1 test 1 key, so they are deterministic, and its `kid` is the RFC 7638 thumbprint of RFC 8037 appendix A.3.

## Rules

A vector changes only with a protocol version: a codec that stops reproducing one is a codec that changed a format.
Running `generate.py`, `identity.py`, `session.py` and `secrets.py` again must print `evidence.json`, `identity.json`, `session.json` and `secrets.json` unchanged, and neither file is ever edited to make a test pass: `task check:vectors` (or `make check-vectors`) compares each with its generator.
The generator needs Python 3 and the `cryptography` package (`pip install cryptography`; the vectors were computed with version 50).
Target formats are not here: each is frozen by the package that designs it, as `status.md` lists under "Deferred format freezes".
