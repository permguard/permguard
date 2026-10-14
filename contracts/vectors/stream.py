# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/stream.json (WP-5.1 to WP-5.4).

Computes the stream engine's records from the owner decisions of 2026-10-13 (the label tables in
status.md) with Python's standard library and `cryptography`, never by calling the Rust codecs, so
the Rust tests compare two implementations: a genesis run statement carrying a fence and a
successor after a fork naming its predecessor and the approved plan, both COSE_Sign1
`permguard.stream.run.v1` under a `host.operations` key (the RFC 8032 section 7.1 test 2 key),
their digests, a run end, a group of records, a record digest and two STATEs.
Ed25519 is deterministic, so every byte is fixed.

WP-5.2 adds two sealed batches of the genesis run, chained, each a flattened JWS over the RFC 8785
canonical JSON envelope under a `data.attest` key (the RFC 8032 section 7.1 test 1 key), the
signer spans naming that key, and a cutover pending at the next sequence.
"""
import base64, datetime, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SEED_OPERATIONS = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
OPERATIONS = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_OPERATIONS))
OPERATIONS_PUB = OPERATIONS.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these records use.
    if v is True: return b"\xf5"
    if v is False: return b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def sign1(content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = OPERATIONS.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

RUN = "permguard.stream.run.v1"
RUN_DIGEST = b"permguard.stream.run.v1\n"
DECISION_RECORD = b"permguard.decision.v1\n"
KID = b"host.operations:vector"
PRODUCER = bytes.fromhex("01a3185c50007111a111111111111111")
BOOT = bytes.fromhex("01a3185c50007222b222222222222222")
RUN_ID = bytes([0x31] * 16)
SUCCESSOR_ID = bytes([0x32] * 16)
RESOURCE = "plane/data/zone/zone-a/ledger/ledger-1"
MEMBERSHIP = bytes.fromhex("01a3185c50007333c333333333333333")

def sha(domain, data): return hashlib.sha256(domain + data).digest()

records = [b'{"n":1}', b'{"n":2}']
last_digest = sha(DECISION_RECORD, records[-1])
fence = {1: MEMBERSHIP, 2: "decisions", 3: 4}
genesis = cbor({1: "data", 2: "decisions", 3: 1, 4: RESOURCE, 5: PRODUCER, 6: RUN_ID, 7: BOOT,
                8: 1_800_000_000, 10: fence})
end = {1: RUN_ID, 2: 2, 3: last_digest}
approval = bytes([0x55] * 32)
successor = cbor({1: "data", 2: "decisions", 3: 1, 4: RESOURCE, 5: PRODUCER, 6: SUCCESSOR_ID,
                  7: BOOT, 8: 1_800_000_100, 9: end, 11: approval})
genesis_envelope = sign1(RUN, KID, genesis)
successor_envelope = sign1(RUN, KID, successor)
group = cbor({1: 1, 2: records})
state = cbor({1: RUN_ID, 2: sha(RUN_DIGEST, genesis_envelope), 3: 3, 4: 2, 5: 1, 6: 1, 7: 1})
state_pending = cbor({1: RUN_ID, 2: sha(RUN_DIGEST, genesis_envelope), 3: 3, 4: 2, 5: 0, 6: 0,
                      7: 1, 8: successor_envelope, 9: 2})

# WP-5.2: sealed batches.
SEED_ATTEST = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ATTEST = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_ATTEST))
ATTEST_PUB = ATTEST.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
ATTEST_KID = "data.attest:vector"
DECISION_BATCH = "permguard.decision.batch.v1"
GENESIS_HEAD = "sha256:" + "00" * 32

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def jcs(value):
    # RFC 8785 for what these records hold: ASCII member names and strings, integers.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def uuid(raw):
    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def digest_string(record): return "sha256:" + sha(DECISION_RECORD, record).hex()

def merkle_root(leaves):
    # RFC 6962: leaf = SHA-256(0x00 || the digest string), node = SHA-256(0x01 || l || r), an odd
    # level's last node promoted.
    level = [hashlib.sha256(b"\x00" + leaf.encode()).digest() for leaf in leaves]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2: nxt.append(level[-1])
        level = nxt
    return "sha256:" + level[0].hex()

ATTEST_JWK = {"alg": "EdDSA", "crv": "Ed25519", "kid": ATTEST_KID, "kty": "OKP",
              "use": "sig", "x": b64(ATTEST_PUB)}
CREATED = datetime.datetime.fromtimestamp(1_800_000_200, datetime.timezone.utc)

def seal(first, batch_records, previous):
    digests = [digest_string(record) for record in batch_records]
    last = first + len(batch_records) - 1
    envelope = {"descriptor_version": 1,
                "stream_key": {"plane": "data", "type": "decisions", "resource": RESOURCE,
                               "producer_host_id": uuid(PRODUCER)},
                "run": RUN_ID.hex(), "membership_id": uuid(MEMBERSHIP), "epoch": 4,
                "first_seq": first, "last_seq": last, "count": len(batch_records),
                "previous_head": previous, "head": digests[-1],
                "merkle_root": merkle_root(digests), "batch_id": f"{RUN_ID.hex()}-{first}",
                "created_at": CREATED.strftime("%Y-%m-%dT%H:%M:%SZ"), "key_set_epoch": 1}
    protected = b64(jcs({"typ": DECISION_BATCH, "alg": "EdDSA", "kid": ATTEST_KID}))
    payload = b64(jcs(envelope))
    signature = b64(ATTEST.sign(f"{protected}.{payload}".encode()))
    file = jcs({"signature": {"protected": protected, "payload": payload, "signature": signature},
                "records": [b64(record) for record in batch_records]})
    return envelope, file, digests[-1]

batch_records = records + [b'{"n":3}']
first_envelope, first_file, first_head = seal(1, batch_records[:2], GENESIS_HEAD)
second_envelope, second_file, _ = seal(3, batch_records[2:], first_head)
signers = cbor({1: [{1: RUN_ID, 2: [{1: 1, 2: ATTEST_KID, 3: jcs(ATTEST_JWK).decode()}]}]})
STREAM = f"data/decisions/{hashlib.sha256(RESOURCE.encode()).hexdigest()}/{RUN_ID.hex()}"
cutover = cbor({1: STREAM, 2: MEMBERSHIP, 3: "data.attest", 4: "data.attest:next", 5: 4,
                6: False})

# WP-5.3: the ingest.
STATEMENT = bytes.fromhex("a0")
ingest = {"ship": cbor({1: first_file, 2: STATEMENT}).hex(),
          "statement": STATEMENT.hex(),
          "answer_ok": cbor({1: "ok", 2: 2}).hex(),
          "answer_out_of_order": cbor({1: "out_of_order", 2: 2, 3: 3}).hex(),
          "consumer_state": cbor({1: 2, 2: 1}).hex(),
          "fork_mark": cbor({1: RUN_ID, 2: 3}).hex()}

# WP-5.4: fan-out.
fanout = {"subscription_active": cbor({1: MEMBERSHIP, 2: "decisions", 3: True,
                                       4: [{1: RUN_ID, 2: 2}], 5: 0}).hex(),
          "subscription_paused": cbor({1: MEMBERSHIP, 2: "decisions", 3: False, 4: [], 5: 1,
                                       6: 4}).hex(),
          "subscription_stopped": cbor({1: MEMBERSHIP, 2: "decisions", 3: True, 4: [], 5: 2,
                                        7: "fork"}).hex(),
          "pruned_mark": cbor({1: 2}).hex()}

out = {"comment": "Stream engine records (WP-5.1 to WP-5.4); see README.md and stream.py",
       "operations_public": OPERATIONS_PUB.hex(), "kid": KID.decode(),
       "producer_host_id": PRODUCER.hex(), "producer_boot_id": BOOT.hex(), "resource": RESOURCE,
       "membership_id": MEMBERSHIP.hex(),
       "genesis": {"run_id": RUN_ID.hex(), "payload": genesis.hex(),
                   "cose_sign1": genesis_envelope.hex(),
                   "digest": sha(RUN_DIGEST, genesis_envelope).hex()},
       "successor": {"run_id": SUCCESSOR_ID.hex(), "payload": successor.hex(),
                     "cose_sign1": successor_envelope.hex(), "approval": approval.hex()},
       "run_end": cbor(end).hex(),
       "records": [record.decode() for record in records],
       "last_record_digest": last_digest.hex(),
       "group": group.hex(),
       "state": state.hex(), "state_pending": state_pending.hex(),
       "batches": {"attest_jwk": ATTEST_JWK, "records": [r.decode() for r in batch_records],
                   "first": {"envelope": first_envelope, "file": first_file.decode()},
                   "second": {"envelope": second_envelope, "file": second_file.decode()},
                   "signers": signers.hex(), "cutover": cutover.hex(), "stream": STREAM},
       "ingest": ingest, "fanout": fanout}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
