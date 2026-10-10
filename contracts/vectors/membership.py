# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/membership.json (WP-4.1).

Computes the membership records from the owner decisions of 2026-10-09 (the label tables in
status.md) with Python's standard library and `cryptography`, never by calling the Rust codecs, so
the Rust tests compare two implementations. The coordinator's `host.operations` key is the RFC 8032
section 7.1 test 2 key, its identity the test 1 key; the member's identity is the test 3 key and
its data.attest key the test 1024 key.
Ed25519 is deterministic, so every byte is fixed.
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def key(seed_hex):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return k, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

SEED_COORDINATOR = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
SEED_OPERATIONS = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
SEED_MEMBER = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
SEED_MEMBER_RING = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
_, COORDINATOR_PUB = key(SEED_COORDINATOR)
_, MEMBER_RING_PUB = key(SEED_MEMBER_RING)
OPERATIONS, OPERATIONS_PUB = key(SEED_OPERATIONS)
_, MEMBER_PUB = key(SEED_MEMBER)

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these records use.
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)

def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def digest(domain, data): return "sha256:" + hashlib.sha256(domain + data).hexdigest()

def fingerprint(pub): return "sha256:" + hashlib.sha256(pub).hexdigest()

def sign1(signer, content_type, kid, payload):
    # COSE_Sign1, protected {1 alg EdDSA, 3 content type, 4 kid}, empty unprotected, no AAD.
    protected = cbor({1: -8, 3: content_type, 4: kid})
    signature = signer.sign(cbor(["Signature1", protected, b"", payload]))
    return cbor([protected, {}, payload, signature])

def uuid_v7(byte):
    # A UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, version 7, the variant, ten equal bytes.
    h = bytearray((1_800_000_000_000).to_bytes(8, "big")[2:] + bytes([byte]) * 10)
    h[6] = (h[6] & 0x0F) | 0x70
    h[8] = (h[8] & 0x3F) | 0x80
    return bytes(h)

COORDINATOR, MEMBER = uuid_v7(0x11), uuid_v7(0x22)
INVITE_ID, MEMBERSHIP_ID = uuid_v7(0x33), uuid_v7(0x44)
AT = 1_800_000_000
TOKEN = bytes(range(32))
# The invitation's key pair, derived from its token: the coordinator keeps only the public key.
TOKEN_KEY, TOKEN_PUB = key(hashlib.sha256(b"permguard.membership.token-key.v1\n" + TOKEN).hexdigest())
EXPORTER = bytes([0xE1]) * 32

coordinator_ref = {1: COORDINATOR, 2: 1, 3: fingerprint(COORDINATOR_PUB)}
member_ref = {1: MEMBER, 2: 1, 3: fingerprint(MEMBER_PUB)}
limits = {1: 1_048_576, 2: 4, 3: 600, 4: 1000, 5: 2_592_000}
task = {1: "decisions", 2: "decisions.ship", 3: "member", 4: "coordinator", 5: "plane/data/*",
        6: ["decision"], 7: True, 8: limits, 9: []}
lease_policy = {1: 3600, 2: 86_400, 3: 30, 4: 2_592_000, 5: 7_776_000}

invitation = cbor({1: INVITE_ID, 2: TOKEN_PUB, 3: "plane/data/*", 4: [task], 5: AT + 86_400,
                   6: fingerprint(MEMBER_PUB), 8: 1, 9: AT, 10: "spiffe://acme/operators/root"})

# The token proof: the token key's Ed25519 signature over the domain, both Host ids and the
# connection's exporter.
token_proof = TOKEN_KEY.sign(b"permguard.membership.enroll.v1\n" + COORDINATOR + MEMBER + EXPORTER)

# The ring statement the member presents: its data.attest set, one key, and the binding its
# identity signs (keys.py's shape).
RING = "data.attest"
SUITE = "pg-ed25519-sha256-v1"
def thumbprint(pub):
    return b64url(hashlib.sha256(
        ('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64url(pub)).encode()).digest())
ring_thumbprint = thumbprint(MEMBER_RING_PUB)
ring_kid = RING + ":" + ring_thumbprint
ring_jwk = json.dumps({"kid": ring_kid, "kty": "OKP", "crv": "Ed25519", "x": b64url(MEMBER_RING_PUB),
                       "alg": "EdDSA", "use": "sig"}, separators=(",", ":"))
ring_digest = hashlib.sha256(b"permguard.key-set.v1\n" + cbor(
    {"ring": RING, "epoch": 1, "algorithm": SUITE, "keys_by_thumbprint": [ring_thumbprint]})).digest()
_MEMBER_KEY, _ = key(SEED_MEMBER)
ring_binding = sign1(_MEMBER_KEY, "permguard.host.ring-binding.v1", b"1",
                     cbor({1: MEMBER, 2: RING, 3: 1, 4: ring_digest, 5: SUITE, 6: AT,
                           7: AT + 30 * 86400}))
ring_statement = {1: RING, 2: 1, 3: SUITE, 4: [ring_jwk], 5: ring_binding}

request = cbor({1: INVITE_ID, 2: token_proof, 3: "plane/data/*", 4: [task], 5: member_ref,
                6: [ring_statement]})
request_digest = digest(b"permguard.membership.request.v1\n", request)

# The member's hello and the transcript of an enrollment session: 9 request_digest in the hello,
# 16 in the transcript.
NONCE_A, NONCE_B = bytes([0xA1]) * 16, bytes([0xB1]) * 16
EXPIRES = AT + 60
hello = cbor({1: 1, 2: MEMBER, 3: 1, 4: "production", 5: NONCE_A, 6: "enroll", 9: request_digest})
challenge = cbor({1: COORDINATOR, 2: 1, 3: "production", 4: NONCE_B, 5: EXPIRES})
transcript = cbor({1: "permguard.host.session.v1", 2: MEMBER, 3: COORDINATOR, 4: 1, 5: 1,
                   6: NONCE_A, 7: NONCE_B, 10: "enroll", 11: EXPIRES, 12: EXPORTER,
                   13: digest(b"permguard.host.session.hello.v1\n", hello),
                   14: digest(b"permguard.host.session.challenge.v1\n", challenge),
                   15: "initiator", 16: request_digest})

# The genesis manifest and its successor, under the coordinator's operations key.
operations_kid = ("host.operations:" + thumbprint(OPERATIONS_PUB)).encode()
pin = {1: "member", 2: RING, 3: 1, 4: ring_digest, 5: ring_binding}

def manifest(epoch, status, previous):
    payload = {1: MEMBERSHIP_ID, 2: coordinator_ref, 3: member_ref, 4: "plane/data/*", 5: [task],
               6: "production", 9: [pin], 10: epoch, 11: lease_policy, 13: AT + epoch,
               14: AT + 365 * 86_400, 15: status}
    if previous is not None:
        payload[12] = previous
    return cbor(payload)

genesis_payload = manifest(1, "active", None)
genesis = sign1(OPERATIONS, "permguard.membership.manifest.v1", operations_kid, genesis_payload)
genesis_digest = digest(b"permguard.membership.manifest.v1\n", genesis)
successor_payload = manifest(2, "suspended", genesis_digest)
successor = sign1(OPERATIONS, "permguard.membership.manifest.v1", operations_kid, successor_payload)

# The pending membership an enrollment creates.
pending = cbor({1: MEMBERSHIP_ID, 2: INVITE_ID, 3: coordinator_ref, 4: member_ref,
                5: "plane/data/*", 6: [task], 7: "production", 8: [ring_statement], 9: AT + 1})

# Three journal entries, each carrying the record it concerns and chained to the one before; the
# first to the digest of an empty journal.
GENESIS_CHAIN = digest(b"permguard.membership.journal.v1\n", b"")
first = cbor({1: 1, 2: "invited", 3: INVITE_ID, 5: AT, 7: GENESIS_CHAIN, 8: invitation})
second = cbor({1: 2, 2: "enrolled", 3: MEMBERSHIP_ID, 5: AT + 1,
               7: digest(b"permguard.membership.journal.v1\n", first), 8: pending})
third = cbor({1: 3, 2: "manifest", 3: MEMBERSHIP_ID, 4: 1, 5: AT + 1, 6: bytes([0x55]) * 16,
              7: digest(b"permguard.membership.journal.v1\n", second), 8: genesis})

out = {"comment": "Membership records (WP-4.1); see README.md and membership.py",
       "coordinator": {"host_id": COORDINATOR.hex(), "seed": SEED_COORDINATOR,
                       "public_key": COORDINATOR_PUB.hex(), "fingerprint": fingerprint(COORDINATOR_PUB)},
       "member": {"host_id": MEMBER.hex(), "seed": SEED_MEMBER, "public_key": MEMBER_PUB.hex(),
                  "fingerprint": fingerprint(MEMBER_PUB)},
       "operations": {"seed": SEED_OPERATIONS, "public_key": OPERATIONS_PUB.hex(),
                      "kid": operations_kid.decode()},
       "invite_id": INVITE_ID.hex(), "membership_id": MEMBERSHIP_ID.hex(),
       "token": TOKEN.hex(), "token_key": TOKEN_PUB.hex(), "exporter": EXPORTER.hex(),
       "invitation": invitation.hex(),
       "token_proof": token_proof.hex(),
       "ring_statement": {"jwk": ring_jwk, "binding": ring_binding.hex(), "digest": ring_digest.hex()},
       "request": {"bytes": request.hex(), "digest": request_digest},
       "hello": hello.hex(), "challenge": challenge.hex(), "transcript_initiator": transcript.hex(),
       "manifest_genesis": {"payload": genesis_payload.hex(), "cose_sign1": genesis.hex(),
                            "digest": genesis_digest},
       "manifest_successor": {"payload": successor_payload.hex(), "cose_sign1": successor.hex()},
       "pending": pending.hex(),
       "journal": {"genesis_chain": GENESIS_CHAIN, "first": first.hex(), "second": second.hex(),
                   "third": third.hex()}}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
