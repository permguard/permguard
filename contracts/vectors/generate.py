# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/evidence.json (WP-0.7).

Computes every value from the published rules with Python's standard library and `cryptography`,
never by calling the Rust codecs, so the Rust tests compare two implementations.
"""
import base64, hashlib, hmac, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# RFC 8032 section 7.1 test 1.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert PUB.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwk_thumbprint(pub):
    # RFC 7638 for an OKP key: members crv, kty, x in lexicographic order.
    doc = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64(pub)
    return b64(hashlib.sha256(doc.encode()).digest())

KID = jwk_thumbprint(PUB)
assert KID == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", KID  # RFC 8037 appendix A.3

def jcs(value):
    # RFC 8785 for the values used here: ASCII strings, non-negative integers, objects, arrays,
    # booleans and null; ASCII keys sort the same by code unit as by UTF-16 code unit.
    def walk(v):
        if isinstance(v, bool) or v is None or isinstance(v, int) or isinstance(v, str):
            return v
        if isinstance(v, list): return [walk(x) for x in v]
        if isinstance(v, dict): return {k: walk(v[k]) for k in sorted(v)}
        raise TypeError(v)
    for s in json.dumps(value, ensure_ascii=False):
        assert ord(s) < 128
    return json.dumps(walk(value), separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode()

def domain_digest(domain, value):
    return "sha256:" + hashlib.sha256(domain.encode() + jcs(value)).hexdigest()

def merkle_root(leaves):
    level = [hashlib.sha256(b"\x00" + leaf.encode()).digest() for leaf in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return "sha256:" + level[0].hex()

out = {
    "comment": [
        "Golden vectors of today's evidence, stream and statement formats (WP-0.7). Computed independently of the Rust codecs, from the published rules; every codec crate reproduces them.",
        "A vector changes only with a protocol version. Target formats are frozen by the packages that design them (status.md, Deferred format freezes).",
        "Signing key: RFC 8032 section 7.1 test 1 (`seed`), Ed25519, deterministic; `kid` is its RFC 7638 thumbprint (RFC 8037 appendix A.3).",
    ],
    "key": {"seed": SEED.hex(), "public": PUB.hex(), "kid": KID},
}

# ---- decisions ---------------------------------------------------------------------------------
DEC_DOMAIN = "permguard.decision.v1\n"
GENESIS = "sha256:" + "0" * 64
dec_stream = {"id": "data-plane-7f3a", "instance": "01931f2c"}
# Records the codec accepts (`permguard_decisions::record::Record`), in the evidence contract's
# shape: a marker opening the stream, then a decision. The decision carries a member this version
# does not know: the digest covers it verbatim.
dec_records = [
    {"v": 1, "stream": dec_stream, "seq": 1, "prev": GENESIS, "kind": "marker",
     "at": "2026-10-05T10:00:00Z", "pdp": {"version": "0.1.0", "engines": {"cedar": "4.11.0"}},
     "sampling": {"permits": "1.0"}, "commitments": {"alg": "HMAC-SHA256", "key_version": "v1"}},
    {"v": 1, "stream": dec_stream, "seq": 2, "prev": None, "kind": "decision",
     "id": "decision-0001", "at": "2026-10-05T10:00:01Z", "pdp": {"version": "0.1.0"},
     "store": {"zone": "zone-a", "ledger": "ledger-1", "profile": "default", "counter": 3,
               "commit": "sha256:" + hashlib.sha256(b"commit").hexdigest()},
     "subject": {"type": "User", "id": "v1:5c2e"}, "resource": {"type": "Document", "id": "budget"},
     "action": {"name": "read"}, "inputs": {"context": "hmac-sha256:v1:" + "ab" * 32, "external": []},
     "decision": True, "policies": ["policy-1"], "reason": {"code": "permit"}, "latency_us": 321,
     "retained_by_newer_producer": "unknown to this version, digested verbatim"},
]
dec_records[1]["prev"] = domain_digest(DEC_DOMAIN, dec_records[0])
dec_digests = [domain_digest(DEC_DOMAIN, r) for r in dec_records]
dec_envelope = {
    "stream": dec_stream, "first_seq": 1, "last_seq": 2, "count": 2,
    "previous_head": GENESIS, "head": dec_digests[-1], "merkle_root": merkle_root(dec_digests),
    "sampling": {"permits": "1"}, "at": "2026-10-05T10:00:02Z",
}
dec_protected = ('{"alg":"EdDSA","kid":"%s"}' % KID).encode()  # field order of the struct, no typ
dec_payload = jcs(dec_envelope)
dec_input = b64(dec_protected) + "." + b64(dec_payload)
dec_sig = KEY.sign(dec_input.encode())
out["decision_record"] = [
    {"name": f"record {i + 1}", "record": r, "digest": d} for i, (r, d) in enumerate(zip(dec_records, dec_digests))
]
out["decision_batch"] = {
    "name": "today's batch: flattened JWS, protected {alg, kid} without typ",
    "records": dec_records,
    "envelope": dec_envelope,
    "envelope_jcs": dec_payload.decode(),
    "protected": b64(dec_protected),
    "payload": b64(dec_payload),
    "signature": b64(dec_sig),
}

# ---- input tag ---------------------------------------------------------------------------------
INPUT_DOMAIN = "permguard.input.v1\n"
tag_key = bytes(range(32))
tag_value = {"principal": {"id": "alice", "type": "user"}, "resource": {"id": "budget", "type": "document"}}
tag = hmac.new(tag_key, INPUT_DOMAIN.encode() + jcs(tag_value), hashlib.sha256).hexdigest()
out["input_tag"] = {"key": tag_key.hex(), "version": "v7", "value": tag_value,
                    "tag": f"hmac-sha256:v7:{tag}"}

# ---- events ------------------------------------------------------------------------------------
EV_REC = "permguard.event.record.v1\n"
EV_OCC = "permguard.event.occurrence.v1\n"
EV_HIS = "permguard.event.history.v1\n"
occurrence = {"id": "evt-0001", "kind": "request", "subject": {"id": "alice", "type": "User"},
              "occurred_at": "2026-10-05T09:59:00Z"}
# The history key as the codec digests it: pin names and their canonical typed values.
history = {"pins": ["subject.id"], "values": ["\"alice\""]}
ev_stream = {"producer": {"class": "permguard.event.producer.data-plane.v1", "id": "data-plane-7f3a",
                          "instance": "01931f2c"}, "zone": "zone-a", "ledger": "ledger-1"}
# A record `permguard_events::record::validate` accepts.
ev_records = [
    {"v": 1, "record_type": "permguard.event.record.v1", "stream": ev_stream, "seq": 1,
     "prev": GENESIS, "event_type": "permguard.dogwood.event.v1", "event_id": "evt-0001",
     "occurrence_digest": domain_digest(EV_OCC, occurrence), "kind": "request",
     "profile": "default", "policy_partitions": ["main"],
     "commit": "sha256:" + hashlib.sha256(b"commit").hexdigest(),
     "history_key": {"pins": history["pins"], "values": history["values"],
                     "digest": domain_digest(EV_HIS, history)},
     "occurred_at": "2026-10-05T09:59:00Z", "observed_at": "2026-10-05T10:00:00Z",
     "event": occurrence},
]
ev_digests = [domain_digest(EV_REC, r) for r in ev_records]
ev_envelope = {
    "stream": ev_stream, "first_seq": 1, "last_seq": 1, "count": 1, "previous_head": GENESIS,
    "head": ev_digests[-1], "merkle_root": merkle_root(ev_digests),
    "event_types": ["permguard.dogwood.event.v1"],
    "record_version": 1, "at": "2026-10-05T10:00:01Z",
}
ev_protected = ('{"alg":"EdDSA","typ":"permguard.event.batch.v1","kid":"%s"}' % KID).encode()
ev_payload = jcs(ev_envelope)
ev_input = b64(ev_protected) + "." + b64(ev_payload)
ev_sig = KEY.sign(ev_input.encode())
out["event_digests"] = {
    "occurrence": occurrence, "occurrence_digest": domain_digest(EV_OCC, occurrence),
    "history": history, "history_digest": domain_digest(EV_HIS, history),
    "record": ev_records[0], "record_digest": ev_digests[0],
}
out["event_batch"] = {
    "name": "today's batch: compact JWS, protected {alg, typ, kid} in field order",
    "records": ev_records, "envelope": ev_envelope, "envelope_jcs": ev_payload.decode(),
    "protected": b64(ev_protected), "payload": b64(ev_payload), "signature": b64(ev_sig),
    "compact": f"{b64(ev_protected)}.{b64(ev_payload)}.{b64(ev_sig)}",
}

# ---- merkle ------------------------------------------------------------------------------------
leaves = ["sha256:" + hashlib.sha256(bytes([i])).hexdigest() for i in range(5)]
out["merkle"] = [{"name": f"{n} leaves", "leaves": leaves[:n], "root": merkle_root(leaves[:n])} for n in (1, 2, 3, 5)]

# ---- pseudonym (today) ---------------------------------------------------------------------------
ps_key = bytes(range(32, 64))
ps_value = "alice@example.com"
out["pseudonym"] = {"name": "today's pseudonym: no domain, undivided key", "key": ps_key.hex(),
                    "key_version": "v3", "identifier": ps_value,
                    "pseudonym": "v3:" + hmac.new(ps_key, ps_value.encode(), hashlib.sha256).digest()[:16].hex()}

# ---- cursor v1 (today) ---------------------------------------------------------------------------
FILTERS = "permguard.stream.filters.v1\n"
filters = {"event_types": ["login"], "subject": "alice"}
filter_digest = "sha256:" + hashlib.sha256(FILTERS.encode() + jcs(filters)).hexdigest()
cursor = {"v": 1, "api": "events", "scope": "zone-a/ledger-1", "filters": filter_digest,
          "positions": {"data-plane-7f3a": {"segment": 1, "offset": 2}},
          "frontier": {"v": 1, "covered": {"data-plane-7f3a": 3}}}
# serde field order of `Cursor`: v, api, scope, filters, [until], positions, frontier
cursor_json = json.dumps(cursor, separators=(",", ":")).encode()
cur_key = bytes(range(64, 96))
c = b64(cursor_json)
m = b64(hmac.new(cur_key, c.encode(), hashlib.sha256).digest())
sealed = json.dumps({"c": c, "m": m}, separators=(",", ":")).encode()
out["cursor_v1"] = {"name": "today's cursor: HMAC over the encoded body, no prefix",
                    "key": cur_key.hex(), "filters": filters, "filter_digest": filter_digest,
                    "cursor": cursor, "body": cursor_json.decode(), "token": b64(sealed)}

# ---- head statement (today) ----------------------------------------------------------------------
def cbor_head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 2**32: return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
def cbor(v):
    if isinstance(v, int):
        return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)
    if isinstance(v, str): b = v.encode(); return cbor_head(3, len(b)) + b
    if isinstance(v, bytes): return cbor_head(2, len(v)) + v
    if isinstance(v, list): return cbor_head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor(k), cbor(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return cbor_head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(v)
statement = {1: "zone-a", 2: "ledger-1", 3: "refs/heads/main",
             4: "sha256:" + hashlib.sha256(b"commit").hexdigest(), 5: 7, 6: 1791194400}
kid_bytes = KID.encode()
protected = cbor({1: -8, 4: kid_bytes})
payload = cbor(statement)
sig_structure = cbor(["Signature1", protected, b"", payload])
signature = KEY.sign(sig_structure)
sign1 = cbor([protected, {}, payload, signature])
out["head_statement"] = {"name": "today's signed head statement",
                         "zone": "zone-a", "ledger": "ledger-1", "ref": "refs/heads/main",
                         "digest": statement[4], "counter": 7, "signed_at": 1791194400,
                         "kid": KID, "protected": protected.hex(), "payload": payload.hex(),
                         "sig_structure": sig_structure.hex(), "cose_sign1": sign1.hex()}

out["key_set_digest"] = {
    "name": "frozen by WP-0.4; the vectors live with the rest of the cryptographic profile",
    "file": "crates/permguard-objects/tests/vectors/crypto.json",
    "section": "key_set_digest",
}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
