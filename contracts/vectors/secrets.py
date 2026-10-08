# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/secrets.json (WP-3.3).

Computes the secrets' witness, a Host-local key and pseudonym, a zone root, the distributed keys
of a zone and the shared pseudonym and input tag under them, from the keys architecture and the
owner decisions of 2026-10-08, with Python's standard library only and never by calling the Rust
code, so the Rust tests compare two implementations.
"""
import hashlib, hmac, json, struct, sys

def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + struct.pack(">H", n)
    if n < 2 ** 32: return bytes([major << 5 | 26]) + struct.pack(">I", n)
    return bytes([major << 5 | 27]) + struct.pack(">Q", n)

def cbor(v):
    # RFC 8949 core deterministic encoding, for the types these tuples use.
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return head(3, len(b)) + b
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    raise TypeError(v)

def hkdf(salt, ikm, info, length=32):
    # RFC 5869 with SHA-256.
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]

def mac(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()

LABEL = "permguard.kdf.v1"
WITNESS = b"permguard.secret.witness.v1\n"
PSEUDONYM = b"permguard.audit.pseudonym.v1\n"
INPUT = b"permguard.input.v1\n"

ROOT = bytes(range(32))
COORDINATOR_ROOT = bytes(range(32, 64))
HOST = bytes.fromhex("01a3185c500071119111111111111111")
OTHER_HOST = bytes.fromhex("01a3185c50007222a222222222222222")
ZONE = bytes.fromhex("01a3185c50007333b333333333333333")
LEDGER = bytes.fromhex("01a3185c50007444c444444444444444")

def host_local(root, owner, purpose, resource, version):
    info = cbor([LABEL, "host-local", purpose, owner, resource, version])
    return info, hkdf(owner, root, info)

def pseudonym(key, version, identifier_type, identifier):
    message = cbor([identifier_type, identifier.strip()])
    return "v%d:%s" % (version, mac(key, PSEUDONYM, message)[:16].hex())

out = {"comment": "Secrets and zone derivations (WP-3.3); see README.md and secrets.py",
       "root": ROOT.hex(), "coordinator_root": COORDINATOR_ROOT.hex(),
       "host": HOST.hex(), "other_host": OTHER_HOST.hex(), "zone": ZONE.hex(), "ledger": LEDGER.hex(),
       "witness": mac(ROOT, WITNESS).hex()}

info, key = host_local(ROOT, HOST, "audit.pseudonym", "host", 1)
_, other = host_local(ROOT, OTHER_HOST, "audit.pseudonym", "host", 1)
out["host_local"] = {"purpose": "audit.pseudonym", "resource": "host", "version": 1,
                     "info": info.hex(), "key": key.hex(),
                     "pseudonym": pseudonym(key, 1, "principal", " alice "),
                     "other_host_pseudonym": pseudonym(other, 1, "principal", "alice")}
info, cursor = host_local(ROOT, HOST, "stream.cursor", "decisions/acme/main", 1)
out["cursor"] = {"api": "decisions", "resource": "acme/main", "info": info.hex(), "key": cursor.hex()}

zone_info = cbor([LABEL, "zone-root", ZONE, 1])
zone_root = hkdf(HOST, COORDINATOR_ROOT, zone_info)
out["zone_root"] = {"version": 1, "info": zone_info.hex(), "key": zone_root.hex()}

def distributed(purpose, scope):
    info = cbor([LABEL, "zone-use", purpose, ZONE, scope, 1])
    return info, hkdf(HOST, zone_root, info)

info, users = distributed("audit.pseudonym", ZONE)
out["zone_pseudonym"] = {"info": info.hex(), "key": users.hex(),
                         "pseudonym": pseudonym(users, 1, "subject", "alice")}
info, tags = distributed("decision.commitment", LEDGER)
value = b'"HR"'
out["input_tag"] = {"info": info.hex(), "key": tags.hex(), "value": value.decode(),
                    "tag": mac(tags, INPUT, value).hex()}

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
