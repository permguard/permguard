# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

"""Independent generator for contracts/vectors/signed-response.json (WP-6.6).

Computes every value from the published rules (3-data-plane/2-data-plane-pdp.md, signed
response) and the decisions recorded in status.md, with Python's standard library and
`cryptography`, never by calling the Rust code, so the Rust tests compare two implementations.
"""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# RFC 8032 section 7.1 test 1: a published throwaway key, the `data.attest` key of these vectors.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert PUB.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
KID = "data-attest-vector-1"

AUDIENCE = "spiffe://acme/pep"
NONCE = "AAECAwQFBgcICQoLDA0ODw"
ISSUED = 1_790_000_000
VALIDITY = 300
SKEW = 30


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jcs(value):
    # RFC 8785 for the values used here: ASCII strings, booleans, null, small integers, objects
    # and arrays; members sorted, no white space.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(domain, value):
    return "sha256:" + hashlib.sha256(domain + jcs(value)).hexdigest()


def rfc3339(seconds):
    import datetime
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entity(body):
    held = {"type": body["type"], "id": body["id"]}
    if "properties" in body:
        held["properties"] = body["properties"]
    return held


def normalized(request):
    """The normalized request the request digest covers (status.md, WP-6.6 decisions)."""
    def evaluation(asked, inherited, request_id):
        held = {
            "subject": entity(asked.get("subject", inherited.get("subject"))),
            "resource": entity(asked.get("resource", inherited.get("resource"))),
            "action": asked.get("action", inherited.get("action")),
            "partition_inputs": asked.get("partition_inputs", inherited.get("partition_inputs", {})),
            "request_id": request_id,
        }
        context = asked.get("context", inherited.get("context"))
        if context is not None:
            held["context"] = context
        return held

    if "evaluations" in request:
        evaluations = [evaluation(asked, request, asked.get("request_id")) for asked in request["evaluations"]]
    else:
        evaluations = [evaluation({}, request, request.get("request_id"))]
    semantic = request.get("options", {}).get("evaluations_semantic", "execute_all")
    return {
        "interface": "permguard.api.pdp.native.v1",
        "store": {"zone": request["zone"], "ledger": request["ledger"],
                  "profile": request.get("profile", "default")},
        "semantic": semantic,
        "request_id": request.get("request_id"),
        "request_nonce": request.get("request_nonce"),
        "asserted_principal": entity(request["principal"]) if "principal" in request else None,
        "evaluations": evaluations,
    }


POLICY = {
    "authority_host_id": "01937000-0000-7000-8000-00000000a0a0",
    "zone_id": "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c",
    "ledger_id": "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5d",
    "ref": "main",
    "commit": "sha256:" + "b" * 64,
    "counter": "1",
    "profile": "default",
}


def evidence(record_id, sequence):
    return {"mode": "required", "status": "durable", "record_id": record_id,
            "position": {"host_id": "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b",
                         "run": "0102030405060708090a0b0c0d0e0f10", "sequence": str(sequence)}}


def context(record_id, sequence):
    return {"id": record_id,
            "reason_admin": {"code": "200", "message": "permitted"},
            "reason_user": {"code": "200", "message": "permitted"},
            "policies": ["p-1"],
            "evidence": evidence(record_id, sequence)}


def signed(request, answer, request_ids, signed_evidence):
    payload = {
        "v": 1,
        "interface": "permguard.api.pdp.native.v1",
        "request_digest": digest(b"permguard.decision.request.v1\n", normalized(request)),
        "request_nonce": request["request_nonce"],
        "request_ids": request_ids,
        "audience": AUDIENCE,
        "policy": POLICY,
        "decision": answer["decision"],
        "response_digest": digest(b"permguard.decision.response-body.v1\n", answer),
        "evidence": signed_evidence,
        "issued_at": rfc3339(ISSUED),
        "expires_at": rfc3339(ISSUED + VALIDITY),
    }
    protected = b64(jcs({"alg": "EdDSA", "kid": KID, "typ": "permguard.decision.response.v1"}))
    body = b64(jcs(payload))
    signature = b64(KEY.sign(("%s.%s" % (protected, body)).encode()))
    response = dict(answer)
    response["attestation"] = {"protected": protected, "payload": body, "signature": signature}
    return payload, response


SINGLE_REQUEST = {
    "zone": "acme", "ledger": "main-ledger",
    "subject": {"type": "user", "id": "alice"},
    "resource": {"type": "document", "id": "budget"},
    "action": {"name": "read"},
    "request_id": "r-1",
    "request_nonce": NONCE,
}
SINGLE_ANSWER = {"decision": True, "request_id": "r-1", "context": context("dec-1", 7)}

BATCH_REQUEST = {
    "zone": "acme", "ledger": "main-ledger",
    "subject": {"type": "user", "id": "alice"},
    "resource": {"type": "document", "id": "budget"},
    "action": {"name": "read"},
    "evaluations": [{"request_id": "one"}, {"resource": {"type": "document", "id": "other"}}],
    "request_nonce": NONCE,
}
BATCH_ANSWER = {
    "decision": True,
    "context": {"reason_admin": {"code": "200", "message": "every evaluation permitted"},
                "reason_user": {"code": "200", "message": "permitted"}},
    "evaluations": [
        {"decision": True, "request_id": "one", "context": context("dec-2", 8)},
        {"decision": True, "context": context("dec-3", 9)},
    ],
}

single_payload, single_response = signed(SINGLE_REQUEST, SINGLE_ANSWER, ["r-1"], evidence("dec-1", 7))
batch_payload, batch_response = signed(BATCH_REQUEST, BATCH_ANSWER, ["one", None], evidence("dec-3", 9))

document = {
    "description": "WP-6.6: signed native decision responses. The key is RFC 8032 section 7.1 test 1. A PEP verifies each `response` to its `request` under `key`, expecting `audience`, at `now`, with the advertised `validity_seconds` and `clock_skew_seconds`, the nonce outstanding, and the exact `policy`; `payload` is what the attestation's payload decodes to.",
    "key": {"kid": KID, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "x": b64(PUB)},
    "audience": AUDIENCE,
    "now": ISSUED + 10,
    "validity_seconds": VALIDITY,
    "clock_skew_seconds": SKEW,
    "policy": POLICY,
    "single": {"request": SINGLE_REQUEST, "response": single_response, "payload": single_payload},
    "batch": {"request": BATCH_REQUEST, "response": batch_response, "payload": batch_payload},
}
print(json.dumps(document, indent=2, ensure_ascii=False))
