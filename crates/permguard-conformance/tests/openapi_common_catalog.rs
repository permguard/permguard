// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `contracts/openapi/common.json`: the wire types every REST surface shares, checked against
//! their schemas.
//!
//! `catalog.json` is checked in the control plane, next to its private `NameBody`: its coverage
//! spans one private type and the public `Zone` and `Ledger`, and a document gets one coverage
//! assertion in the one place that sees all its schemas.

use permguard_conformance::schema::Document;
use permguard_core::codes::common;
use permguard_core::{
    AccessDenial, ApiError, Disclosure, ErrorClass, Jwk, JwkSet, WireDenial, WireError,
};

/// Every class and both denials, and a key set holding an Edwards key and a NIST key.
#[test]
fn test_common_wire_types_match_their_schemas() {
    let doc = Document::load("common.json");

    let refusals = [
        (ErrorClass::Validation, common::INVALID_ARGUMENT),
        (ErrorClass::Conflict, common::CONFLICT),
        (ErrorClass::NotFound, common::NOT_FOUND),
        (ErrorClass::Unavailable, common::UNAVAILABLE),
        (ErrorClass::Internal, common::INTERNAL),
    ];
    assert_eq!(
        refusals.len(),
        ErrorClass::ALL.len(),
        "a class has no case here"
    );
    for (class, code) in refusals {
        let wire: WireError =
            ApiError::new(class, code, "a refusal").on_the_wire(Disclosure::Minimal);
        assert_eq!(wire.class, class);
        doc.check("WireError", &wire);
    }

    let denials: [WireDenial; 2] = [
        AccessDenial::unauthenticated("no client certificate").on_the_wire(),
        AccessDenial::forbidden("not on the allow list").on_the_wire(),
    ];
    for denial in &denials {
        doc.check("WireDenial", denial);
    }
    // A denial is not a refusal: it has no `class`, and the schemas keep them apart.
    assert!(!doc.accepts_json(
        "WireDenial",
        &serde_json::json!({"code": "forbidden", "message": "m", "class": "conflict"})
    ));
    assert!(!doc.accepts_json(
        "WireError",
        &serde_json::json!({"class": "teapot", "code": "c", "message": "m"})
    ));

    let okp = Jwk::okp(
        "key-1",
        "Ed25519",
        "EdDSA",
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    );
    let ec = Jwk::ec(
        "key-2",
        "P-256",
        "ES256",
        "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    );
    doc.check("Jwk", &okp);
    doc.check("Jwk", &ec);
    doc.check("JwkSet", &JwkSet::new(vec![okp, ec]));
    doc.check("JwkSet", &JwkSet::new(Vec::new()));
    assert!(!doc.accepts_json("JwkSet", &serde_json::json!({"keys": [], "extra": true})));

    doc.assert_covered();
}
