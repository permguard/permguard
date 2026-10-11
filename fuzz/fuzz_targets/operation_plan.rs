// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::audit::checkpoint::Keys;
use permguard_host::operations::plan::{
    Approval, PlanReceipt, read_receipt, verify_approval, verify_receipt,
};

/// The RFC 8032 section 7.1 test 2 key as a `host.operations` JWK: a set no fuzzed envelope is
/// signed by.
const KEYS: &str = r#"{"keys":[{"kid":"host.operations:FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk","kty":"OKP","crv":"Ed25519","x":"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw","alg":"EdDSA","use":"sig"}]}"#;

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = PlanReceipt::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(receipt.encode().ok().as_deref(), Some(data));
    }
    if let Ok(approval) = Approval::decode(data) {
        assert_eq!(approval.encode().ok().as_deref(), Some(data));
    }
    // A receipt an operator presents, read before its bytes are matched: refused or read, never a
    // panic.
    let _ = read_receipt(data);
    // Under a key it was not signed by: refused, never a panic.
    if let Ok(keys) = Keys::from_document(KEYS) {
        assert!(verify_receipt(&keys, data).is_err());
        assert!(verify_approval(&keys, data).is_err());
    }
});
