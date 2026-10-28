// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_host::api::host_input::{InvitationHandoff, PinStore};
use permguard_host::api::members::{AssuranceOffer, NarrowView, TaskView};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, document)) = data.split_first() else {
        return;
    };
    match kind % 5 {
        0 => {
            let _ = permguard_host::api::decode_external_json::<InvitationHandoff>(document);
        }
        1 => {
            let _ = permguard_host::api::decode_external_json::<PinStore>(document);
        }
        2 => {
            let _ = permguard_host::api::decode_external_json::<Vec<TaskView>>(document);
        }
        3 => {
            let _ = permguard_host::api::decode_external_json::<NarrowView>(document);
        }
        _ => {
            let _ = permguard_host::api::decode_external_json::<AssuranceOffer>(document);
        }
    }
});
