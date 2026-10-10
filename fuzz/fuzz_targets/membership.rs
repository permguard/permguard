// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;

use permguard_core::assurance::EvidenceClass;
use permguard_host::membership::record::{
    Action, EnrollAnswer, EnrollRequest, Entry, Invitation, Kind, Manifest, MembershipAnswer,
    MembershipRequest, Pending, Role, Status, TaskType, Verdict,
};

fuzz_target!(|data: &[u8]| {
    // Whatever decodes re-encodes to the same bytes: each record has one encoding.
    if let Ok(record) = Manifest::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Invitation::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = EnrollRequest::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Pending::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = EnrollAnswer::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = MembershipRequest::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = MembershipAnswer::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Entry::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The tokens a record or a Host API request names: whatever reads back spells itself.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(role) = Role::from_str(text) {
            assert_eq!(role.as_str(), text);
        }
        if let Ok(task) = TaskType::from_str(text) {
            assert_eq!(task.as_str(), text);
        }
        if let Ok(status) = Status::from_str(text) {
            assert_eq!(status.as_str(), text);
        }
        if let Ok(verdict) = Verdict::from_str(text) {
            assert_eq!(verdict.as_str(), text);
        }
        // An evidence class reads its name around white space, as the policy setting is written.
        if let Ok(class) = EvidenceClass::from_str(text) {
            assert_eq!(class.as_str(), text.trim());
        }
        let _ = Action::from_str(text);
        let _ = Kind::from_str(text);
    }
});
