// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;

use permguard_core::assurance::EvidenceClass;
use permguard_host::membership::record::{
    Acknowledgement, Action, ContractRole, Cutover, Delivered, EnrollAnswer, EnrollRequest, Entry, Invitation, KeptProgress, Kind,
    LastSession, Lease, LeaseAnswer, LeaseRequest, Manifest, MembershipAnswer, MembershipRequest,
    Pending, ProgressAnswer, ReplayEntry, RingStatement, Role, Status, TaskAnswer, TaskMessage, TaskProgress,
    TaskType, Verdict, WatchEvent, WatchRequest,
};
use permguard_host::membership::egress;
use permguard_host::membership::import;
use permguard_host::membership::zone;

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
    // The task session's records (WP-4.3).
    if let Ok(record) = LeaseRequest::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Lease::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = LeaseAnswer::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = TaskMessage::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = TaskAnswer::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The task router's records (WP-4.4).
    if let Ok(record) = TaskProgress::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = ProgressAnswer::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = KeptProgress::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = LastSession::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = WatchRequest::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = WatchEvent::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = ReplayEntry::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The ring re-pin's records (WP-4.5).
    if let Ok(record) = RingStatement::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Cutover::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Acknowledgement::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = Delivered::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The `zone.secrets` contract's records (WP-4.7).
    if let Ok(record) = zone::Request::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = zone::Delivery::decode(data) {
        assert_eq!(record.encode().ok().as_deref().map(|bytes| bytes.as_slice()), Some(data));
    }
    if let Ok(record) = zone::Receipt::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The `events.import` contract's records (WP-6.2c1).
    if let Ok(record) = import::Request::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = import::Origins::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = import::Checkpoint::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = import::State::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    // The `audit.checkpoints` contract's records (WP-5.9).
    if let Ok(record) = egress::Ship::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = egress::Ack::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = egress::Acks::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = egress::Kept::decode(data) {
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
        if let Ok(role) = ContractRole::from_str(text) {
            assert_eq!(role.as_str(), text);
        }
        // An evidence class reads its name around white space, as the policy setting is written.
        if let Ok(class) = EvidenceClass::from_str(text) {
            assert_eq!(class.as_str(), text.trim());
        }
        let _ = Action::from_str(text);
        let _ = Kind::from_str(text);
    }
});
