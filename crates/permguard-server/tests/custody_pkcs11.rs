// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `pkcs11` custody against SoftHSMv2 (WP-3.2): a ring key generated in the token,
//! non-extractable, signing there, and a KEK in the token whose wrap is bound to its context.
//!
//! Runs where SoftHSMv2 is installed (`softhsm2-util` on the path, its module at a standard
//! place or named by `PERMGUARD_TEST_PKCS11_MODULE`); elsewhere it says why it did not run.

#![cfg(feature = "pkcs11")]
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use zeroize::Zeroizing;

use permguard_host::identity::Suite;
use permguard_host::keys::custody::{Dek, Remote as _, Wrap as _};
use permguard_host::storage::Dir;
use permguard_server::custody::pkcs11::{Hsm, HsmKek, SharedHsm, Token};

const MODULES: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
];

/// A fresh SoftHSM token, or why there is none.
fn token() -> Result<(PathBuf, PathBuf), String> {
    let module = std::env::var_os("PERMGUARD_TEST_PKCS11_MODULE")
        .map(PathBuf::from)
        .or_else(|| MODULES.iter().map(PathBuf::from).find(|path| path.exists()))
        .ok_or("no SoftHSMv2 module is installed")?;
    let root = std::env::temp_dir().join(format!("permguard-pkcs11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("tokens")).map_err(|error| error.to_string())?;
    let conf = root.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!("directories.tokendir = {}\n", root.join("tokens").display()),
    )
    .map_err(|error| error.to_string())?;
    // SAFETY of the test: the binary's one test sets it before any other thread runs.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
    let status = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "permguard",
            "--pin",
            "1234",
            "--so-pin",
            "5678",
        ])
        .status()
        .map_err(|error| format!("softhsm2-util: {error}"))?;
    if !status.success() {
        return Err("softhsm2-util could not create a token".to_owned());
    }
    Ok((module, root))
}

fn open(module: PathBuf) -> Arc<Hsm> {
    Hsm::open(Token {
        module,
        label: "permguard".to_owned(),
        pin: Zeroizing::new("1234".to_owned()),
    })
    .expect("the token opens")
}

/// One test, so `SOFTHSM2_CONF` is set once in a process with no other thread reading the
/// environment, under `cargo test` as under nextest.
#[test]
fn the_token_holds_the_ring_keys_and_the_kek() {
    let (module, root) = match token() {
        Ok(found) => found,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let hsm = open(module.clone());
    a_ring_key_is_generated_in_the_token_and_signs_there(&hsm, &root);
    the_identity_is_provisioned_and_opened_in_the_token(&hsm, &root);
    a_token_kek_binds_its_context_and_its_attributes_are_checked(&hsm, &module);
}

fn a_ring_key_is_generated_in_the_token_and_signs_there(hsm: &Arc<Hsm>, root: &std::path::Path) {
    let dir = root.join("ring");
    std::fs::create_dir_all(&dir).expect("created");
    let keys = SharedHsm(Arc::clone(hsm))
        .provider("host.operations", Dir::open(&dir).expect("opens"))
        .expect("a provider");
    for suite in [Suite::Ed25519Sha256V1, Suite::P256Sha256V1] {
        let (slot, public) = keys
            .generate_addressed(suite)
            .expect("generated in the token");
        assert_eq!(
            std::fs::read_to_string(dir.join(format!("{slot}.ref"))).expect("the label"),
            format!("host.operations:{slot}")
        );
        // Enough signatures that a token answering high-s would be caught.
        for round in 0..16u8 {
            let signature = keys
                .sign(&slot, suite, &[round])
                .expect("signed in the token");
            suite
                .verify(&public.bytes, &[round], &signature)
                .expect("verifies, low-s");
        }
        assert_eq!(keys.public(&slot, suite).expect("read"), public);
        keys.destroy(&slot).expect("destroyed");
        assert!(keys.sign(&slot, suite, b"x").is_err());
    }

    // A reference naming another ring's key is refused.
    let (slot, _) = keys
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
    std::fs::write(dir.join("forged.ref"), format!("host.operations:{slot}")).expect("written");
    assert!(keys.sign("forged", Suite::Ed25519Sha256V1, b"m").is_err());
}

/// The identity's slots are its epochs, and its keys are labelled by thumbprint like a ring's.
fn the_identity_is_provisioned_and_opened_in_the_token(hsm: &Arc<Hsm>, root: &std::path::Path) {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::identity::{self, Identity, IdentityError};
    use permguard_host::storage::volume::Volume;

    let volume =
        Volume::claim(&root.join("volume"), AssuranceProfile::Development).expect("claimed");
    let shared = SharedHsm(Arc::clone(hsm));
    let keys = || identity::directories(&volume).expect("the directories").1;
    let provisioned = Identity::provision_with(
        &volume,
        |_| {
            shared
                .provider("host.identity", keys())
                .map_err(IdentityError::from)
        },
        Suite::Ed25519Sha256V1,
        1_800_000_000,
        1_800_000_000_000,
    )
    .expect("provisioned in the token");
    let opened = Identity::open(
        &volume,
        shared
            .provider("host.identity", keys())
            .expect("a provider"),
    )
    .expect("opened from the token");
    assert_eq!(opened.host_id_text(), provisioned.host_id_text());
    assert!(
        !root.join("volume/host/identity/keys/1.key").exists(),
        "no key file: the key is in the token"
    );
}

fn a_token_kek_binds_its_context_and_its_attributes_are_checked(
    hsm: &Arc<Hsm>,
    module: &std::path::Path,
) {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::Attribute;
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;

    // The operator's AES keys: one a KEK must be, one extractable.
    {
        let context = Pkcs11::new(module).expect("the module");
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .expect("initialized");
        let slot = context.get_slots_with_token().expect("slots")[0];
        let session = context.open_rw_session(slot).expect("a session");
        session
            .login(UserType::User, Some(&AuthPin::from("1234")))
            .expect("logged in");
        for (label, extractable) in [("permguard-kek", false), ("loose-kek", true)] {
            session
                .generate_key(
                    &Mechanism::AesKeyGen,
                    &[
                        Attribute::Token(true),
                        Attribute::Sensitive(true),
                        Attribute::Extractable(extractable),
                        Attribute::Encrypt(true),
                        Attribute::Decrypt(true),
                        Attribute::ValueLen(32.into()),
                        Attribute::Label(label.as_bytes().to_vec()),
                    ],
                )
                .expect("the KEK");
        }
    }
    let kek = HsmKek::open(Arc::clone(hsm), "permguard-kek", 1).expect("a KEK");
    let dek = Dek::from_unwrapped(Zeroizing::new([6u8; 32]));
    let wrapped = kek.wrap(&dek, b"context").expect("wrapped");
    assert_eq!(wrapped.len(), 12 + 32 + 16);
    assert_eq!(
        kek.unwrap(1, &wrapped, b"context")
            .expect("unwrapped")
            .expose(),
        &[6u8; 32]
    );
    assert!(kek.unwrap(1, &wrapped, b"another").is_err());
    assert!(
        HsmKek::open(Arc::clone(hsm), "loose-kek", 1).is_err(),
        "an extractable key is no KEK"
    );
}
