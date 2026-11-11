// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard authority …` against a real Authority Plane, composed on a Host as a Server composes
//! it and served over TLS, REST and gRPC on one port: the administrator made at the first start
//! manages a service account and its access key over either transport, the secret going to a
//! private file and never to the output; the account obtains its token, which the Host verifies
//! until the token is revoked; and an account without the scope is refused the administration.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Actor, Authenticator as _, Resource};
use permguard_core::config::SETTING_WORKING_DIR;
use permguard_core::{Config, PlaneContext, ProductIdentity, ServerContext, TlsSettings};
use permguard_host::authz::access_tokens::{TokenAuthenticator, Trust};
use permguard_host::authz::authority::{AuthorityTrust, DEFAULT_AUDIENCE};
use permguard_host::authz::{Authorization, PrincipalMapper};
use permguard_host::composition::Host;
use permguard_host::storage::volume::Volume;
use permguard_server::plane::SETTING_AUTHORITY_URL;
use serde_json::Value;

/// The issuer every token names: where a Host would reach the Authority Plane.
const ISSUER: &str = "https://localhost:8443";

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-cli-authority-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// A certificate authority, and the certificate of `localhost` it signed: the CA's path, the
/// certificate's and its key's.
fn pki(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("parameters");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let authority_key = rcgen::KeyPair::generate().expect("a key");
    let authority = params.self_signed(&authority_key).expect("self-signed");
    let issuer = rcgen::Issuer::from_params(&params, &authority_key);
    let server = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("parameters");
    let server_key = rcgen::KeyPair::generate().expect("a key");
    let signed = server.signed_by(&server_key, &issuer).expect("signed");
    let write = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("written");
        path
    };
    (
        write("ca.pem", &authority.pem()),
        write("server.pem", &signed.pem()),
        write("server.key", &server_key.serialize_pem()),
    )
}

/// The Authority Plane of a Host over the volume under `dir`, served over TLS on a runtime of its
/// own: the address it bound, the trust the Host verifies its tokens with, and the authenticator
/// its listener runs.
fn serve(
    dir: &Path,
    certificate: &Path,
    key: &Path,
) -> (std::net::SocketAddr, Arc<AuthorityTrust>) {
    let root = dir.join("volume");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let identity = Arc::new(
        permguard_host::identity::Identity::provision(
            &volume,
            Arc::new(permguard_host::keys::FileKeyProvider::new(
                permguard_host::identity::directories(&volume)
                    .expect("the identity directory")
                    .1,
            )),
            permguard_host::identity::Suite::Ed25519Sha256V1,
            permguard_host::authz::store::now(),
            permguard_host::authz::store::now() * 1000,
        )
        .expect("provisioned"),
    );
    let time = Arc::new(permguard_host::time::TimeGuard::system(
        Duration::from_secs(30),
    ));
    let ring = Arc::new(
        permguard_host::keys::ring::Ring::open(
            &volume,
            permguard_host::keys::ring::AUTHORITY_TOKENS,
            permguard_host::identity::Suite::Ed25519Sha256V1,
            permguard_host::keys::ring::Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(7200),
            },
            Arc::clone(&time),
        )
        .expect("the ring opens")
        .with_binder(Arc::clone(&identity) as Arc<dyn permguard_host::keys::ring::Binder>),
    );
    permguard_core::KeyManager::maintain(ring.as_ref()).expect("the ring is maintained");
    let mutations = Arc::new(
        permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
            .expect("the mutation journal opens"),
    );
    let trust = Arc::new(AuthorityTrust::in_memory(Some(ISSUER), DEFAULT_AUDIENCE));
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            permguard_server::plane::AUTHORITY_SETTINGS
                .into_iter()
                .chain([permguard_server::plane::SETTING_AUTHORITY_HTTP_ADDR]),
            permguard_core::config::Layers::new().with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    root.to_string_lossy().into_owned(),
                ),
                (SETTING_AUTHORITY_URL.to_owned(), ISSUER.to_owned()),
                // A listener of its own, or the Authority Plane is dormant: the test serves its
                // routes on a listener it binds itself.
                (
                    permguard_server::plane::SETTING_AUTHORITY_HTTP_ADDR.to_owned(),
                    "127.0.0.1:8443".to_owned(),
                ),
            ]),
        )
        .expect("the configuration builds"),
    ));
    let module = permguard_authority_plane::module();
    let registration = Host::builder()
        .ring(permguard_host::composition::AUTHORITY_TOKENS, ring)
        .host_id(identity.host_id())
        .mutations(mutations)
        .authorization(Arc::new(Authorization::closed()))
        .authority_trust(Arc::clone(&trust))
        .volume(&volume)
        .time(Arc::clone(&time))
        .build()
        .register(module.declaration(config))
        .expect("the Authority Plane registers");
    std::mem::forget(volume);
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(
            ProductIdentity::new(
                "permguard-authority-plane",
                "Permguard",
                "tagline",
                "about",
                "",
            ),
            config,
            Box::leak(Box::new(permguard_std::storage::MemoryStorage::new())),
            Box::leak(Box::new(permguard_std::audit::RecordingAuditSink::new())),
        )
        .with_plane_handles("authority", Arc::new(registration)),
    ));
    let context = PlaneContext::new(server, "authority");
    let router = module
        .http_routes(&context)
        .merge(module.grpc_routes(&context));
    let authenticator = Arc::new(TokenAuthenticator {
        trust: Arc::clone(&trust) as Arc<dyn Trust>,
        inner: Arc::new(PrincipalMapper::empty()),
        time,
    });
    let token_paths = module.client_authentication_paths();
    let settings = TlsSettings::new(certificate, key);
    let (bound, address) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the plane's runtime starts");
        runtime.block_on(async move {
            let surface =
                permguard_transport::Surface::listener("authority-plane", "127.0.0.1:0", router)
                    .tls(Some(&settings))
                    .authenticator(Some(authenticator))
                    .client_authentication(token_paths)
                    .start()
                    .await
                    .expect("the plane binds");
            bound.send(surface.address()).expect("the test waits");
            std::future::pending::<()>().await;
            drop(surface);
        });
    });
    (address.recv().expect("the plane started"), trust)
}

/// The CLI, without the `PERMGUARD_*` variables of the shell running the tests, its home and its
/// token cache under `workdir`.
fn cli(workdir: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_permguard"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(workdir)
        .env("HOME", workdir)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .args(args)
        .output()
        .expect("the CLI runs")
}

/// The `jti` a token's claims name, read without verifying.
fn jti_of(token: &str) -> String {
    use base64::Engine as _;
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).expect("a payload"))
        .expect("base64url");
    serde_json::from_slice::<Value>(&claims).expect("JSON")["jti"]
        .as_str()
        .expect("a jti")
        .to_owned()
}

/// Whether `output` printed a secret key or a token: what it must never do.
fn printed_a_secret(output: &Output) -> bool {
    let printed = String::from_utf8_lossy(&output.stdout).into_owned()
        + String::from_utf8_lossy(&output.stderr).as_ref();
    printed.contains("pgsk_") || printed.contains("eyJ")
}

#[test]
fn the_authority_commands_manage_an_account_whose_token_the_host_verifies_until_revoked() {
    let dir = scratch("commands");
    let (ca, certificate, key) = pki(&dir);
    let (address, trust) = serve(&dir, &certificate, &key);
    let admin_key = dir.join("volume/planes/authority/admin.key");
    let admin_access_key = std::fs::read_to_string(&admin_key)
        .expect("the administrator's key file is written at the first start")
        .lines()
        .find_map(|line| {
            line.strip_prefix("access_key:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .expect("its access key");
    let ca = ca.to_str().expect("a UTF-8 path").to_owned();
    let verifier = TokenAuthenticator {
        trust: Arc::clone(&trust) as Arc<dyn Trust>,
        inner: Arc::new(PrincipalMapper::empty()),
        time: Arc::new(permguard_host::time::TimeGuard::system(
            Duration::from_secs(30),
        )),
    };

    let mut admins = Vec::new();
    for scheme in ["https", "grpcs"] {
        let endpoint = format!("{scheme}://localhost:{}", address.port());
        let run = |access_key: &str, secret: &Path, args: &[&str]| {
            let mut full = vec![
                "-o",
                "json",
                "--authority-endpoint",
                &endpoint,
                "--tls-ca-file",
                &ca,
                "--access-key",
                access_key,
                "--secret-key-file",
                secret.to_str().expect("a UTF-8 path"),
            ];
            full.extend_from_slice(args);
            let output = cli(&dir, &full);
            assert!(!printed_a_secret(&output), "{scheme}: {output:?}");
            output
        };
        let as_admin = |args: &[&str]| {
            let output = run(&admin_access_key, &admin_key, args);
            assert!(output.status.success(), "{scheme} {args:?}: {output:?}");
            serde_json::from_slice::<Value>(&output.stdout).expect("the CLI answers JSON")
        };
        let account = format!("billing-{scheme}");

        let created = as_admin(&[
            "authority",
            "service-accounts",
            "create",
            &account,
            "--scope",
            "decision.evaluate@plane/data/*",
        ]);
        assert_eq!(created["name"], account.as_str(), "{created}");
        admins.push(as_admin(&["authority", "service-accounts", "get", "admin"]));

        let secret = dir.join(format!("{account}.key"));
        let key_created = as_admin(&[
            "authority",
            "keys",
            "create",
            &account,
            "--secret-out",
            secret.to_str().expect("a UTF-8 path"),
        ]);
        let access_key = key_created["access_key"]
            .as_str()
            .expect("the new access key")
            .to_owned();
        assert!(access_key.starts_with("pgak_"), "{key_created}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&secret)
                .expect("written")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{scheme}: the secret is its owner's alone");
        }

        // The account obtains its token, and the Host verifies it within its scope.
        let token_file = dir.join(format!("{account}.jwt"));
        let issued = run(
            &access_key,
            &secret,
            &[
                "authority",
                "token",
                "--out",
                token_file.to_str().expect("a UTF-8 path"),
            ],
        );
        assert!(issued.status.success(), "{scheme}: {issued:?}");
        let token = std::fs::read_to_string(&token_file).expect("the token is written");
        let Actor::Authenticated(context) = verifier
            .authenticate(None, Some(token.trim()))
            .expect("the Host verifies the token")
        else {
            panic!("{scheme}: authenticated");
        };
        assert_eq!(
            context.authorization_principal().as_str(),
            format!("sa:{account}")
        );
        let grant = context.token().expect("a token's bearer");
        assert!(grant.permits(
            "decision.evaluate",
            &Resource::ledger("data", "zone", "ledger")
        ));
        assert!(!grant.permits("catalog.read", &Resource::plane("control")));

        // Without the administration's scope, the account is refused it.
        let refused = run(
            &access_key,
            &secret,
            &["authority", "service-accounts", "list"],
        );
        assert!(!refused.status.success(), "{scheme}: {refused:?}");

        // A key file names its access key, so `--secret-key-file` alone is enough: each key
        // file keeps its own token, and the account never acts with the administrator's, kept
        // the command before.
        let alone = |secret: &Path, args: &[&str]| {
            let mut full = vec![
                "-o",
                "json",
                "--authority-endpoint",
                &endpoint,
                "--tls-ca-file",
                &ca,
                "--secret-key-file",
                secret.to_str().expect("a UTF-8 path"),
            ];
            full.extend_from_slice(args);
            let output = cli(&dir, &full);
            assert!(!printed_a_secret(&output), "{scheme}: {output:?}");
            output
        };
        let listed = alone(&admin_key, &["authority", "service-accounts", "list"]);
        assert!(listed.status.success(), "{scheme}: {listed:?}");
        let refused = alone(&secret, &["authority", "service-accounts", "list"]);
        assert!(!refused.status.success(), "{scheme}: {refused:?}");

        // Listed by its account, never shown; revoked by its `jti`, and the Host refuses it.
        // Two: the one written to the file, and the one the refused call obtained.
        let listed = as_admin(&["authority", "tokens", "list", "--account", &account]);
        let tokens = listed.as_array().expect("a list of tokens");
        assert_eq!(tokens.len(), 2, "{listed}");
        let jti = jti_of(token.trim());
        assert!(
            tokens.iter().any(|listed| listed["jti"] == jti.as_str()),
            "{listed}"
        );
        as_admin(&["authority", "tokens", "revoke", &jti]);
        assert!(
            verifier.authenticate(None, Some(token.trim())).is_err(),
            "{scheme}: a revoked token is refused at once on this Host"
        );
        let invalid = as_admin(&["authority", "tokens", "list", "--status", "invalid"]);
        assert!(invalid.to_string().contains(&jti), "{invalid}");

        // The account goes with its keys.
        as_admin(&["authority", "service-accounts", "delete", &account]);
        let gone = run(
            &admin_access_key,
            &admin_key,
            &["authority", "service-accounts", "get", &account],
        );
        assert!(!gone.status.success(), "{scheme}: {gone:?}");
    }
    // The administrator reads the same over either transport, its key's last use aside.
    for admin in &mut admins {
        if let Some(keys) = admin["keys"].as_array_mut() {
            for key in keys {
                key.as_object_mut().map(|key| key.remove("last_used_at"));
            }
        }
    }
    assert_eq!(admins[0], admins[1]);
    assert_eq!(admins[0]["name"], "admin");
}
