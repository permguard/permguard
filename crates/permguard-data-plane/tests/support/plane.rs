// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A real control plane, served in process on an ephemeral port.
//!
//! The router is the shipped one — catalog and NOTP, the same code a
//! deployment runs — so what this suite exercises is the product's listing
//! and transfer, not a stand-in for them.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::keys::KeyManager as _;
use permguard_core::{Config, PlaneContext, ProductIdentity, ServerContext};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::catalog::FileCatalog;
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use permguard_std::storage::MemoryStorage;

/// A plane that stops when the test drops it.
pub struct Plane {
    pub url: String,
    stop: tokio::task::JoinHandle<()>,
}

impl Drop for Plane {
    fn drop(&mut self) {
        self.stop.abort();
    }
}

/// Starts the control plane's HTTP surface over `volume`.
pub async fn start(volume: &Path) -> Plane {
    // The collaborators outlive the served router, so they are leaked on
    // purpose: this process is one test binary, and the alternative is a
    // lifetime dance that teaches nobody anything.
    // The working directory is a setting, so it arrives the way every
    // setting does — through the layers, not through a setter.
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            Vec::<String>::new(),
            permguard_core::config::Layers::new().with_environment(vec![(
                permguard_core::config::SETTING_WORKING_DIR.to_owned(),
                volume.to_string_lossy().into_owned(),
            )]),
        )
        .expect("the test configuration builds"),
    ));
    let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
    let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
    let catalog = Arc::new(FileCatalog::new(config.zones_directory()));
    let keys = Arc::new(DirectoryKeyManager::new(
        volume.join("keys/control"),
        KeyPolicy {
            publish_ahead: Duration::ZERO,
            rotate_every: Duration::from_secs(3600),
            retain: Duration::from_secs(3600),
            verify_retain: Duration::from_secs(3600),
        },
    ));
    keys.maintain().expect("the ring publishes");
    keys.maintain().expect("the ring activates");

    // The control plane signs through the handle the Host registers for it, as in a server.
    let module = permguard_control_plane_server::module();
    let registration = permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::CONTROL_ATTEST, keys)
        // Every head statement names its Host (WP-7.1): NOTP is served only with one.
        .host_id([0x11; 16])
        // Every ref update runs in a mutation transaction (WP-7.12).
        .mutations(Arc::new(
            permguard_host::operations::mutation::Mutations::open_offline(
                &permguard_host::storage::volume::Volume::claim(
                    &volume.join("host-volume"),
                    permguard_core::assurance::AssuranceProfile::Development,
                )
                .expect("the volume is claimed"),
                "test",
            )
            .expect("the mutation journal opens"),
        ))
        // This suite is about mirroring, not about who may read the catalog.
        .authorization(Arc::new(
            permguard_host::composition::Authorization::permissive(),
        ))
        .build()
        .register(module.declaration(config))
        .expect("the control plane registers");
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(identity(), config, storage, audit)
            .with_catalog(catalog)
            .with_plane_handles("control", Arc::new(registration)),
    ));
    // The boundary every served surface has: nobody is anonymous without it (WP-2.4).
    let router = module
        .http_routes(&PlaneContext::new(server, "control"))
        .layer(permguard_transport::ActorLayer::new(Arc::new(
            permguard_core::NoRules,
        )));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port is free");
    let address: SocketAddr = listener.local_addr().expect("the address is known");
    let stop = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    Plane {
        url: format!("http://{address}"),
        stop,
    }
}

fn identity() -> ProductIdentity {
    ProductIdentity::new(
        "permguard-control-plane",
        "Permguard",
        "tagline",
        "about",
        "",
    )
}

/// Creates the zones and ledgers a test needs, through the same client the
/// product uses — so the fixture cannot drift from the API.
pub fn provision(url: &str, zone: &str, ledgers: &[&str]) {
    let catalog = permguard_control_client::catalog::client(
        url,
        &permguard_control_client::TlsOptions::default(),
        Box::new(permguard_control_client::narrate::Silent),
    )
    .expect("the catalog client connects");
    let created = catalog.create_zone(zone).expect("the zone is created");
    for ledger in ledgers {
        catalog
            .create_ledger(&created.id, ledger)
            .expect("the ledger is created");
    }
}
