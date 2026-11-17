// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A server assembled outside the Permguard workspace: a Plane of its own, registered beside the
//! open-source Data Plane in a server built from the kit, `permguard-server` with no feature.
//!
//! Everything it touches is public: [`PlaneModule`] for what a Plane serves, declares and runs,
//! [`PlaneServer`] to register Planes and compose the server, and `App::serve_until` to run it on
//! a runtime the program owns, until the program says stop. No source of the workspace is
//! changed, copied or reached around.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::routing::get;
use permguard_core::{BoxFuture, PlaneContext, PlaneTask, ProductIdentity};
use permguard_server::plane::{PlaneAddresses, PlaneModule, PlaneServer, build_settings};

/// The Plane's id, as `runtime.planes` would name it.
pub const PLANE: &str = "fixture";

/// A Plane the workspace does not know: one route, one background task, one declaration.
pub struct FixturePlane {
    /// Set once the Plane's background task has started, cleared when it stops.
    pub working: Arc<AtomicBool>,
}

impl PlaneModule for FixturePlane {
    fn id(&self) -> &'static str {
        PLANE
    }

    fn component(&self) -> &'static str {
        "fixture-plane"
    }

    fn description(&self) -> &'static str {
        "fixture Plane"
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        // The Plane's own view of the Host: here, the configuration it runs under.
        let version = context.config().version().to_owned();
        Router::new().route(
            "/fixture/v1/ping",
            get(move || {
                let version = version.clone();
                async move { format!("pong {version}") }
            }),
        )
    }

    fn grpc_routes(&self, _: &PlaneContext<'_>) -> Router {
        Router::new()
    }

    fn services(&self) -> Vec<Box<dyn PlaneTask>> {
        vec![Box::new(Working(Arc::clone(&self.working)))]
    }

    /// What the Plane asks of the Host: nothing but its own name, which the Host registers and
    /// answers handles for.
    fn declaration(&self, _: &permguard_core::Config) -> permguard_host::composition::Declaration {
        permguard_host::composition::Declaration::new(PLANE)
    }
}

/// The Plane's background work: started with the server, stopped with it.
struct Working(Arc<AtomicBool>);

impl PlaneTask for Working {
    fn name(&self) -> &'static str {
        "fixture-work"
    }

    fn start<'a>(&'a self, _: &'a PlaneContext<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        self.0.store(true, Ordering::SeqCst);
        Box::pin(std::future::ready(Ok(())))
    }

    fn stop<'a>(&'a self, _: &'a PlaneContext<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
        self.0.store(false, Ordering::SeqCst);
        Box::pin(std::future::ready(Ok(())))
    }
}

/// The edition: the fixture's Plane at `addresses`, beside the open-source Data Plane at the
/// addresses its own settings name.
pub fn edition(working: Arc<AtomicBool>, addresses: PlaneAddresses) -> anyhow::Result<PlaneServer> {
    let identity = ProductIdentity::new(
        "external-edition",
        "External Edition",
        "",
        "a server assembled outside the workspace",
        "",
    );
    Ok(PlaneServer::new(identity, build_settings("9.9.9"))
        .with_plane(Box::new(FixturePlane { working }), addresses)
        .with_plane(
            permguard_data_plane_server::module(),
            permguard_server::addresses_for_plane("data")
                .ok_or_else(|| anyhow::anyhow!("the Data Plane's addresses are not known"))?,
        ))
}
