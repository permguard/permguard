// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks one full lifecycle of the default server host against in-process collaborators.

use std::hint::black_box;
use std::time::Instant;

use permguard_core::{Config, ProductIdentity, ServerContext, ServerHost};
use permguard_server::DefaultServerHost;
use permguard_std::audit::TracingAuditSink;
use permguard_std::storage::MemoryStorage;

const ITERATIONS: u32 = 10_000;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the benchmark runtime starts");

    runtime.block_on(async {
        let identity = ProductIdentity::new(
            "permguard",
            "Permguard",
            "A tagline",
            "Permguard CLI",
            "<art>",
        );
        let config = Config::default();
        let storage = MemoryStorage::new();
        let audit = TracingAuditSink::new("demo-x", "9.9.9");
        let context = ServerContext::new(identity, &config, &storage, &audit);
        let host = DefaultServerHost::new();

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            host.run(black_box(&context), Box::pin(std::future::ready(())))
                .await
                .expect("the default host runs");
        }
        let elapsed = start.elapsed();

        println!(
            "DefaultServerHost::run: {ITERATIONS} lifecycles in {elapsed:?} ({:?}/lifecycle)",
            elapsed / ITERATIONS
        );
    });
}
