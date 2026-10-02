// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How a test asks for a fault.
//!
//! The hooks live in `permguard-core`, because the stores that consult them cannot depend on a test
//! crate; this module is the one place a test author reads to learn the four faults and how each
//! is requested.
//!
//! | Fault                | How a test asks for it                                                              | What the store sees |
//! | -------------------- | ----------------------------------------------------------------------------------- | ------------------- |
//! | fsync failure        | `let _guard = fault::inject(&volume, Fault::Fsync);`                                | every flush under `volume` fails with an I/O error |
//! | disk full            | `let _guard = fault::inject(&volume, Fault::DiskFull { remaining_bytes: n });`      | writes succeed until `n` bytes, then fail with `StorageFull` and write nothing |
//! | clock jump           | `let clock = ManualClock::at(t); … clock.jump(-3_600);`, handed to the component as its `Clock` | `now()` moves by the jump, in either direction |
//! | `kill -9`            | the crash harness in `tests/crash.rs`: a child process appends and is killed with `SIGKILL` at a random point | the parent reopens what the dead child left |
//!
//! A store consults the first two through [`permguard_core::fault::write`] and
//! [`permguard_core::fault::sync`] around each durability-relevant write and flush. Today these go
//! through them:
//!
//! | Store              | Covered                                                                 | Not yet covered |
//! | ------------------ | ----------------------------------------------------------------------- | --------------- |
//! | decision spool     | segment append and flush, `STATE` write, flush and directory flush, the terminal record in `RESERVE` | creating `RESERVE`, truncating a torn tail |
//! | event journal      | segment append and flush, the occurrence index append and flush, `STATE` write, flush and directory flush | the checkpoint and occurrence-state files, `RESERVE`, truncating a torn tail |
//!
//! The storage contract of the Host (WP-1.1) routes every write of its own through one storage
//! module; a store adopting it inherits the hooks there. A component consults the clock by taking a
//! [`permguard_core::time::Clock`] instead of reading the system time itself; nothing does yet, and
//! the Host time guard (WP-2.12) is its first consumer.

pub use permguard_core::fault::{Fault, Injected, inject};
pub use permguard_core::time::{Clock, ManualClock, SystemClock};
