// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authoring engine, as `docs/cli-workspace.md` specifies it: sources,
//! the manifest, planning, applying, materialization — everything that lives
//! under `.permguard`.
//!
//! What is *not* here: how a server is reached, how the local mirror is
//! filled, how a signed head is verified, when a checkpoint may move. That
//! is [`permguard_control_client`], which the data plane consumes too — so
//! the two speak the wire identically and neither reimplements a proof.
//!
//! A module of the CLI, not a crate: the CLI is the only thing that authors.

pub mod workspace;

pub use permguard_control_client::{FsStore, Store, remote, verify};
pub use workspace::{Workspace, WorkspaceError, lock};
