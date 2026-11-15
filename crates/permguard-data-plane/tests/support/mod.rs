// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the integration tests of this package stand on, shared so each is built once: a real
//! Control Plane in process, `policy.mirror` task sessions over it, and the repository's examples
//! as verified mirrors. Each test binary uses part of it.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

pub mod examples;
pub mod plane;
pub mod tasks;
