// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the Host handed this Plane, read through its context in one place: the registration the
//! Host made of its declaration, which carries the journal, the keys and the authorization the
//! Plane serves with (WP-2.4).

use std::sync::Arc;

use permguard_core::PlaneContext;
use permguard_host::composition::Registration;

/// The Host's registration of this Plane; `None` when no Host registered it.
pub(crate) fn registration(context: &PlaneContext<'_>) -> Option<Arc<Registration>> {
    context.handles::<Registration>()
}
