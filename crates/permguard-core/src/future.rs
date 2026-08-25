// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shape asynchronous contract methods take.
//!
//! Every collaborator in this workspace is reached through `Box<dyn Trait>`, and `async fn` in a trait
//! is not dyn-compatible: the compiler cannot give a trait object a method whose return type depends
//! on the implementation. Returning a boxed future is the way to have both, and it is what the
//! ecosystem settled on before `async fn` in traits existed.
//!
//! The alias also keeps a runtime out of this crate. A contract that returned a `tokio` type would
//! drag a runtime into the one crate every other crate depends on; a `Future` is `std`, so the choice
//! of runtime stays where it belongs — in the binary.

use std::future::Future;
use std::pin::Pin;

/// A future a contract method returns.
///
/// `Send` because the work it represents crosses tasks and threads; the lifetime because the future
/// usually borrows from the receiver and its arguments.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Wraps a value in an already-finished future, for the many contract methods whose default does
/// nothing.
pub fn ready<'a, T: Send + 'a>(value: T) -> BoxFuture<'a, T> {
    Box::pin(std::future::ready(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn test_a_ready_future_resolves_to_what_it_was_given() {
        assert_eq!(ready(7_u8).await, 7);
    }

    #[tokio::test]
    async fn test_a_boxed_future_can_borrow_from_its_caller() {
        let owned = String::from("borrowed");

        let future: BoxFuture<'_, usize> = Box::pin(async { owned.len() });

        assert_eq!(future.await, 8);
    }
}
