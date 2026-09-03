// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stack an engine is entered with.
//!
//! # Why a policy engine needs this at all
//!
//! Evaluating policy is recursive over the shape of an expression, so an engine that recursed
//! freely would let a deep enough policy overflow the stack — a crash, in the one process that
//! must never stop answering. Cedar's evaluator therefore guards itself: before interpreting an
//! expression it asks [`stacker::remaining_stack`] for a megabyte of headroom, and if it is not
//! there it declines the whole evaluation with "recursion limit reached". Dogwood lowers to the
//! same engine and inherits the same guard.
//!
//! That guard is only as good as the answer to "how much stack is left", and on one of the
//! platforms Permguard ships to that answer is wrong. musl does not track the stack of the
//! process's first thread: its `pthread_getattr_np` probes the pages currently mapped and reports
//! what it finds — around 128 KiB — where glibc and Darwin report the real eight megabytes. Every
//! Linux release binary is musl-static, and both engine entry points can run on that first thread
//! ([`crate::fanout::Fanout::run`] deliberately evaluates the first partition on the calling
//! thread, and the temporal path decides on the caller's). The result was a two-line policy
//! answering "recursion limit reached" on Linux while the same workspace passed on macOS, and
//! passed again over gRPC, where the work lands on a spawned thread whose bounds musl does know.
//!
//! # Why growing, rather than a bigger thread
//!
//! A larger stack would not have helped: the number musl reports has nothing to do with the stack
//! the thread was given, so `RUST_MIN_STACK` and an explicit `stack_size` change the reported
//! headroom not at all. What fixes it is claiming the room and *saying so* — [`stacker::maybe_grow`]
//! allocates a segment and sets the limit stacker itself reports afterwards, so the engine's own
//! check reads the stack it was actually handed.
//!
//! Applied at the engine boundary rather than inside one engine: how much stack it needs is the
//! engine's business, and guaranteeing the headroom is this crate's. A thread that already has the
//! room pays one comparison for it.

/// The headroom an engine is guaranteed before it is entered.
///
/// A megabyte, because that is what Cedar's own guard demands: below it, its evaluator declines
/// rather than risk the stack. Matching it means the guard never fires for want of room — only for
/// a policy that is genuinely too deep for [`GROW_TO`].
const RED_ZONE: usize = 1024 * 1024;

/// How much stack is claimed when the headroom is short.
///
/// Eight megabytes: what the platforms Permguard ships to give a thread by default, so an engine on
/// a stack-starved thread is neither more nor less constrained than one on a healthy thread.
/// Claimed on demand, and only when [`RED_ZONE`] is not already available.
const GROW_TO: usize = 8 * 1024 * 1024;

/// Runs `work` with at least [`RED_ZONE`] of stack beneath it.
///
/// Every call into a policy engine goes through here. See the module documentation for what goes
/// wrong when one does not.
pub fn with<T>(work: impl FnOnce() -> T) -> T {
    stacker::maybe_grow(RED_ZONE, GROW_TO, work)
}
