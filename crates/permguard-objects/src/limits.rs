// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The structural limits of the object model. Enforced at push; an object
//! over any limit is rejected, never truncated.

/// Maximum encoded size of one object, in bytes.
pub const MAX_OBJECT_BYTES: usize = 5 * 1024 * 1024;

/// Maximum number of entries in one tree.
pub const MAX_TREE_ENTRIES: usize = 10_000;

/// Maximum tree depth.
pub const MAX_TREE_DEPTH: usize = 32;

/// Maximum nesting depth of one decoded CBOR value.
///
/// The decoder walks arrays and maps by recursing, and every byte of a hostile payload can open
/// another level: `0x81` repeated is one array per byte, so a body well inside `MAX_OBJECT_BYTES`
/// can exhaust the stack and abort the process. A limit is what makes the recursion bounded, and it
/// is checked on the way *down*, before the frame is taken.
///
/// Twice `MAX_TREE_DEPTH` because a tree at full depth is itself a nested value and its encoding
/// adds levels of its own — a limit that refused the deepest legal object would be a limit on the
/// model rather than on the decoder.
pub const MAX_VALUE_DEPTH: usize = MAX_TREE_DEPTH * 2;

/// Maximum number of annotations on one tree entry.
pub const MAX_ANNOTATIONS_PER_ENTRY: usize = 32;

/// Maximum byte length of one annotation value.
pub const MAX_ANNOTATION_VALUE_BYTES: usize = 1024;

/// Maximum number of predecessors of a commit.
pub const MAX_PREDECESSORS: usize = 2;
