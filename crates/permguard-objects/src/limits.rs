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

/// Maximum number of annotations on one tree entry.
pub const MAX_ANNOTATIONS_PER_ENTRY: usize = 32;

/// Maximum byte length of one annotation value.
pub const MAX_ANNOTATION_VALUE_BYTES: usize = 1024;

/// Maximum number of predecessors of a commit.
pub const MAX_PREDECESSORS: usize = 2;
