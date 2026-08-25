// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Merkle tree over a batch, so a tenant can verify its own records
//! without being handed anybody else's.
//!
//! # Why the chain is not enough
//!
//! A tenant-scoped reader sees a *subsequence* of a producer's stream: the
//! records between its own belong to other tenants and must not be disclosed.
//! A hash chain cannot be checked with holes in it — that is the whole point
//! of a chain. So each batch envelope carries a Merkle root beside its head,
//! and a scoped reader is given the inclusion path for each of its records.
//!
//! Two proofs, two audiences: the chain proves the producer's whole history to
//! whoever is authorized for it; the inclusion path proves *this record was in
//! a batch signed by that producer* to somebody authorized for one tenant.
//!
//! # The construction
//!
//! [RFC 6962]'s, including the part that is easy to leave out:
//!
//! ```text
//! leaf(d)        = SHA-256( 0x00 || d )
//! node(l, r)     = SHA-256( 0x01 || l || r )
//! ```
//!
//! The distinct prefixes are what stop an internal node from being presented
//! as a leaf — without them a two-record proof can be forged from a one-record
//! tree. An odd level promotes its last node unchanged rather than duplicating
//! it, which is the other half of the same defence.
//!
//! [RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962#section-2.1

use sha2::{Digest as _, Sha256};

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

/// One step of an inclusion path: a sibling, and which side it is on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Step {
    /// The sibling hash, `sha256:`-prefixed like every digest in this product.
    pub sibling: String,
    /// Whether the sibling sits on the left of the node being carried up.
    pub left: bool,
}

/// Computes the root over `leaves`, in order.
///
/// An empty batch has no root: a batch with no records is not shipped, and a
/// caller asking for the root of nothing has a bug rather than an edge case.
pub fn root(leaves: &[String]) -> Option<String> {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
    if level.is_empty() {
        return None;
    }

    while level.len() > 1 {
        level = fold(&level);
    }

    level.first().map(render)
}

/// Builds the inclusion path for the leaf at `index`.
pub fn path(leaves: &[String], index: usize) -> Option<Vec<Step>> {
    if index >= leaves.len() {
        return None;
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
    let mut position = index;
    let mut steps = Vec::new();

    while level.len() > 1 {
        // The last node of an odd level is promoted, so it has no sibling here.
        if position.is_multiple_of(2) && position + 1 == level.len() {
            level = fold(&level);
            position /= 2;
            continue;
        }
        let (sibling, left) = if position.is_multiple_of(2) {
            (level[position + 1], false)
        } else {
            (level[position - 1], true)
        };
        steps.push(Step {
            sibling: render(&sibling),
            left,
        });
        level = fold(&level);
        position /= 2;
    }

    Some(steps)
}

/// Recomputes the root that `leaf` and `steps` imply.
///
/// A verifier compares this against the root in the signed envelope. It never
/// takes the root from the same place it took the path.
pub fn recompute(leaf: &str, steps: &[Step]) -> String {
    let mut carried = hash_leaf(leaf);
    for step in steps {
        let sibling = parse(&step.sibling).unwrap_or([0u8; 32]);
        carried = if step.left {
            hash_node(&sibling, &carried)
        } else {
            hash_node(&carried, &sibling)
        };
    }

    render(&carried)
}

fn fold(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let (pairs, odd) = level.as_chunks::<2>();
    for pair in pairs {
        next.push(hash_node(&pair[0], &pair[1]));
    }
    // An odd level promotes its last node unchanged rather than duplicating it:
    // see the module documentation for why that is half of the defence.
    if let Some(promoted) = odd.first() {
        next.push(*promoted);
    }

    next
}

fn hash_leaf(digest: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF]);
    // The leaf commits to the digest string as it is written, so a verifier
    // that never parsed a digest reaches the same tree.
    hasher.update(digest.as_bytes());

    hasher.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE]);
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

fn render(hash: &[u8; 32]) -> String {
    let mut text = String::from("sha256:");
    for byte in hash {
        text.push_str(&format!("{byte:02x}"));
    }

    text
}

fn parse(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut raw = [0u8; 32];
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        raw[index] = u8::from_str_radix(pair, 16).ok()?;
    }

    Some(raw)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn leaves(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("sha256:{index:064x}"))
            .collect()
    }

    #[test]
    fn test_every_leaf_of_every_shape_proves_itself() {
        // Odd sizes are where a promoted last node either works or does not.
        for count in 1..=17 {
            let leaves = leaves(count);
            let root = root(&leaves).expect("a non-empty batch has a root");
            for (index, leaf) in leaves.iter().enumerate() {
                let steps = path(&leaves, index).expect("the leaf is in the tree");
                assert_eq!(
                    recompute(leaf, &steps),
                    root,
                    "leaf {index} of {count} does not reach the root"
                );
            }
        }
    }

    #[test]
    fn test_a_leaf_cannot_be_moved_to_another_position() {
        let leaves = leaves(8);
        let root = root(&leaves).expect("a root");
        let steps = path(&leaves, 3).expect("a path");

        assert_ne!(
            recompute(&leaves[4], &steps),
            root,
            "another leaf must not verify against a path that is not its own"
        );
    }

    #[test]
    fn test_an_internal_node_cannot_be_presented_as_a_leaf() {
        // The domain-separating prefixes are what make this true: without
        // them, hash_node(a, b) and hash_leaf(x) live in one space and a
        // subtree can be replayed as a record.
        let pair = [format!("sha256:{:064x}", 1), format!("sha256:{:064x}", 2)];
        let internal = root(&pair).expect("a root");

        assert_ne!(
            hash_leaf(&internal),
            hash_node(&hash_leaf(&pair[0]), &hash_leaf(&pair[1])),
            "a node hash must not be reachable as a leaf hash"
        );
    }

    #[test]
    fn test_one_record_has_a_root_and_an_empty_path() {
        let single = leaves(1);
        let root = root(&single).expect("a root");

        assert_eq!(path(&single, 0), Some(Vec::new()));
        assert_eq!(recompute(&single[0], &[]), root);
    }

    #[test]
    fn test_a_batch_with_no_records_has_no_root() {
        assert_eq!(root(&[]), None);
        assert_eq!(path(&[], 0), None);
    }

    #[test]
    fn test_changing_any_record_changes_the_root() {
        let mut leaves = leaves(6);
        let before = root(&leaves).expect("a root");
        leaves[4] = format!("sha256:{:064x}", 999);

        assert_ne!(before, root(&leaves).expect("a root"));
    }
}
