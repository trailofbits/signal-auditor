//! The Log Tree is a binary left-balanced merkle tree.
//!
//! Leaves are inserted left-to-right. Only the roots of the maximal complete
//! subtrees are stored. This is sufficient to compute the evolution of the
//! log.
//!
//! For example, the log
//!
//! ```text
//!     (*)
//!   /   \
//!  *     *
//! / \   / \
//! 0 1 2 3 4
//!
//! evolves into:
//!         *
//!       /  \
//!     (*)   (5)
//!   /   \
//!  *     *
//! / \   / \
//! 0 1 2 3 4
//!
//! which evolves into:
//!
//!          *
//!       /    \
//!     (*)     (*)
//!   /   \    /   \
//!  *     *  5     6
//! / \   / \
//! 0 1 2 3 4

//!
//! where (_) denotes a cached maximal root.
//! ```

use crate::Hash;
use sha2::{Digest, Sha256};

/// A log node is a root of a maximal balanced subtree.
/// When size is 1, the node is a leaf.
#[derive(Clone)]
struct LogNode {
    root: Hash,
    size: u64, // Not strictly necessary, we could compute from the total size of the log.
}

impl LogNode {
    /// Serialize the node as a 33-byte array.
    /// The first byte is 1 if the node is not a leaf, 0 otherwise.
    /// The remaining 32 bytes are the root hash.
    fn as_bytes(&self) -> [u8; 33] {
        let mut buf = [0u8; 33];
        buf[0] = (self.size != 1) as u8;
        buf[1..].copy_from_slice(self.root.as_slice());
        buf
    }
}

/// The log tree is a left-balanced binary tree.
/// `roots` is a list of the roots of the maximal complete subtrees.
///  which are always the left children nodes in the traversal to the rightmost node
#[derive(Clone)]
pub(crate) struct LogTreeCache {
    roots: Vec<LogNode>,
}

impl LogTreeCache {
    pub fn new() -> Self {
        Self { roots: vec![] }
    }

    /// Insert a new leaf into the log on the right
    pub fn insert(&mut self, entry: &Hash) {
        let mut new_node = LogNode {
            root: *entry,
            size: 1,
        };

        // Add the new node as a maximal subtree and then
        // iteratively combine it with the rightmost node.
        while let Some(x) = self.roots.pop() {
            // If we have two complete subtrees of the same size,
            // combine them into a larger complete subtree.
            if x.size == new_node.size {
                new_node = LogNode {
                    root: tree_hash(&x, &new_node),
                    size: new_node.size * 2,
                };
            } else {
                // Otherwise, we have a complete subtree of a different size.
                // Add it back to the list and stop.
                // This implicitly adds a new unbalanced node to the tree that is the parent of
                // the two rightmost maximal subtrees.
                self.roots.push(x);
                break;
            }
        }

        self.roots.push(new_node);
    }

    /// Compute the root of the log tree.
    pub fn root(&self) -> Hash {
        let mut roots = self.roots.clone();
        let mut root = roots.pop().expect("Log tree is nonempty");
        while let Some(x) = roots.pop() {
            root = LogNode {
                root: tree_hash(&x, &root),
                size: x.size + root.size,
            }
        }
        root.root
    }
}

/// Compute the parent hash of two log nodes.
fn tree_hash(left: &LogNode, right: &LogNode) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic_array::GenericArray;
    use hex::decode;
    use sha2::digest::OutputSizeUser;

    fn generic_hex(hex: &str) -> GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize> {
        let mut arr = GenericArray::default();
        arr.copy_from_slice(&decode(hex).unwrap());
        arr
    }

    #[test]
    fn test_log_append() {
        let mut log = LogTreeCache::new();
        let mut leaf = GenericArray::default();
        log.insert(&leaf);

        let expected_root =
            generic_hex("0000000000000000000000000000000000000000000000000000000000000000");

        assert_eq!(log.root(), expected_root);

        leaf[0] = 1;
        log.insert(&leaf);

        let expected_root =
            generic_hex("133f2fb2b9884f212cb981871e3a33bddd95c40fc65a43a1ab21c1011d1a48c7");

        assert_eq!(log.root(), expected_root);

        leaf[0] = 2;
        log.insert(&leaf);

        let expected_root =
            generic_hex("7fb7325069ae4e7dd39c974f8839e6ff988d679267d0a356073e2c99fb1e3a03");

        assert_eq!(log.root(), expected_root);
    }
}
