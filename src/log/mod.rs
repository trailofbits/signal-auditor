use sha2::{Digest, Sha256};
use crate::{Hash, Index, Seed};

// A log node is a root of a maximal balanced subtree.
#[derive(Clone)]
struct LogNode {
    root: Hash,
    size: u64, // Not strictly necessary, we could compute from the total size of the log.
}

impl LogNode {
    fn as_bytes(&self) -> [u8; 33] {
        let mut buf = [0u8; 33];
        buf[0] = (self.size != 1) as u8;
        buf[1..].copy_from_slice(self.root.as_slice());
        buf
    }
}

// The log tree is a left-balanced binary tree.
// `roots` is a list of the roots of the maximal complete subtrees.
//  which are always the left children nodes in the traversal to the rightmost node
#[derive(Clone)]
pub(crate) struct LogTreeCache {
    roots: Vec<LogNode>,
}

impl LogTreeCache {
    pub fn new() -> Self {
        Self { roots: vec![] }
    }



    pub fn insert(&mut self, entry: &Hash) {
        let mut new_node = LogNode {
            root: entry.clone(),
            size: 1,
        };

        while let Some(x) = self.roots.pop() {
            if x.size == new_node.size {
                new_node = LogNode {
                    root: tree_hash(&x, &new_node),
                    size: new_node.size * 2,
                };
            } else {
                self.roots.push(x);
                break;
            }
        }

        self.roots.push(new_node);
    }

    pub fn root(&self) -> Hash {
        let mut roots = self.roots.clone();
        let mut root = roots.pop().expect("Log tree is nonempty");
        while let Some(x) = roots.pop() {
            root = LogNode { 
                root: tree_hash(&x, &root),
                size: x.size + root.size
            }
        }
        root.root
    }
}



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

        let expected_root = generic_hex("0000000000000000000000000000000000000000000000000000000000000000");

        assert_eq!(log.root(), expected_root);

        leaf[0] = 1;
        log.insert(&leaf);

        let expected_root = generic_hex("133f2fb2b9884f212cb981871e3a33bddd95c40fc65a43a1ab21c1011d1a48c7");

        assert_eq!(log.root(), expected_root);

        leaf[0] = 2;
        log.insert(&leaf);

        let expected_root = generic_hex("7fb7325069ae4e7dd39c974f8839e6ff988d679267d0a356073e2c99fb1e3a03");

        assert_eq!(log.root(), expected_root);
    }
}