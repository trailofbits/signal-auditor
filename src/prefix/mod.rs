//! The Prefix Tree is a binary prefix merkle tree.
//!
//! The tree maps an `Index` to a leaf that tracks
//! - `counter`: version of the leaf, increments each time the index is inserted
//! - `position`: the index in the top-level log at which the the index was _first_ inserted
//!
//! Rather than using variable-depth leaves, all leaves are located at the lowest
//! level of the tree (256). The copath of the leaf is generated pseudorandomly at
//! the time of insertion. These nodes are called "stand-ins hashes".
//!
//! When inserting a new leaf, a non-inclusion proof is provided,
//! terminating at the first stand-in hash on the leaf's direct path. The implementation
//! verifies the non-inclusion proof against the current root and then replaces the
//! stand-in hash with a fresh subtree containing the new leaf.
//!
//! When incrementing the counter of a leaf, an inclusion proof is provided for the
//! existing leaf. The implementation verifies the inclusion proof against the current root
//! and then updates the leaf with the new counter, retaining the original position.
//!
//! The tree also supports a "fake" update, which is used to replace a stand-in hash
//! with a new stand-in hash. This is used to mask the metadata of user updates.

use crate::proto::AuditorUpdate;
use crate::proto::auditor_proof::{DifferentKey, Proof, SameKey};
use crate::{Hash, Index, Seed, try_into_hash};
use sha2::{Digest, Sha256};

/// A head of the prefix tree, at a particular position in the top-level log.
pub struct PrefixTreeCache {
    pub(crate) head: Hash,
    pub(crate) size: u64,
}

impl Default for PrefixTreeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// An update to the prefix tree.
pub(crate) enum PrefixTreeUpdate {
    /// A new tree is created with a single initial real leaf.
    NewTree { index: Index, seed: Seed },
    /// Either a fake node is replaced with a real leaf,
    /// or a fake node is replaced with a fake node.
    DifferentKey {
        real: bool,
        index: Index,
        seed: Seed,
        old_seed: Seed,
        copath: Vec<Hash>,
    },
    /// A real leaf is incremented.
    SameKey {
        index: Index,
        copath: Vec<Hash>,
        seed: Seed,
        counter: u32,
        position: u64,
    },
}

// Convert an auditor update off the wire into a prefix tree update.
impl TryFrom<AuditorUpdate> for PrefixTreeUpdate {
    type Error = String;
    fn try_from(update: AuditorUpdate) -> Result<Self, Self::Error> {
        let proof = update.proof.and_then(|x| x.proof).ok_or("Missing proof")?;
        match proof {
            Proof::NewTree(_) => {
                // New trees always start with one real leaf.
                if !update.real {
                    return Err("Fake update".to_string());
                }
                Ok(PrefixTreeUpdate::NewTree {
                    index: update.index.try_into().map_err(|_| "Invalid index")?,
                    seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
                })
            }
            Proof::DifferentKey(DifferentKey { copath, old_seed }) => {
                Ok(PrefixTreeUpdate::DifferentKey {
                    real: update.real,
                    index: update.index.try_into().map_err(|_| "Invalid index")?,
                    seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
                    old_seed: old_seed.try_into().map_err(|_| "Invalid old seed")?,
                    copath: copath
                        .into_iter()
                        .map(try_into_hash)
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            Proof::SameKey(SameKey {
                copath,
                counter,
                position,
            }) => {
                // Real leaves cannot be replaced with fake nodes.
                if !update.real {
                    return Err("Fake update".to_string());
                }

                Ok(PrefixTreeUpdate::SameKey {
                    index: update.index.try_into().map_err(|_| "Invalid index")?,
                    copath: copath
                        .into_iter()
                        .map(try_into_hash)
                        .collect::<Result<Vec<_>, _>>()?,
                    seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
                    counter,
                    position,
                })
            }
        }
    }
}

impl PrefixTreeCache {
    /// Creates a new empty prefix tree cache.
    pub fn new() -> Self {
        Self {
            head: Hash::default(),
            size: 0,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.size > 0
    }

    /// Apply an update to the prefix tree
    ///
    /// Returns the new head of the tree and the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the update is malformed or inconsistent with the current state.
    pub(crate) fn apply_update(&mut self, update: PrefixTreeUpdate) -> Result<(), String> {
        let proof = match update {
            PrefixTreeUpdate::NewTree { index, seed } => {
                if self.is_initialized() {
                    return Err("Tree already initialized".to_string());
                }

                PrefixProof::real(
                    &PrefixLeaf {
                        index,
                        counter: 0,
                        position: 0,
                    },
                    &[],
                    &seed,
                )
            }
            PrefixTreeUpdate::SameKey {
                index,
                copath,
                seed,
                counter,
                position,
            } => {
                if !self.is_initialized() {
                    return Err("Tree not initialized".to_string());
                }

                // Check that lookup at counter, position is the same as the old root.
                let proof = PrefixProof::real(
                    &PrefixLeaf {
                        index,
                        counter,
                        position,
                    },
                    &copath,
                    &seed,
                )?;

                // Check the proof is consistent with the current root.
                if proof.compute_root() != self.head {
                    return Err("Old root mismatch".to_string());
                }

                // Update the cache
                PrefixProof::real(
                    &PrefixLeaf {
                        index,
                        counter: counter + 1,
                        // Tracks the _first_ time the index was inserted.
                        position,
                    },
                    &copath,
                    &seed,
                )
            }
            PrefixTreeUpdate::DifferentKey {
                real,
                index,
                seed,
                old_seed,
                copath,
            } => {
                if !self.is_initialized() {
                    return Err("Tree not initialized".to_string());
                }

                // DifferentKey updates always replace a fake node.
                // The proof is a non-inclusion proof, terminating at the first stand-in hash.
                let proof = PrefixProof::fake(&index, &copath, &old_seed)?;

                // Check the proof is consistent with the current root.
                if proof.compute_root() != self.head {
                    return Err("Old root mismatch".to_string());
                }

                if real {
                    PrefixProof::real(
                        &PrefixLeaf {
                            index,
                            counter: 0,
                            position: self.size,
                        },
                        &copath,
                        &seed,
                    )
                } else {
                    PrefixProof::fake(&index, &copath, &seed)
                }
            }
        };

        self.head = proof?.compute_root();
        self.size += 1;

        Ok(())
    }

    pub fn root(&self) -> Option<Hash> {
        if self.is_initialized() {
            Some(self.head)
        } else {
            None
        }
    }
}

struct PrefixLeaf {
    index: Index,
    position: u64, // The index of the first log entry in which this leaf appeared.
    counter: u32,  // The version of this leaf (number of updates)
}

fn leaf_hash(leaf: &PrefixLeaf) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf.index);
    hasher.update(leaf.counter.to_be_bytes());
    hasher.update(leaf.position.to_be_bytes());
    hasher.finalize()
}

fn stand_in_hash(seed: &Seed, level: u8) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x02]);
    hasher.update(seed);
    hasher.update([level]);
    hasher.finalize()
}

fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

/// A PrefixProof is a proof that `value` appears along the direct path to
/// `index` in the tree at height `copath.len()`.
struct PrefixProof {
    value: Hash,
    index: Index,
    copath: Vec<Hash>,
}

impl PrefixProof {
    /// Constructs a proof for a fake insertion.
    /// The insertion replaces a stand-in hash along the direct
    /// path to `index` at height `copath.len()`.
    fn fake(index: &Index, copath: &[Hash], seed: &Seed) -> Result<Self, String> {
        let level: u8 = (copath.len() - 1).try_into().or(Err("Copath too long"))?;

        let value = stand_in_hash(seed, level);

        Ok(Self {
            value,
            index: index.to_owned(),
            copath: copath.to_owned(),
        })
    }

    /// Constructs a proof for a new leaf insertion.
    /// The copath is generated pseudorandomly at the time of insertion.
    /// using the `seed` parameter.
    fn real(leaf: &PrefixLeaf, copath: &[Hash], seed: &Seed) -> Result<Self, String> {
        if copath.len() > 256 {
            return Err("Copath too long".to_string());
        }

        // TODO - use iterators to avoid copying
        let mut copath = copath.to_vec();
        // Fill in missing copath nodes using the seed.
        for i in copath.len()..256 {
            copath.push(stand_in_hash(seed, i as u8));
        }

        let value = leaf_hash(leaf);
        Ok(Self {
            value,
            index: leaf.index,
            copath,
        })
    }

    /// Compute root from a proof.
    fn compute_root(&self) -> Hash {
        let mut node = self.value;
        let index = self.index;
        for i in (0..self.copath.len()).rev() {
            if index[i / 8] >> (7 - (i % 8)) & 1 == 0 {
                node = parent_hash(&node, &self.copath[i]);
            } else {
                node = parent_hash(&self.copath[i], &node);
            }
        }

        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;
    use hex_literal::hex;

    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use generic_array::GenericArray;

    use crate::proto::auditor_proof::{DifferentKey, Proof};
    use crate::proto::{AuditorProof, AuditorUpdate};

    fn seed(position: u64) -> Seed {
        // Encrypt "position" with zero AES seed
        let mut buffer = GenericArray::default();
        buffer[8..].copy_from_slice(&position.to_be_bytes());
        let aes = Aes128::new(&[0u8; 16].into());
        aes.encrypt_block(&mut buffer);
        buffer.into()
    }

    #[test]
    fn test_new_tree() {
        let index = Index::default();
        let seed = seed(0);
        let expected_root =
            hex!("6eefbfcdf7b929b73963cb21eb882a2a3e49e8958fe25795df82d099e551915c").into();

        let mut cache = PrefixTreeCache::new();
        cache
            .apply_update(PrefixTreeUpdate::NewTree { index, seed })
            .unwrap();
        assert_eq!(
            cache.head,
            expected_root,
            "Expected root: {:?}, got: {:?}",
            expected_root.encode_hex::<String>(),
            cache.head.encode_hex::<String>()
        );
        assert_eq!(cache.size, 1);
    }

    #[test]
    fn test_update() {
        let mut index = Index::default().to_vec();
        index[0] = 0x80;
        let old_seed = seed(0);
        let seed = seed(1).to_vec();
        let commitment = Hash::default().to_vec();
        let old_root =
            hex!("6eefbfcdf7b929b73963cb21eb882a2a3e49e8958fe25795df82d099e551915c").into();
        let expected_root =
            hex!("55a94bcb3a3958a83fab0053bdb553b4774b19a6516ac7fe0811a498396c2d36").into();

        let copath =
            vec![hex!("33819dcecb822883dd9e134325f28ba79d114fe69bb33a09d9755c6507fe22e7").into()];

        let update = AuditorUpdate {
            real: true,
            index,
            seed,
            commitment,
            proof: Some(AuditorProof {
                proof: Some(Proof::DifferentKey(DifferentKey {
                    copath,
                    old_seed: old_seed.to_vec(),
                })),
            }),
        }
        .try_into()
        .unwrap();

        let mut cache = PrefixTreeCache {
            head: old_root,
            size: 1,
        };

        cache.apply_update(update).unwrap();

        assert_eq!(
            cache.head,
            expected_root,
            "Expected root: {:?}, got: {:?}",
            expected_root.encode_hex::<String>(),
            cache.head.encode_hex::<String>()
        );
        assert_eq!(cache.size, 2);
    }

    #[test]
    fn test_fake_update() {
        let mut index: Vec<u8> = Index::default().into();
        index[0] = 0xc0;
        let commitment = Hash::default().to_vec();
        let old_root =
            hex!("55a94bcb3a3958a83fab0053bdb553b4774b19a6516ac7fe0811a498396c2d36").into();
        let expected_root =
            hex!("82c7616b35828d31468590ecec7e3b62a31c7ec7a6874229da90a9cebf28a1df").into();

        let copath = vec![
            hex!("33819dcecb822883dd9e134325f28ba79d114fe69bb33a09d9755c6507fe22e7").into(),
            hex!("a7d0256b66a95ad4a8f9efed2ee9f060cc50c32336223063c30483dda33f0408").into(),
        ];

        let update = AuditorUpdate {
            real: false,
            index,
            seed: seed(2).into(),
            commitment,
            proof: Some(AuditorProof {
                proof: Some(Proof::DifferentKey(DifferentKey {
                    copath,
                    old_seed: seed(1).into(),
                })),
            }),
        }
        .try_into()
        .unwrap();

        let mut cache = PrefixTreeCache {
            head: old_root,
            size: 2,
        };

        cache.apply_update(update).unwrap();

        assert_eq!(
            cache.head,
            expected_root,
            "Expected root: {:?}, got: {:?}",
            expected_root.encode_hex::<String>(),
            cache.head.encode_hex::<String>()
        );
        assert_eq!(cache.size, 3);
    }
}
