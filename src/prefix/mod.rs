use crate::{Hash, Index, Seed, AuditorUpdate, Proof, try_into_hash};
use crate::transparency::auditor_proof::{DifferentKey, SameKey};
use sha2::{Digest, Sha256};

// Prefix tree is a K-V merkle tree. However, instead of
// dynamically increasing the size of the tree and giving variable-length
// copaths, the tree is fixed-size and sibling nodes are generated pseudorandomly
// at insertion time. Updates may later replace a fake node with a real one.
pub(crate) struct PrefixTreeCache {
    head: Hash,
    position: u64,
}


pub(crate) enum PrefixTreeUpdate {
    NewTree {
        index: Index,
        seed: Seed,
    },
    DifferentKey {
        real: bool,
        index: Index,
        seed: Seed,
        old_seed: Seed,
        copath: Vec<Hash>,
    },
    SameKey {
        index: Index,
        copath: Vec<Hash>,
        seed: Seed,
        counter: u32,
        position: u64,
    },
}

impl TryFrom<AuditorUpdate> for PrefixTreeUpdate {
    type Error = String;
    fn try_from(update: AuditorUpdate) -> Result<Self, Self::Error> {
        let proof = update.proof.and_then(|x| x.proof).ok_or("Missing proof")?;
        match proof {
            Proof::NewTree(_) => {
                if !update.real {
                    return Err("Fake update".to_string());
                }
                Ok(PrefixTreeUpdate::NewTree {
                index: update.index.try_into().map_err(|_| "Invalid index")?,
                seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
            })},
            Proof::DifferentKey( DifferentKey { copath, old_seed }) => Ok(PrefixTreeUpdate::DifferentKey {
                real: update.real,
                index: update.index.try_into().map_err(|_| "Invalid index")?,
                seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
                old_seed: old_seed.try_into().map_err(|_| "Invalid old seed")?,
                copath: copath.into_iter().map(try_into_hash).collect::<Result<Vec<_>, _>>()?,
            }),
            Proof::SameKey (SameKey { copath, counter, position }) => {
                if !update.real {
                    return Err("Fake update".to_string());
                }
                
                Ok(PrefixTreeUpdate::SameKey {
                index: update.index.try_into().map_err(|_| "Invalid index")?,
                copath: copath.into_iter().map(try_into_hash).collect::<Result<Vec<_>, _>>()?,
                seed: update.seed.try_into().map_err(|_| "Invalid seed")?,
                counter,
                position,
            })}
        }
    }
}

impl PrefixTreeCache {
    pub fn new(index: Index, seed: Seed) -> Self {
        let proof = PrefixProof::real(
            &PrefixLeaf {
                index,
                counter: 0,
                position: 0,
            },  
            &[],
            &seed).expect("empty copath is OK");
    
            let head = proof.compute_root();
    
            PrefixTreeCache { head, position: 0 }
    }

    pub fn apply_update(
        &self,
        update: PrefixTreeUpdate,
    ) -> Result<Self, String> {
        let proof = match update {
            PrefixTreeUpdate::NewTree { index, seed } => {
                PrefixProof::real(
                    &PrefixLeaf {
                        index,
                        counter: 0,
                        position: self.position + 1,
                    },  
                    &[],
                    &seed)
                
            }
            PrefixTreeUpdate::SameKey { index, copath, seed, counter, position } => {    
    
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
    
                let old_root = proof.compute_root();
    
                if old_root != self.head {
                    return Err("Old root mismatch".to_string());
                }
    
                // Update the cache
                PrefixProof::real(
                    &PrefixLeaf {
                        index,
                        counter: counter + 1,
                        position,
                    },
                    &copath,
                    &seed,
                )
            }
    
            PrefixTreeUpdate::DifferentKey { real, index, seed, old_seed, copath } => {
                let proof = PrefixProof::fake(&index, &copath, &old_seed)?;
    
                let old_head = proof.compute_root();
    
                if old_head != self.head {
                    return Err("Old root mismatch".to_string());
                }
    
                if real {
                    PrefixProof::real(
                        &PrefixLeaf {
                            index,
                            counter: 0,
                            position: self.position + 1,
                        },
                        &copath,
                        &seed,
                    )
                } else {
                    PrefixProof::fake(&index, &copath, &seed)
                }
            }
        };

        let head = proof?.compute_root();
    
        Ok(Self {
            head,
            position: self.position + 1,
        })
    }

    pub fn root(&self) -> Hash {
        self.head
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
    hasher.update(&[level]);
    hasher.finalize()
}

fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

struct PrefixProof {
    value: Hash,
    index: Index,
    copath: Vec<Hash>,
}

impl PrefixProof {
    // A proof for a fake insertion. The insertion replaces the stand-in hash at the
    // endpoint of the copath
    fn fake(index: &Index, copath: &[Hash], seed: &Seed) -> Result<Self, String> {
        let level: u8 = (copath.len() - 1).try_into().or(Err("Copath too long"))?;

        let value = stand_in_hash(seed, level);

        Ok(Self {
            value,
            index: index.to_owned(),
            copath: copath.to_owned(),
        })
    }

    /* 
    // A proof for a version increment operation.
    fn update(leaf: &PrefixLeaf, copath: &[Hash]) -> Result<Self, String> {
        let value = leaf_hash(leaf);
        Ok(Self {
            value,
            index: leaf.index.to_owned(),
            copath: copath.to_owned(),
        })
    }
    */

    // A proof for a new leaf insertion.
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

    // Compute root from a proof. Proofs may be partial.
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
    use hex_literal::hex;
    use hex::ToHex;

    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;
    use generic_array::GenericArray;

    use crate::transparency::{AuditorUpdate, AuditorProof};
    use crate::transparency::auditor_proof::{DifferentKey, SameKey, Proof};

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
        let expected_root = hex!("6eefbfcdf7b929b73963cb21eb882a2a3e49e8958fe25795df82d099e551915c").into();


        let cache = PrefixTreeCache::new(index, seed);
        assert_eq!(cache.head, expected_root, "Expected root: {:?}, got: {:?}", expected_root.encode_hex::<String>(), cache.head.encode_hex::<String>());
        assert_eq!(cache.position, 0);
    }

    #[test]
    fn test_update() {
        let mut index = Index::default().to_vec();
        index[0] = 0x80;
        let old_seed = seed(0);
        let seed = seed(1).to_vec();
        let commitment = Hash::default().to_vec();
        let old_root = hex!("6eefbfcdf7b929b73963cb21eb882a2a3e49e8958fe25795df82d099e551915c").into();
        let expected_root = hex!("55a94bcb3a3958a83fab0053bdb553b4774b19a6516ac7fe0811a498396c2d36").into();

        let copath = vec![
            hex!("33819dcecb822883dd9e134325f28ba79d114fe69bb33a09d9755c6507fe22e7").into(),
        ];


        let update = AuditorUpdate {
            real: true,
            index,
            seed,
            commitment,
            proof: Some(AuditorProof{proof: Some(Proof::DifferentKey (DifferentKey{
                copath,
                old_seed: old_seed.to_vec(),
            }))})
        }.try_into().unwrap();


        let cache = PrefixTreeCache { head: old_root, position: 0 }
            .apply_update(update).unwrap();
        assert_eq!(cache.head, expected_root, "Expected root: {:?}, got: {:?}", expected_root.encode_hex::<String>(), cache.head.encode_hex::<String>());
        assert_eq!(cache.position, 1);
    }

    #[test]
    fn test_fake_update() {
        let mut index : Vec<u8> = Index::default().into();
        index[0] = 0xc0;
        let commitment = Hash::default().to_vec();
        let old_root = hex!("55a94bcb3a3958a83fab0053bdb553b4774b19a6516ac7fe0811a498396c2d36").into();
        let expected_root = hex!("82c7616b35828d31468590ecec7e3b62a31c7ec7a6874229da90a9cebf28a1df").into();

        let copath = vec![
            hex!("33819dcecb822883dd9e134325f28ba79d114fe69bb33a09d9755c6507fe22e7").into(),
            hex!("a7d0256b66a95ad4a8f9efed2ee9f060cc50c32336223063c30483dda33f0408").into(),
        ];

        let update = AuditorUpdate {
            real: false,
            index,
            seed: seed(2).into(),
            commitment,
            proof: Some(AuditorProof{proof: Some(Proof::DifferentKey (DifferentKey{
                copath,
                old_seed: seed(1).into(),
            }))})
        }.try_into().unwrap();

        let cache = PrefixTreeCache { head: old_root, position: 1 }
            .apply_update(update).unwrap();

        assert_eq!(cache.head, expected_root, "Expected root: {:?}, got: {:?}", expected_root.encode_hex::<String>(), cache.head.encode_hex::<String>());
        assert_eq!(cache.position, 2);
    }
}
