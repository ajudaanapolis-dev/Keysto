//! Keystone alpha — Bitcoin merkle inclusion proof verification (slice 2).
//!
//! MerkleProof { tx_index, siblings, total_transactions }: reconstrói o
//! merkle_root do bloco a partir do txid e compara com o do header. Qualquer
//! falha => BadMerklePath. Endurecido contra CVE-2012-2459.

use crate::{sha256d, H256Internal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    EmptyTree,
    IndexOutOfRange { index: u32, total: u32 },
    BranchLengthMismatch { expected: usize, got: usize },
    IdenticalChildren { level: usize },
    MalformedDuplication { level: usize },
    RootMismatch { expected: H256Internal, got: H256Internal },
}

impl MerkleError {
    pub fn challenge_reason(&self) -> &'static str {
        "BadMerklePath"
    }
}

fn tree_depth(n: u32) -> usize {
    let mut width = n as u64;
    let mut depth = 0usize;
    while width > 1 {
        width = (width + 1) / 2;
        depth += 1;
    }
    depth
}

#[inline]
fn hash_pair(left: &H256Internal, right: &H256Internal) -> H256Internal {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d(&buf)
}

pub fn compute_merkle_root_from_branch(
    txid: &H256Internal,
    index: u32,
    siblings: &[H256Internal],
    total_transactions: u32,
) -> Result<H256Internal, MerkleError> {
    if total_transactions == 0 {
        return Err(MerkleError::EmptyTree);
    }
    if index >= total_transactions {
        return Err(MerkleError::IndexOutOfRange {
            index,
            total: total_transactions,
        });
    }
    let depth = tree_depth(total_transactions);
    if siblings.len() != depth {
        return Err(MerkleError::BranchLengthMismatch {
            expected: depth,
            got: siblings.len(),
        });
    }

    let mut h = *txid;
    let mut idx = index as u64;
    let mut num = total_transactions as u64;

    for (level, sib) in siblings.iter().enumerate() {
        let is_last_odd = (num % 2 == 1) && (idx == num - 1);

        if is_last_odd {
            if *sib != h {
                return Err(MerkleError::MalformedDuplication { level });
            }
            h = hash_pair(&h, &h);
        } else if idx % 2 == 0 {
            if *sib == h {
                return Err(MerkleError::IdenticalChildren { level });
            }
            h = hash_pair(&h, sib);
        } else {
            if *sib == h {
                return Err(MerkleError::IdenticalChildren { level });
            }
            h = hash_pair(sib, &h);
        }

        idx /= 2;
        num = (num + 1) / 2;
    }

    Ok(h)
}

pub fn verify_merkle_inclusion(
    txid: &H256Internal,
    index: u32,
    siblings: &[H256Internal],
    total_transactions: u32,
    expected_merkle_root: &H256Internal,
) -> Result<(), MerkleError> {
    let got = compute_merkle_root_from_branch(txid, index, siblings, total_transactions)?;
    if &got != expected_merkle_root {
        return Err(MerkleError::RootMismatch {
            expected: *expected_merkle_root,
            got,
        });
    }
    Ok(())
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn depth_table() {
        assert_eq!(tree_depth(1), 0);
        assert_eq!(tree_depth(2), 1);
        assert_eq!(tree_depth(3), 2);
        assert_eq!(tree_depth(4), 2);
        assert_eq!(tree_depth(5), 3);
        assert_eq!(tree_depth(6), 3);
        assert_eq!(tree_depth(7), 3);
        assert_eq!(tree_depth(8), 3);
        assert_eq!(tree_depth(9), 4);
    }

    #[test]
    fn single_tx_root_is_the_txid() {
        let txid = [7u8; 32];
        let root = compute_merkle_root_from_branch(&txid, 0, &[], 1).unwrap();
        assert_eq!(root, txid);
    }
}
