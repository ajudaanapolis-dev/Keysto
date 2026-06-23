//! Keystone alpha — linkagem da cadeia de cabeçalhos a um checkpoint aceito.
//!
//! P5/P6/C6: nenhuma altura é lida de campo afirmado. A cadeia
//! `confirmation_headers` EXCLUI o checkpoint e começa no filho dele:
//!   confirmation_headers[0].prev_block == checkpoint.hash
//!   confirmation_headers[i].prev_block == hash(confirmation_headers[i-1])
//! Toda altura é DERIVADA por contagem a partir de `checkpoint.height`:
//!   block_height(i)            = checkpoint.height + i + 1
//!   claimed_tip_height_derived = checkpoint.height + len
//! O `claimed_tip_height` afirmado é validado contra a contagem; o
//! `claimed_tip_hash` é validado contra o hash do último header.
//!
//! No alpha, o PoW de TODO header é checado contra o `nBits` do checkpoint (P3).

use crate::pow::{self, PowError};
use crate::order::BtcNetwork;
use crate::{sha256d, H256Internal};

/// Âncora confiável (resolvida de um registry de checkpoints aceitos).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointAnchor {
    pub network: BtcNetwork,
    pub height: u32,
    pub hash: H256Internal,
    pub nbits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkageError {
    EmptyChain,
    Pow(PowError),
    /// prev_block de um header não bate com o hash do anterior (ou do checkpoint).
    BrokenLinkage { height: u32 },
    /// claimed_tip_height afirmado != contagem derivada.
    HeightMismatch { claimed: u32, derived: u32 },
    /// claimed_tip_hash afirmado != hash do último header.
    TipHashMismatch,
}

/// Verifica PoW + linkagem da cadeia inteira até o tip afirmado.
pub fn verify_header_chain(
    checkpoint: &CheckpointAnchor,
    confirmation_headers: &[[u8; 80]],
    claimed_tip_height: u32,
    claimed_tip_hash: &H256Internal,
) -> Result<(), LinkageError> {
    if confirmation_headers.is_empty() {
        return Err(LinkageError::EmptyChain);
    }

    let mut prev_hash = checkpoint.hash;
    for (i, hb) in confirmation_headers.iter().enumerate() {
        let height = checkpoint
            .height
            .checked_add(i as u32)
            .and_then(|v| v.checked_add(1))
            .ok_or(LinkageError::HeightMismatch {
                claimed: claimed_tip_height,
                derived: u32::MAX,
            })?;
        // [ALPHA] expected_nbits = checkpoint.nBits para TODO header de confirmação.
        pow::check_pow_with_expected_nbits(hb, checkpoint.nbits).map_err(LinkageError::Pow)?;
        let header = pow::parse_header(hb);
        if header.prev_block != prev_hash {
            return Err(LinkageError::BrokenLinkage { height });
        }
        prev_hash = sha256d(hb);
    }

    let derived_tip_height = checkpoint
        .height
        .checked_add(confirmation_headers.len() as u32)
        .ok_or(LinkageError::HeightMismatch {
            claimed: claimed_tip_height,
            derived: u32::MAX,
        })?;
    if claimed_tip_height != derived_tip_height {
        return Err(LinkageError::HeightMismatch {
            claimed: claimed_tip_height,
            derived: derived_tip_height,
        });
    }
    if &prev_hash != claimed_tip_hash {
        return Err(LinkageError::TipHashMismatch);
    }
    Ok(())
}

/// Altura do bloco que contém a tx, derivada por posição (P5).
pub fn block_height(checkpoint_height: u32, tx_block_index: u32) -> Option<u32> {
    checkpoint_height
        .checked_add(tx_block_index)
        .and_then(|height| height.checked_add(1))
}

/// Profundidade (confirmações) da tx: do bloco dela ao tip, inclusivo.
pub fn confirmations(chain_len: u32, tx_block_index: u32) -> u32 {
    chain_len - tx_block_index
}
