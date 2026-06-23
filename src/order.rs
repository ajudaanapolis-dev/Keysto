//! Keystone alpha — identidade econômica da ordem e derivação do endereço.
//!
//! P1: quebra a circularidade order_id <-> commitment.
//!   order_id         = keccak256(canonical_encode(OrderPreimage))
//!   (i0, i1)         = ( u31(sha256(order_id || 0x00)), u31(sha256(order_id || 0x01)) )
//!   script_pubkey    = derive_p2tr(xpub, i0, i1)                    (§2.6)
//!   commitment       = keccak256(script_pubkey_bytes)
//!   final_order_hash = keccak256(order_id || commitment)            (o solver assina ISSO)
//!
//! `order_id` é função SÓ do preimage; o commitment é derivado depois; o
//! final_order_hash amarra os dois. Sem ciclo.

use crate::taproot::{self, Xpub};
use crate::{keccak256, sha256};

pub type B256 = [u8; 32];
pub type Address = [u8; 20];

/// uint256 da EVM, big-endian. Parte da identidade da ordem (entra no hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        b[16..].copy_from_slice(&v.to_be_bytes());
        U256(b)
    }
    pub fn be_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtcNetwork {
    Mainnet = 0,
    Testnet = 1,
    Signet = 2,
    Regtest = 3,
}

impl BtcNetwork {
    pub fn tag(self) -> u8 {
        self as u8
    }
}

/// Identidade econômica da ordem (P1). Hash deste preimage gera o `order_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderPreimage {
    pub solver: Address,
    pub recipient: Address,
    pub btc_network: BtcNetwork,
    pub solver_btc_key_id: B256,
    pub amount_sat: u64,
    pub destination_token: Address,
    pub destination_amount: U256,
    pub min_confirmations: u32,
    pub max_btc_inclusion_height: u32,
    pub quote_expires_at_l2: u64,
    pub claim_deadline_l2: u64,
    pub reclaim_after_l2: u64,
    pub max_destination_amount_cap: U256,
    pub replay_domain: B256,
    pub nonce: B256,
}

impl OrderPreimage {
    /// [RECONSTRUÍDO — confirmar contra a codificação canônica de §0.3/§4.1]
    /// Encoding canônico determinístico: campos em largura fixa, big-endian,
    /// concatenados na ordem de declaração. Sem padding variável, sem ambiguidade.
    pub fn canonical_encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(20 + 20 + 1 + 32 + 8 + 20 + 32 + 4 + 4 + 8 + 8 + 8 + 32 + 32 + 32);
        o.extend_from_slice(&self.solver);
        o.extend_from_slice(&self.recipient);
        o.push(self.btc_network.tag());
        o.extend_from_slice(&self.solver_btc_key_id);
        o.extend_from_slice(&self.amount_sat.to_be_bytes());
        o.extend_from_slice(&self.destination_token);
        o.extend_from_slice(&self.destination_amount.0);
        o.extend_from_slice(&self.min_confirmations.to_be_bytes());
        o.extend_from_slice(&self.max_btc_inclusion_height.to_be_bytes());
        o.extend_from_slice(&self.quote_expires_at_l2.to_be_bytes());
        o.extend_from_slice(&self.claim_deadline_l2.to_be_bytes());
        o.extend_from_slice(&self.reclaim_after_l2.to_be_bytes());
        o.extend_from_slice(&self.max_destination_amount_cap.0);
        o.extend_from_slice(&self.replay_domain);
        o.extend_from_slice(&self.nonce);
        o
    }

    pub fn order_id(&self) -> B256 {
        keccak256(&self.canonical_encode())
    }

    pub fn validate(&self) -> Result<(), PreimageError> {
        if self.quote_expires_at_l2 > self.claim_deadline_l2 {
            return Err(PreimageError::Timeline);
        }
        if self.claim_deadline_l2 >= self.reclaim_after_l2 {
            return Err(PreimageError::Timeline);
        }
        if self.destination_amount > self.max_destination_amount_cap {
            return Err(PreimageError::DestinationAmountCapExceeded);
        }
        Ok(())
    }
}

/// (i0, i1) = ( u31(sha256(order_id||0x00)), u31(sha256(order_id||0x01)) ).
pub fn child_indices(order_id: &B256) -> (u32, u32) {
    let mut b0 = [0u8; 33];
    b0[..32].copy_from_slice(order_id);
    b0[32] = 0x00;
    let mut b1 = [0u8; 33];
    b1[..32].copy_from_slice(order_id);
    b1[32] = 0x01;
    (u31(&sha256(&b0)), u31(&sha256(&b1)))
}

/// [RECONSTRUÍDO] u31 = primeiros 4 bytes big-endian, com o bit alto zerado
/// (índice BIP32 não-endurecido, 0..2^31-1).
fn u31(h: &[u8; 32]) -> u32 {
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & 0x7fff_ffff
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    UnknownKey,
    Derivation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreimageError {
    Timeline,
    DestinationAmountCapExceeded,
}

/// Resolve `solver_btc_key_id` no xpub do solver (§2.6 / P8).
pub trait KeyRegistry {
    fn resolve(&self, key_id: &B256) -> Option<Xpub>;
}

/// Deriva (script_pubkey de 34B, commitment) a partir do preimage + registry.
pub fn derive_script_and_commitment<R: KeyRegistry>(
    preimage: &OrderPreimage,
    registry: &R,
) -> Result<([u8; 34], B256), BindError> {
    let oid = preimage.order_id();
    let (i0, i1) = child_indices(&oid);
    let xpub = registry.resolve(&preimage.solver_btc_key_id).ok_or(BindError::UnknownKey)?;
    let spk = taproot::derive_p2tr(&xpub, i0, i1).map_err(|_| BindError::Derivation)?;
    let commitment = keccak256(&spk);
    Ok((spk, commitment))
}

pub fn final_order_hash(order_id: &B256, commitment: &B256) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(order_id);
    b[32..].copy_from_slice(commitment);
    keccak256(&b)
}

/// Ordem completa: identidade + commitment derivado (P1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub order_id: B256,
    pub preimage: OrderPreimage,
    pub btc_script_pubkey_commitment: B256,
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn order_id_is_deterministic_and_preimage_only() {
        let p = sample_preimage();
        let a = p.order_id();
        let b = p.clone().order_id();
        assert_eq!(a, b);
        // mudar um campo do preimage muda o order_id.
        let mut p2 = p.clone();
        p2.amount_sat += 1;
        assert_ne!(p2.order_id(), a);
    }

    #[test]
    fn indices_are_non_hardened() {
        let p = sample_preimage();
        let (i0, i1) = child_indices(&p.order_id());
        assert_eq!(i0 & 0x8000_0000, 0);
        assert_eq!(i1 & 0x8000_0000, 0);
    }

    #[test]
    fn invalid_timeline_is_rejected() {
        let mut p = sample_preimage();
        p.claim_deadline_l2 = p.quote_expires_at_l2 - 1;
        assert_eq!(p.validate(), Err(PreimageError::Timeline));
    }

    #[test]
    fn destination_amount_above_cap_is_rejected() {
        let mut p = sample_preimage();
        p.max_destination_amount_cap = U256::from_u128(999_999);
        assert_eq!(p.validate(), Err(PreimageError::DestinationAmountCapExceeded));
    }

    fn sample_preimage() -> OrderPreimage {
        OrderPreimage {
            solver: [1u8; 20],
            recipient: [2u8; 20],
            btc_network: BtcNetwork::Regtest,
            solver_btc_key_id: [3u8; 32],
            amount_sat: 100_000,
            destination_token: [4u8; 20],
            destination_amount: U256::from_u128(1_000_000),
            min_confirmations: 1,
            max_btc_inclusion_height: 5_000,
            quote_expires_at_l2: 10,
            claim_deadline_l2: 20,
            reclaim_after_l2: 30,
            max_destination_amount_cap: U256::from_u128(2_000_000),
            replay_domain: [5u8; 32],
            nonce: [6u8; 32],
        }
    }
}
