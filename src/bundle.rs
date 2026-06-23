//! Keystone alpha — ClaimBundle (Parte E do patch v1.1.1) e os registries
//! confiáveis (chaves de solver, checkpoints aceitos).

use crate::order::{B256, BtcNetwork, Order};
use crate::taproot::Xpub;
use crate::H256Internal;

/// Prova de inclusão de Merkle. `total_transactions` é OBRIGATÓRIO para a
/// defesa CVE-2012-2459 (ver `merkle.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub tx_index: u32,
    pub siblings: Vec<H256Internal>,
    pub total_transactions: u32,
}

/// Pacote de evidência do pagamento Bitcoin (net, para o PR 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBundle {
    pub order: Order,                       // P1: { order_id, preimage, commitment }
    pub txid_internal: H256Internal,        // P4: verificado, nunca confiado
    pub raw_tx: Vec<u8>,                    // B1: forma WIRE (verificador faz o strip)
    pub vout: u32,                          // single output (§7.2)
    pub merkle_proof: MerkleProof,
    pub tx_block_index: u32,                // P5: índice em confirmation_headers
    pub checkpoint_id: B256,
    pub checkpoint_height: u32,
    pub checkpoint_hash: H256Internal,
    pub confirmation_headers: Vec<[u8; 80]>, // P6: EXCLUI checkpoint; [0].prev == cp.hash
    pub claimed_tip_height: u32,            // validado contra a contagem (P5/C6)
    pub claimed_tip_hash: H256Internal,
}

/// Registro de um checkpoint aceito (resolvido por `checkpoint_id`).
/// No alpha o checkpoint é fixado manualmente por um operador (§13 / narrativa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub network: BtcNetwork,
    pub height: u32,
    pub hash: H256Internal,
    pub nbits: u32,
}

pub trait CheckpointRegistry {
    fn resolve(&self, checkpoint_id: &B256) -> Option<CheckpointRecord>;
    fn contains(&self, network: BtcNetwork, height: u32, hash: &H256Internal) -> bool;
}

// --- Registries em memória (referência / testes) ---

/// Registry simples de chaves de solver.
#[derive(Default)]
pub struct InMemoryKeyRegistry {
    entries: Vec<(B256, Xpub)>,
}

impl InMemoryKeyRegistry {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }
    pub fn insert(&mut self, key_id: B256, xpub: Xpub) {
        self.entries.push((key_id, xpub));
    }
}

impl crate::order::KeyRegistry for InMemoryKeyRegistry {
    fn resolve(&self, key_id: &B256) -> Option<Xpub> {
        self.entries.iter().find(|(k, _)| k == key_id).map(|(_, v)| v.clone())
    }
}

/// Registry simples de checkpoints aceitos.
#[derive(Default)]
pub struct InMemoryCheckpointRegistry {
    entries: Vec<(B256, CheckpointRecord)>,
}

impl InMemoryCheckpointRegistry {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }
    pub fn insert(&mut self, checkpoint_id: B256, record: CheckpointRecord) {
        self.entries.push((checkpoint_id, record));
    }
}

impl CheckpointRegistry for InMemoryCheckpointRegistry {
    fn resolve(&self, checkpoint_id: &B256) -> Option<CheckpointRecord> {
        self.entries.iter().find(|(k, _)| k == checkpoint_id).map(|(_, v)| *v)
    }

    fn contains(&self, network: BtcNetwork, height: u32, hash: &H256Internal) -> bool {
        self.entries
            .iter()
            .any(|(_, v)| v.network == network && v.height == height && &v.hash == hash)
    }
}
