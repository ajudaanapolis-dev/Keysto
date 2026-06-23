//! Keystone alpha — `evaluate_claim_bundle`: o coração do verificador (§8).
//!
//! É o ORÁCULO: a definição executável da verdade contra a qual o contrato
//! otimista e o futuro circuito ZK são testados por diferencial. Ele desconfia
//! de CADA campo do bundle — nada que vem de quem submete passa sem verificação.
//!
//! ORDEM DE ADJUDICAÇÃO DETERMINÍSTICA (C8) — também a ordem de avaliação:
//!   1. encoding da tx + txid          -> BadTxEncoding / TxidMismatch
//!   2. parâmetros e janela L2         -> InvalidOrderParameters /
//!                                        ClaimExpired / ReclaimPhaseStarted /
//!                                        DestinationAmountCapExceeded
//!   3. âncora: PoW + linkagem         -> InvalidTarget / BadHeaderPoW /
//!                                        BrokenLinkage / InvalidCheckpointLinkage
//!   4. profundidade                   -> InsufficientDepth / InclusionHeightExceeded
//!   5. inclusão (Merkle no header)    -> BadMerklePath
//!   6. binding: script + valor        -> WrongScript / InsufficientAmount
//!
//! Cada `ClaimError` é exatamente um `ChallengeReason` submissível (C8): o
//! superconjunto de inconsistências de identidade (order_id, commitment, chave
//! não resolvida, derivação, vout fora de range) dobra em `WrongScript`, porque
//! todas significam "o output provado não é o que a identidade da ordem deriva".

use crate::bundle::{CheckpointRegistry, ClaimBundle};
use crate::linkage::{self, CheckpointAnchor, LinkageError};
use crate::order::{self, Address, KeyRegistry, PreimageError, U256, B256};
use crate::pow::PowError;
use crate::reason::ChallengeReason;
use crate::{merkle, pow, verify_txid_internal, H256Internal, TxError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    InvalidOrderParameters,
    ClaimExpired,
    ReclaimPhaseStarted,
    InvalidCheckpointLinkage,
    InclusionHeightExceeded,
    DestinationAmountCapExceeded,
    BadTxEncoding,
    TxidMismatch,
    BadMerklePath,
    WrongScript,
    InsufficientAmount,
    BadHeaderPoW,
    InvalidTarget,
    BrokenLinkage,
    InsufficientDepth,
}

impl ClaimError {
    /// C8: mapeamento total para o catálogo submissível (aqui, identidade).
    pub fn challenge_reason(&self) -> ChallengeReason {
        match self {
            ClaimError::InvalidOrderParameters => ChallengeReason::InvalidOrderParameters,
            ClaimError::ClaimExpired => ChallengeReason::ClaimExpired,
            ClaimError::ReclaimPhaseStarted => ChallengeReason::ReclaimPhaseStarted,
            ClaimError::InvalidCheckpointLinkage => ChallengeReason::InvalidCheckpointLinkage,
            ClaimError::InclusionHeightExceeded => ChallengeReason::InclusionHeightExceeded,
            ClaimError::DestinationAmountCapExceeded => {
                ChallengeReason::DestinationAmountCapExceeded
            }
            ClaimError::BadTxEncoding => ChallengeReason::BadTxEncoding,
            ClaimError::TxidMismatch => ChallengeReason::TxidMismatch,
            ClaimError::BadMerklePath => ChallengeReason::BadMerklePath,
            ClaimError::WrongScript => ChallengeReason::WrongScript,
            ClaimError::InsufficientAmount => ChallengeReason::InsufficientAmount,
            ClaimError::BadHeaderPoW => ChallengeReason::BadHeaderPoW,
            ClaimError::InvalidTarget => ChallengeReason::InvalidTarget,
            ClaimError::BrokenLinkage => ChallengeReason::BrokenLinkage,
            ClaimError::InsufficientDepth => ChallengeReason::InsufficientDepth,
        }
    }
}

impl From<PreimageError> for ClaimError {
    fn from(e: PreimageError) -> Self {
        match e {
            PreimageError::Timeline => ClaimError::InvalidOrderParameters,
            PreimageError::DestinationAmountCapExceeded => ClaimError::DestinationAmountCapExceeded,
        }
    }
}

impl From<TxError> for ClaimError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::BadTxEncoding(_) => ClaimError::BadTxEncoding,
            TxError::TxidMismatch { .. } => ClaimError::TxidMismatch,
        }
    }
}

impl From<LinkageError> for ClaimError {
    fn from(e: LinkageError) -> Self {
        match e {
            LinkageError::Pow(PowError::InvalidTarget) => ClaimError::InvalidTarget,
            LinkageError::Pow(PowError::BadHeaderPoW) => ClaimError::BadHeaderPoW,
            LinkageError::BrokenLinkage { .. } => ClaimError::BrokenLinkage,
            LinkageError::EmptyChain
            | LinkageError::HeightMismatch { .. }
            | LinkageError::TipHashMismatch => ClaimError::InvalidCheckpointLinkage,
        }
    }
}

/// Veredito positivo: o que o contrato otimista libera ao fim da janela.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    pub order_id: B256,
    pub txid_internal: H256Internal,
    pub recipient: Address,
    pub destination_token: Address,
    pub destination_amount: U256,
    pub amount_paid_sat: u64,
    pub block_height: u32,
    pub confirmations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Context {
    pub now_l2: u64,
}

pub fn evaluate_claim_bundle<K, C>(
    bundle: &ClaimBundle,
    keys: &K,
    checkpoints: &C,
    l2: &L2Context,
) -> Result<Settlement, ClaimError>
where
    K: KeyRegistry,
    C: CheckpointRegistry,
{
    // ---- 1. encoding da tx + txid (B1/P4) ----
    // raw_tx é WIRE; verify_txid_internal parseia, descarta witness, re-serializa
    // legacy e exige sha256d(legacy) == txid_internal.
    let tx = verify_txid_internal(&bundle.raw_tx, &bundle.txid_internal)?;

    // ---- 2. âncora: checkpoint aceito + PoW + linkagem (P3/P5/P6/C6) ----
    let preimage = &bundle.order.preimage;
    preimage.validate()?;
    if l2.now_l2 >= preimage.reclaim_after_l2 {
        return Err(ClaimError::ReclaimPhaseStarted);
    }
    if l2.now_l2 > preimage.claim_deadline_l2 {
        return Err(ClaimError::ClaimExpired);
    }
    let cp = checkpoints
        .resolve(&bundle.checkpoint_id)
        .ok_or(ClaimError::InvalidCheckpointLinkage)?;
    if cp.network != preimage.btc_network {
        return Err(ClaimError::InvalidCheckpointLinkage);
    }
    // o checkpoint afirmado no bundle DEVE bater com o registrado/aceito.
    if cp.height != bundle.checkpoint_height || cp.hash != bundle.checkpoint_hash {
        return Err(ClaimError::InvalidCheckpointLinkage);
    }
    let anchor = CheckpointAnchor {
        network: cp.network,
        height: cp.height,
        hash: cp.hash,
        nbits: cp.nbits,
    };
    linkage::verify_header_chain(
        &anchor,
        &bundle.confirmation_headers,
        bundle.claimed_tip_height,
        &bundle.claimed_tip_hash,
    )?;

    // ---- 3. posição + profundidade (P5/C6) ----
    let idx = bundle.tx_block_index as usize;
    if idx >= bundle.confirmation_headers.len() {
        return Err(ClaimError::InvalidCheckpointLinkage);
    }
    let block_height = linkage::block_height(cp.height, bundle.tx_block_index)
        .ok_or(ClaimError::InvalidCheckpointLinkage)?;
    if block_height > preimage.max_btc_inclusion_height {
        return Err(ClaimError::InclusionHeightExceeded);
    }
    let confirmations =
        linkage::confirmations(bundle.confirmation_headers.len() as u32, bundle.tx_block_index);
    if confirmations < bundle.order.preimage.min_confirmations {
        return Err(ClaimError::InsufficientDepth);
    }
    if !checkpoints.contains(cp.network, bundle.claimed_tip_height, &bundle.claimed_tip_hash) {
        return Err(ClaimError::InvalidCheckpointLinkage);
    }

    // ---- 4. inclusão: Merkle contra o header do bloco da tx ----
    let header = pow::parse_header(&bundle.confirmation_headers[idx]);
    merkle::verify_merkle_inclusion(
        &bundle.txid_internal,
        bundle.merkle_proof.tx_index,
        &bundle.merkle_proof.siblings,
        bundle.merkle_proof.total_transactions,
        &header.merkle_root,
    )
    .map_err(|_| ClaimError::BadMerklePath)?;

    // ---- 5. binding: o output paga o endereço da ordem, com valor suficiente ----
    // a) o preimage publicado realmente hasheia no order_id publicado.
    if preimage.order_id() != bundle.order.order_id {
        return Err(ClaimError::WrongScript);
    }
    // b) o commitment publicado é DERIVÁVEL da identidade + chave do solver.
    let (script_pubkey, commitment) =
        order::derive_script_and_commitment(preimage, keys).map_err(|_| ClaimError::WrongScript)?;
    if commitment != bundle.order.btc_script_pubkey_commitment {
        return Err(ClaimError::WrongScript);
    }
    // c) o output[vout] da tx provada tem exatamente esse scriptPubKey.
    let out = tx
        .outputs
        .get(bundle.vout as usize)
        .ok_or(ClaimError::WrongScript)?;
    if out.script_pubkey.as_slice() != script_pubkey.as_slice() {
        return Err(ClaimError::WrongScript);
    }
    // d) o valor pago cobre o exigido pela ordem.
    if out.value_sat < preimage.amount_sat {
        return Err(ClaimError::InsufficientAmount);
    }

    Ok(Settlement {
        order_id: bundle.order.order_id,
        txid_internal: bundle.txid_internal,
        recipient: preimage.recipient,
        destination_token: preimage.destination_token,
        destination_amount: preimage.destination_amount,
        amount_paid_sat: out.value_sat,
        block_height,
        confirmations,
    })
}

#[cfg(test)]
mod unit {
    use super::*;
    use crate::bundle::{
        CheckpointRecord, ClaimBundle, InMemoryCheckpointRegistry, InMemoryKeyRegistry, MerkleProof,
    };
    use crate::order::{BtcNetwork, Order, OrderPreimage, U256};
    use crate::taproot::Xpub;
    use crate::{sha256d, Transaction, TxIn, TxOut, OutPoint};

    #[test]
    fn accepts_bundle_only_when_tip_is_trusted_and_network_matches() {
        let ctx = sample_context();
        let settlement =
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2).unwrap();
        assert_eq!(settlement.block_height, 101);
        assert_eq!(settlement.confirmations, 1);
        assert_eq!(settlement.amount_paid_sat, 75_000);
    }

    #[test]
    fn rejects_checkpoint_from_wrong_network() {
        let mut ctx = sample_context();
        ctx.checkpoints = sample_checkpoints(ctx.tip_hash, BtcNetwork::Mainnet, true);
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::InvalidCheckpointLinkage)
        );
    }

    #[test]
    fn rejects_bundle_past_max_inclusion_height() {
        let mut ctx = sample_context();
        ctx.bundle.order.preimage.max_btc_inclusion_height = 100;
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::InclusionHeightExceeded)
        );
    }

    #[test]
    fn rejects_tip_that_is_not_accepted_checkpoint() {
        let mut ctx = sample_context();
        ctx.checkpoints = sample_checkpoints(ctx.tip_hash, BtcNetwork::Regtest, false);
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::InvalidCheckpointLinkage)
        );
    }

    #[test]
    fn rejects_expired_claim() {
        let mut ctx = sample_context();
        ctx.l2.now_l2 = ctx.bundle.order.preimage.claim_deadline_l2 + 1;
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::ClaimExpired)
        );
    }

    #[test]
    fn rejects_reclaim_phase() {
        let mut ctx = sample_context();
        ctx.l2.now_l2 = ctx.bundle.order.preimage.reclaim_after_l2;
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::ReclaimPhaseStarted)
        );
    }

    #[test]
    fn rejects_destination_amount_above_cap() {
        let mut ctx = sample_context();
        ctx.bundle.order.preimage.max_destination_amount_cap = U256::from_u128(123_455);
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::DestinationAmountCapExceeded)
        );
    }

    #[test]
    fn rejects_invalid_timeline() {
        let mut ctx = sample_context();
        ctx.bundle.order.preimage.claim_deadline_l2 = ctx.bundle.order.preimage.quote_expires_at_l2 - 1;
        assert_eq!(
            evaluate_claim_bundle(&ctx.bundle, &ctx.keys, &ctx.checkpoints, &ctx.l2),
            Err(ClaimError::InvalidOrderParameters)
        );
    }

    struct TestContext {
        bundle: ClaimBundle,
        keys: InMemoryKeyRegistry,
        checkpoints: InMemoryCheckpointRegistry,
        tip_hash: H256Internal,
        l2: L2Context,
    }

    fn sample_context() -> TestContext {
        let mut keys = InMemoryKeyRegistry::new();
        let preimage = sample_preimage();
        let xpub = Xpub {
            public_key: hex33(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
            chain_code: [7u8; 32],
        };
        keys.insert(preimage.solver_btc_key_id, xpub);

        let (script_pubkey, commitment) =
            crate::order::derive_script_and_commitment(&preimage, &keys).unwrap();
        let order = Order {
            order_id: preimage.order_id(),
            preimage,
            btc_script_pubkey_commitment: commitment,
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                prev: OutPoint {
                    txid: [3u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffff_fffe,
            }],
            outputs: vec![TxOut {
                value_sat: 75_000,
                script_pubkey: script_pubkey.to_vec(),
            }],
            witnesses: None,
            lock_time: 0,
        };
        let raw_tx = tx.wire_serialize();
        let txid_internal = tx.txid_internal().0;

        let checkpoint_hash = [9u8; 32];
        let checkpoint_height = 100;
        let checkpoint_nbits = 0x207f_ffff;
        let header = mine_header(checkpoint_hash, txid_internal, checkpoint_nbits);
        let tip_hash = sha256d(&header);
        let bundle = ClaimBundle {
            order,
            txid_internal,
            raw_tx,
            vout: 0,
            merkle_proof: MerkleProof {
                tx_index: 0,
                siblings: vec![],
                total_transactions: 1,
            },
            tx_block_index: 0,
            checkpoint_id: [1u8; 32],
            checkpoint_height,
            checkpoint_hash,
            confirmation_headers: vec![header],
            claimed_tip_height: checkpoint_height + 1,
            claimed_tip_hash: tip_hash,
        };

        let checkpoints = sample_checkpoints(tip_hash, BtcNetwork::Regtest, true);
        TestContext {
            bundle,
            keys,
            checkpoints,
            tip_hash,
            l2: L2Context { now_l2: 15 },
        }
    }

    fn sample_checkpoints(
        tip_hash: H256Internal,
        network: BtcNetwork,
        include_tip: bool,
    ) -> InMemoryCheckpointRegistry {
        let mut checkpoints = InMemoryCheckpointRegistry::new();
        checkpoints.insert(
            [1u8; 32],
            CheckpointRecord {
                network,
                height: 100,
                hash: [9u8; 32],
                nbits: 0x207f_ffff,
            },
        );
        if include_tip {
            checkpoints.insert(
                [2u8; 32],
                CheckpointRecord {
                    network,
                    height: 101,
                    hash: tip_hash,
                    nbits: 0x207f_ffff,
                },
            );
        }
        checkpoints
    }

    fn sample_preimage() -> OrderPreimage {
        OrderPreimage {
            solver: [1u8; 20],
            recipient: [2u8; 20],
            btc_network: BtcNetwork::Regtest,
            solver_btc_key_id: [4u8; 32],
            amount_sat: 50_000,
            destination_token: [5u8; 20],
            destination_amount: U256::from_u128(123_456),
            min_confirmations: 1,
            max_btc_inclusion_height: 1_000,
            quote_expires_at_l2: 10,
            claim_deadline_l2: 20,
            reclaim_after_l2: 30,
            max_destination_amount_cap: U256::from_u128(123_456),
            replay_domain: [6u8; 32],
            nonce: [7u8; 32],
        }
    }

    fn mine_header(prev_block: H256Internal, merkle_root: H256Internal, nbits: u32) -> [u8; 80] {
        let mut header = [0u8; 80];
        header[..4].copy_from_slice(&2i32.to_le_bytes());
        header[4..36].copy_from_slice(&prev_block);
        header[36..68].copy_from_slice(&merkle_root);
        header[68..72].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        header[72..76].copy_from_slice(&nbits.to_le_bytes());
        for nonce in 0..u32::MAX {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            if crate::pow::check_pow_with_expected_nbits(&header, nbits).is_ok() {
                return header;
            }
        }
        panic!("failed to mine test header");
    }

    fn hex33(s: &str) -> [u8; 33] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    }
}
