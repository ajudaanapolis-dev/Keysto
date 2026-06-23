//! Keystone alpha — catálogo de ChallengeReason (Parte D do patch v1.1.1).
//!
//! C8: todo bundle rejeitado por `evaluate_claim_bundle` mapeia para >= 1
//! ChallengeReason submissível. O verificador de referência usa exatamente este
//! conjunto como seus modos de falha (o oráculo e o catálogo on-chain coincidem),
//! então o mapeamento é a identidade — nenhuma rejeição "cai fora" do catálogo.
//!
//! `InvalidBundleHash` NÃO está aqui (P9): não é fraude, é a precondição
//! `keccak256(claimBundle) == storedBundleHash` checada antes da adjudicação (P2).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeReason {
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
    InvalidTarget, // P3: header.nBits != esperado
    BrokenLinkage,
    InsufficientDepth,
    // v1-beta (fora do escopo do PR 1):
    // InvalidRetarget,
    // HeavierReorgConflict,
}

impl ChallengeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeReason::InvalidOrderParameters => "InvalidOrderParameters",
            ChallengeReason::ClaimExpired => "ClaimExpired",
            ChallengeReason::ReclaimPhaseStarted => "ReclaimPhaseStarted",
            ChallengeReason::InvalidCheckpointLinkage => "InvalidCheckpointLinkage",
            ChallengeReason::InclusionHeightExceeded => "InclusionHeightExceeded",
            ChallengeReason::DestinationAmountCapExceeded => "DestinationAmountCapExceeded",
            ChallengeReason::BadTxEncoding => "BadTxEncoding",
            ChallengeReason::TxidMismatch => "TxidMismatch",
            ChallengeReason::BadMerklePath => "BadMerklePath",
            ChallengeReason::WrongScript => "WrongScript",
            ChallengeReason::InsufficientAmount => "InsufficientAmount",
            ChallengeReason::BadHeaderPoW => "BadHeaderPoW",
            ChallengeReason::InvalidTarget => "InvalidTarget",
            ChallengeReason::BrokenLinkage => "BrokenLinkage",
            ChallengeReason::InsufficientDepth => "InsufficientDepth",
        }
    }

    /// Catálogo completo, na ordem de adjudicação determinística (= ordem de
    /// avaliação de `evaluate_claim_bundle`). Útil para testes de exaustividade.
    pub const ALL: [ChallengeReason; 15] = [
        ChallengeReason::BadTxEncoding,
        ChallengeReason::TxidMismatch,
        ChallengeReason::InvalidOrderParameters,
        ChallengeReason::ClaimExpired,
        ChallengeReason::ReclaimPhaseStarted,
        ChallengeReason::InvalidTarget,
        ChallengeReason::BadHeaderPoW,
        ChallengeReason::BrokenLinkage,
        ChallengeReason::InvalidCheckpointLinkage,
        ChallengeReason::InclusionHeightExceeded,
        ChallengeReason::DestinationAmountCapExceeded,
        ChallengeReason::InsufficientDepth,
        ChallengeReason::BadMerklePath,
        ChallengeReason::WrongScript,
        ChallengeReason::InsufficientAmount,
    ];
}
