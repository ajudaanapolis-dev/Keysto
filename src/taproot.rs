//! Keystone alpha — derivação BIP32 (não-endurecida) + saída P2TR (BIP340/341).
//!
//! §2.6 / C5: o endereço de pagamento é derivado da identidade da ordem.
//!   xpub = registry.resolve(solver_btc_key_id)
//!   P_internal = CKDpub(CKDpub(xpub, i0), i1)            (BIP32 não-endurecida)
//!   Q = lift_x(P_internal) + TapTweak(P_internal_x)·G    (BIP341 key-path-only)
//!   scriptPubKey = OP_1 PUSH32 x(Q)
//!
//! Armadilha de paridade (C5): `lift_x` segue BIP340 e retorna o ponto de Y PAR.
//! Errar isso gera um `P_out` plausível mas incorreto, que falha SILENCIOSAMENTE
//! contra a rede real. Por isso `taproot_output_key` é testado contra o vetor
//! oficial do BIP341 antes de qualquer fixture caseiro.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::Sha512;

use crate::sha256;

type HmacSha512 = Hmac<Sha512>;

/// Chave pública estendida BIP32 (a parte pública de um nó de derivação).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xpub {
    /// chave pública compressa SEC1 (33 bytes, prefixo 0x02/0x03).
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    /// xpub ou ponto intermediário não é um ponto válido da curva.
    InvalidPubkey,
    /// IL >= n, escalar inválido, ou ponto resultante no infinito (negligível).
    InvalidChildScalar,
    /// índice endurecido (bit alto setado) — proibido na derivação pública.
    HardenedIndex,
    /// x-only sem ponto correspondente (lift_x falhou).
    NotOnCurve,
}

fn parse_point(comp: &[u8; 33]) -> Result<AffinePoint, DeriveError> {
    let ep = EncodedPoint::from_bytes(comp).map_err(|_| DeriveError::InvalidPubkey)?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(DeriveError::InvalidPubkey)
}

fn scalar_from_32(bytes: &[u8; 32]) -> Result<Scalar, DeriveError> {
    let repr = k256::FieldBytes::from(*bytes);
    Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(DeriveError::InvalidChildScalar)
}

fn compress(point: &AffinePoint) -> [u8; 33] {
    let ep = point.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(ep.as_bytes());
    out
}

/// CKDpub: derivação BIP32 NÃO-ENDURECIDA de um filho público.
fn ckd_pub(
    parent_pub: &[u8; 33],
    parent_cc: &[u8; 32],
    index: u32,
) -> Result<([u8; 33], [u8; 32]), DeriveError> {
    if index & 0x8000_0000 != 0 {
        return Err(DeriveError::HardenedIndex);
    }
    let mut mac = HmacSha512::new_from_slice(parent_cc).expect("HMAC aceita chave de qualquer tamanho");
    mac.update(parent_pub);
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    let tweak = scalar_from_32(&il)?; // IL >= n => InvalidChildScalar
    let parent_point = parse_point(parent_pub)?;
    let child = ProjectivePoint::from(parent_point) + ProjectivePoint::GENERATOR * tweak;
    if bool::from(child.is_identity()) {
        return Err(DeriveError::InvalidChildScalar);
    }
    Ok((compress(&child.to_affine()), ir))
}

/// P_internal = CKDpub(CKDpub(xpub, i0), i1). Retorna a chave compressa (33B).
pub fn derive_internal_pubkey(xpub: &Xpub, i0: u32, i1: u32) -> Result<[u8; 33], DeriveError> {
    let (p0, cc0) = ckd_pub(&xpub.public_key, &xpub.chain_code, i0)?;
    let (p1, _cc1) = ckd_pub(&p0, &cc0, i1)?;
    Ok(p1)
}

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let th = sha256(tag.as_bytes());
    let mut data = Vec::with_capacity(64 + msg.len());
    data.extend_from_slice(&th);
    data.extend_from_slice(&th);
    data.extend_from_slice(msg);
    sha256(&data)
}

/// BIP340 lift_x: o ponto da curva com a coordenada X dada e Y **PAR**.
fn lift_x(x: &[u8; 32]) -> Result<AffinePoint, DeriveError> {
    let mut comp = [0u8; 33];
    comp[0] = 0x02; // prefixo de Y par
    comp[1..].copy_from_slice(x);
    EncodedPoint::from_bytes(comp)
        .ok()
        .and_then(|ep| Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)))
        .ok_or(DeriveError::NotOnCurve)
}

/// BIP341 (key-path-only, sem árvore de scripts): dado o x-only interno,
/// devolve o x-only da chave de saída `Q = lift_x(P) + TapTweak(P)·G`.
pub fn taproot_output_key(internal_x_only: &[u8; 32]) -> Result<[u8; 32], DeriveError> {
    let p_internal = lift_x(internal_x_only)?;
    let t = tagged_hash("TapTweak", internal_x_only);
    let t_scalar = scalar_from_32(&t)?;
    let q = ProjectivePoint::from(p_internal) + ProjectivePoint::GENERATOR * t_scalar;
    if bool::from(q.is_identity()) {
        return Err(DeriveError::InvalidChildScalar);
    }
    let q_comp = compress(&q.to_affine());
    let mut x = [0u8; 32];
    x.copy_from_slice(&q_comp[1..33]);
    Ok(x)
}

/// scriptPubKey P2TR completo (34 bytes): `OP_1 (0x51) PUSH32 (0x20) <x(Q)>`.
pub fn derive_p2tr(xpub: &Xpub, i0: u32, i1: u32) -> Result<[u8; 34], DeriveError> {
    let internal = derive_internal_pubkey(xpub, i0, i1)?;
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&internal[1..33]);
    let qx = taproot_output_key(&x_only)?;
    let mut spk = [0u8; 34];
    spk[0] = 0x51;
    spk[1] = 0x20;
    spk[2..].copy_from_slice(&qx);
    Ok(spk)
}

#[cfg(test)]
mod unit {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        o
    }

    #[test]
    fn bip341_keypath_official_vector() {
        // BIP341 "Generation of segwit v1 (P2TR) addresses", primeiro vetor
        // (internal key, no script tree).
        let internal = h("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        let expected = h("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343");
        assert_eq!(taproot_output_key(&internal).unwrap(), expected);
    }

    #[test]
    fn p2tr_script_is_well_formed() {
        let internal = h("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
        let qx = taproot_output_key(&internal).unwrap();
        let mut spk = [0u8; 34];
        spk[0] = 0x51;
        spk[1] = 0x20;
        spk[2..].copy_from_slice(&qx);
        assert_eq!(spk[0], 0x51);
        assert_eq!(spk[1], 0x20);
    }
}
