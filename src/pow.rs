//! Keystone alpha — Bitcoin block header parsing + proof-of-work check.
//!
//! P3: no alpha (período de dificuldade único) NÃO se confia no `nBits` do header.
//! O target esperado é o do checkpoint; cada header DEVE declarar exatamente esse
//! `nBits` (senão `InvalidTarget`) e seu hash DEVE bater contra esse alvo
//! (senão `BadHeaderPoW`). Assim um header com dificuldade relaxada não passa.
//!
//! Toda comparação de PoW é feita sobre o hash interpretado como inteiro
//! LITTLE-ENDIAN (convenção Bitcoin), comparado contra o target em big-endian.

use crate::{sha256d, H256Internal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowError {
    /// header.nBits != esperado, ou compact malformado (negativo/overflow/zero).
    InvalidTarget,
    /// hash do header > target.
    BadHeaderPoW,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: i32,
    pub prev_block: H256Internal,
    pub merkle_root: H256Internal,
    pub time: u32,
    pub nbits: u32,
    pub nonce: u32,
}

/// Header é sempre 80 bytes; parsing é total e infalível sobre `[u8; 80]`.
pub fn parse_header(bytes: &[u8; 80]) -> Header {
    let mut prev_block = [0u8; 32];
    prev_block.copy_from_slice(&bytes[4..36]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&bytes[36..68]);
    Header {
        version: i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        prev_block,
        merkle_root,
        time: u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
        nbits: u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]),
        nonce: u32::from_le_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]),
    }
}

/// block hash em ordem INTERNA (não reversa). O campo `prev_block` do header
/// seguinte é exatamente este valor.
pub fn block_hash(bytes: &[u8; 80]) -> H256Internal {
    sha256d(bytes)
}

/// Expande o compact `nBits` para um target de 256 bits em **big-endian**.
/// Rejeita compact negativo (bit 0x00800000), mantissa zero e overflow.
pub fn target_from_nbits(nbits: u32) -> Result<[u8; 32], PowError> {
    if nbits & 0x0080_0000 != 0 {
        return Err(PowError::InvalidTarget); // negativo: proibido
    }
    let exp = (nbits >> 24) as usize;
    let mant = nbits & 0x007f_ffff;
    if mant == 0 {
        return Err(PowError::InvalidTarget);
    }

    let mut target = [0u8; 32];
    if exp <= 3 {
        let shift = 8 * (3 - exp) as u32;
        let m = mant >> shift;
        target[29] = (m >> 16) as u8;
        target[30] = (m >> 8) as u8;
        target[31] = m as u8;
    } else {
        if exp > 32 {
            return Err(PowError::InvalidTarget);
        }
        let pos = 32 - exp; // índice (BE) do byte mais significativo da mantissa
        if pos + 3 > 32 {
            return Err(PowError::InvalidTarget); // mantissa ultrapassaria 256 bits
        }
        target[pos] = (mant >> 16) as u8;
        target[pos + 1] = (mant >> 8) as u8;
        target[pos + 2] = mant as u8;
    }
    Ok(target)
}

/// P3: valida PoW exigindo `nBits` exatamente igual ao esperado (checkpoint).
pub fn check_pow_with_expected_nbits(
    header_bytes: &[u8; 80],
    expected_nbits: u32,
) -> Result<(), PowError> {
    let header = parse_header(header_bytes);
    if header.nbits != expected_nbits {
        return Err(PowError::InvalidTarget);
    }
    let target = target_from_nbits(expected_nbits)?;
    // hash como inteiro little-endian -> big-endian para comparar com target.
    let mut be = sha256d(header_bytes);
    be.reverse();
    if greater_than(&be, &target) {
        return Err(PowError::BadHeaderPoW);
    }
    Ok(())
}

/// `a > b` para inteiros de 256 bits em big-endian.
fn greater_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    false
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn genesis_target_matches_known_value() {
        // nBits 0x1d00ffff => 0x00000000FFFF0000...0000
        let t = target_from_nbits(0x1d00_ffff).unwrap();
        let mut expected = [0u8; 32];
        expected[4] = 0xff;
        expected[5] = 0xff;
        assert_eq!(t, expected);
    }

    #[test]
    fn negative_compact_rejected() {
        assert_eq!(target_from_nbits(0x1d80_0000), Err(PowError::InvalidTarget));
    }

    #[test]
    fn regtest_target_is_near_max() {
        // regtest powLimit: 0x207fffff
        let t = target_from_nbits(0x207f_ffff).unwrap();
        assert_eq!(t[0], 0x7f);
        assert_eq!(t[1], 0xff);
        assert_eq!(t[2], 0xff);
    }

    #[test]
    fn wrong_nbits_is_invalid_target() {
        // header declarando nBits != esperado falha como InvalidTarget,
        // mesmo que o PoW bata contra algum outro alvo.
        let mut hb = [0u8; 80];
        hb[72..76].copy_from_slice(&0x1d00_ffffu32.to_le_bytes());
        assert_eq!(
            check_pow_with_expected_nbits(&hb, 0x207f_ffff),
            Err(PowError::InvalidTarget)
        );
    }
}
