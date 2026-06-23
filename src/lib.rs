//! Keystone alpha — Bitcoin transaction parsing + `txid_internal` verification.
//!
//! raw_tx no bundle = forma WIRE (BIP144). O verificador faz o strip da witness,
//! re-serializa legacy e calcula txid_internal = sha256d(legacy). O txid_internal
//! afirmado é um commitment VERIFICADO, nunca confiado (mismatch => TxidMismatch).
//! Hashes em ordem INTERNA; o "txid" de explorador é o reverso.

use sha2::{Digest, Sha256};

pub mod bundle;
pub mod evaluate;
pub mod linkage;
pub mod merkle;
pub mod order;
pub mod pow;
pub mod reason;
pub mod taproot;

pub use evaluate::{evaluate_claim_bundle, ClaimError, L2Context, Settlement};
pub use reason::ChallengeReason;

/// 32-byte hash in **internal** (non-reversed) byte order.
pub type H256Internal = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Txid(pub H256Internal);

impl Txid {
    pub fn to_display_hex(&self) -> String {
        let mut b = self.0;
        b.reverse();
        hex_encode(&b)
    }
    pub fn to_internal_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    BadTxEncoding(&'static str),
    TxidMismatch { expected: H256Internal, got: H256Internal },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: H256Internal,
    pub vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub prev: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

pub type Witness = Vec<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub witnesses: Option<Vec<Witness>>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn is_segwit(&self) -> bool {
        self.witnesses.is_some()
    }

    pub fn legacy_serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(256);
        o.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut o, self.inputs.len() as u64);
        for i in &self.inputs {
            o.extend_from_slice(&i.prev.txid);
            o.extend_from_slice(&i.prev.vout.to_le_bytes());
            write_varint(&mut o, i.script_sig.len() as u64);
            o.extend_from_slice(&i.script_sig);
            o.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut o, self.outputs.len() as u64);
        for ot in &self.outputs {
            o.extend_from_slice(&ot.value_sat.to_le_bytes());
            write_varint(&mut o, ot.script_pubkey.len() as u64);
            o.extend_from_slice(&ot.script_pubkey);
        }
        o.extend_from_slice(&self.lock_time.to_le_bytes());
        o
    }

    pub fn wire_serialize(&self) -> Vec<u8> {
        let Some(wits) = &self.witnesses else {
            return self.legacy_serialize();
        };
        let mut o = Vec::with_capacity(512);
        o.extend_from_slice(&self.version.to_le_bytes());
        o.push(0x00);
        o.push(0x01);
        write_varint(&mut o, self.inputs.len() as u64);
        for i in &self.inputs {
            o.extend_from_slice(&i.prev.txid);
            o.extend_from_slice(&i.prev.vout.to_le_bytes());
            write_varint(&mut o, i.script_sig.len() as u64);
            o.extend_from_slice(&i.script_sig);
            o.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut o, self.outputs.len() as u64);
        for ot in &self.outputs {
            o.extend_from_slice(&ot.value_sat.to_le_bytes());
            write_varint(&mut o, ot.script_pubkey.len() as u64);
            o.extend_from_slice(&ot.script_pubkey);
        }
        for w in wits {
            write_varint(&mut o, w.len() as u64);
            for item in w {
                write_varint(&mut o, item.len() as u64);
                o.extend_from_slice(item);
            }
        }
        o.extend_from_slice(&self.lock_time.to_le_bytes());
        o
    }

    pub fn txid_internal(&self) -> Txid {
        Txid(sha256d(&self.legacy_serialize()))
    }

    pub fn wtxid_internal(&self) -> Txid {
        Txid(sha256d(&self.wire_serialize()))
    }
}

const MAX_TX_BYTES: u64 = 4_200_000;
const MAX_INPUTS: u64 = 100_000;
const MAX_OUTPUTS: u64 = 100_000;
const MAX_WITNESS_ITEMS: u64 = 100_000;

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, p: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        if self.remaining() < n {
            return Err(TxError::BadTxEncoding("unexpected end of input"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, TxError> {
        Ok(self.take(1)?[0])
    }
    fn peek_u8(&self) -> Result<u8, TxError> {
        self.b
            .get(self.p)
            .copied()
            .ok_or(TxError::BadTxEncoding("unexpected end of input"))
    }
    fn u32_le(&mut self) -> Result<u32, TxError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i32_le(&mut self) -> Result<i32, TxError> {
        Ok(self.u32_le()? as i32)
    }
    fn u64_le(&mut self) -> Result<u64, TxError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn varint(&mut self) -> Result<u64, TxError> {
        let first = self.u8()?;
        let v = match first {
            0xff => {
                let s = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                let v = u64::from_le_bytes(a);
                if v <= 0xffff_ffff {
                    return Err(TxError::BadTxEncoding("non-minimal varint (0xff)"));
                }
                v
            }
            0xfe => {
                let s = self.take(4)?;
                let v = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64;
                if v <= 0xffff {
                    return Err(TxError::BadTxEncoding("non-minimal varint (0xfe)"));
                }
                v
            }
            0xfd => {
                let s = self.take(2)?;
                let v = u16::from_le_bytes([s[0], s[1]]) as u64;
                if v < 0xfd {
                    return Err(TxError::BadTxEncoding("non-minimal varint (0xfd)"));
                }
                v
            }
            n => n as u64,
        };
        Ok(v)
    }
    fn var_bytes(&mut self) -> Result<Vec<u8>, TxError> {
        let n = self.varint()?;
        if n > MAX_TX_BYTES {
            return Err(TxError::BadTxEncoding("var_bytes length too large"));
        }
        Ok(self.take(n as usize)?.to_vec())
    }
}

pub fn parse_tx(raw: &[u8]) -> Result<Transaction, TxError> {
    if raw.len() as u64 > MAX_TX_BYTES {
        return Err(TxError::BadTxEncoding("tx too large"));
    }
    let mut c = Cursor::new(raw);
    let version = c.i32_le()?;

    let mut segwit = false;
    if c.peek_u8()? == 0x00 {
        let _marker = c.u8()?;
        let flag = c.u8()?;
        if flag != 0x01 {
            return Err(TxError::BadTxEncoding("segwit flag must be 0x01"));
        }
        segwit = true;
    }

    let n_in = c.varint()?;
    if n_in == 0 {
        return Err(TxError::BadTxEncoding("zero inputs"));
    }
    if n_in > MAX_INPUTS {
        return Err(TxError::BadTxEncoding("input count too large"));
    }
    let mut inputs = Vec::with_capacity(n_in.min(4096) as usize);
    for _ in 0..n_in {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(c.take(32)?);
        let vout = c.u32_le()?;
        let script_sig = c.var_bytes()?;
        let sequence = c.u32_le()?;
        inputs.push(TxIn {
            prev: OutPoint { txid, vout },
            script_sig,
            sequence,
        });
    }

    let n_out = c.varint()?;
    if n_out == 0 {
        return Err(TxError::BadTxEncoding("zero outputs"));
    }
    if n_out > MAX_OUTPUTS {
        return Err(TxError::BadTxEncoding("output count too large"));
    }
    let mut outputs = Vec::with_capacity(n_out.min(4096) as usize);
    for _ in 0..n_out {
        let value_sat = c.u64_le()?;
        let script_pubkey = c.var_bytes()?;
        outputs.push(TxOut {
            value_sat,
            script_pubkey,
        });
    }

    let witnesses = if segwit {
        let mut all = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            let items = c.varint()?;
            if items > MAX_WITNESS_ITEMS {
                return Err(TxError::BadTxEncoding("witness item count too large"));
            }
            let mut stack = Vec::with_capacity(items.min(1024) as usize);
            for _ in 0..items {
                stack.push(c.var_bytes()?);
            }
            all.push(stack);
        }
        if all.iter().all(|w| w.is_empty()) {
            return Err(TxError::BadTxEncoding("segwit tx with no witness data"));
        }
        Some(all)
    } else {
        None
    };

    let lock_time = c.u32_le()?;

    if c.remaining() != 0 {
        return Err(TxError::BadTxEncoding("trailing bytes after locktime"));
    }

    Ok(Transaction {
        version,
        inputs,
        outputs,
        witnesses,
        lock_time,
    })
}

pub fn verify_txid_internal(
    raw_tx: &[u8],
    claimed_txid_internal: &H256Internal,
) -> Result<Transaction, TxError> {
    let tx = parse_tx(raw_tx)?;
    let got = tx.txid_internal().0;
    if &got != claimed_txid_internal {
        return Err(TxError::TxidMismatch {
            expected: *claimed_txid_internal,
            got,
        });
    }
    Ok(tx)
}

pub fn sha256d(data: &[u8]) -> H256Internal {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// SHA-256 simples (tagged hashes BIP340/341, índices de derivação).
pub fn sha256(data: &[u8]) -> H256Internal {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// keccak256 (Ethereum) — usado nos hashes de identidade da ordem (P1).
pub fn keccak256(data: &[u8]) -> H256Internal {
    use sha3::{Digest as _, Keccak256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

fn write_varint(o: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        o.push(n as u8);
    } else if n <= 0xffff {
        o.push(0xfd);
        o.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        o.push(0xfe);
        o.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        o.push(0xff);
        o.extend_from_slice(&n.to_le_bytes());
    }
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
