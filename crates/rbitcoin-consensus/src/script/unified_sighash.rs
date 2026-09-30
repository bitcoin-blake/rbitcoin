//! Bitcoin Knots unified signature hash (`doc/unified-sighash.md`,
//! `SignatureHashUnified` in `script/interpreter.cpp`, `v29.4.1.knots20260508`).
//!
//! One message for every script type, opted into per signature by
//! [`SIGHASH_UNIFIED`] in the hash type byte, valid from the BLAKE2b fork
//! height. The layout follows BIP341's so the two read side by side; the
//! aggregates are single SHA256 and the result is
//! `TaggedHash("UnifiedSighash", message)`.

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{Transaction, TxOut};

/// Hash type bit that selects this algorithm.
pub const SIGHASH_UNIFIED: u8 = 0x20;
const SIGHASH_ANYONECANPAY: u8 = 0x80;
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_NONE: u8 = 0x02;
const SIGHASH_SINGLE: u8 = 0x03;

/// The script type byte: domain separation between the four spend kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnifiedScriptType {
    /// Bare or P2SH (legacy `scriptCode`, with the signature removed).
    Base = 0,
    /// Segwit v0 (BIP143 `scriptCode`).
    WitnessV0 = 1,
    /// Taproot key path.
    Taproot = 2,
    /// Tapscript leaf.
    Tapscript = 3,
}

/// Per-transaction single-SHA256 aggregates, computed once and shared by every
/// input (what keeps the algorithm linear in the number of inputs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAggregates {
    prevouts: [u8; 32],
    amounts: [u8; 32],
    scripts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

impl UnifiedAggregates {
    /// `spent` is the output each input spends, in input order.
    pub fn compute(tx: &Transaction, spent: &[TxOut]) -> Self {
        let mut prevouts = sha256::Hash::engine();
        let mut amounts = sha256::Hash::engine();
        let mut scripts = sha256::Hash::engine();
        let mut sequences = sha256::Hash::engine();
        let mut outputs = sha256::Hash::engine();
        for input in &tx.input {
            encode(&input.previous_output, &mut prevouts);
            encode(&input.sequence, &mut sequences);
        }
        for out in spent {
            amounts.input(&out.value.to_sat().to_le_bytes());
            encode(&out.script_pubkey, &mut scripts);
        }
        for out in &tx.output {
            encode(out, &mut outputs);
        }
        Self {
            prevouts: sha256::Hash::from_engine(prevouts).to_byte_array(),
            amounts: sha256::Hash::from_engine(amounts).to_byte_array(),
            scripts: sha256::Hash::from_engine(scripts).to_byte_array(),
            sequences: sha256::Hash::from_engine(sequences).to_byte_array(),
            outputs: sha256::Hash::from_engine(outputs).to_byte_array(),
        }
    }
}

/// What the interpreter supplies for a taproot or tapscript spend; none of it
/// is in the transaction.
#[derive(Clone, Copy, Debug)]
pub struct TaprootContext<'a> {
    /// The witness annex, without its leading tag stripped.
    pub annex: Option<&'a [u8]>,
    /// Tapscript only: the tapleaf hash and the position of the last executed
    /// `OP_CODESEPARATOR` (`0xffff_ffff` for none).
    pub leaf: Option<([u8; 32], u32)>,
}

fn encode<T: Encodable>(v: &T, eng: &mut sha256::HashEngine) {
    v.consensus_encode(eng).expect("engines don't error");
}

fn tagged_engine() -> sha256::HashEngine {
    let tag = sha256::Hash::hash(b"UnifiedSighash");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng
}

/// The unified message for `input_index`, or `None` where Knots'
/// `SignatureHashUnified` returns false: the opt-in bit is clear, a taproot hash
/// type BIP341 does not define, `SIGHASH_SINGLE` with no output at the index,
/// or missing taproot context.
///
/// `script_code` is what the legacy rules already use for the script type
/// (ignored for taproot and tapscript).
#[allow(clippy::too_many_arguments)] // the parameters of Knots' `SignatureHashUnified`
pub fn unified_sighash(
    tx: &Transaction,
    spent: &[TxOut],
    input_index: usize,
    hash_type: u8,
    script_type: UnifiedScriptType,
    script_code: &[u8],
    taproot: Option<&TaprootContext<'_>>,
    agg: &UnifiedAggregates,
) -> Option<[u8; 32]> {
    if hash_type & SIGHASH_UNIFIED == 0 || input_index >= tx.input.len() {
        return None;
    }
    let is_taproot = matches!(
        script_type,
        UnifiedScriptType::Taproot | UnifiedScriptType::Tapscript
    );
    let output_type = hash_type & 0x1f;
    if is_taproot {
        if hash_type & !(0x1f | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED) != 0 {
            return None;
        }
        if !matches!(output_type, SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE) {
            return None;
        }
    }
    let taproot = if is_taproot { Some(taproot?) } else { None };
    let anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;

    let mut ss = tagged_engine();
    ss.input(&[0u8]); // epoch
    ss.input(&[hash_type]);
    encode(&tx.version, &mut ss);
    encode(&tx.lock_time, &mut ss);
    ss.input(&[0u8]); // locktime is five bytes here
    if !anyonecanpay {
        ss.input(&agg.prevouts);
        ss.input(&agg.amounts);
        ss.input(&agg.scripts);
        ss.input(&agg.sequences);
    }
    if output_type != SIGHASH_NONE && output_type != SIGHASH_SINGLE {
        ss.input(&agg.outputs);
    }
    ss.input(&[script_type as u8]);
    if anyonecanpay {
        let input = &tx.input[input_index];
        encode(&input.previous_output, &mut ss);
        encode(spent.get(input_index)?, &mut ss);
        encode(&input.sequence, &mut ss);
    } else {
        ss.input(&(input_index as u32).to_le_bytes());
    }
    match taproot {
        None => encode(
            &bitcoin::ScriptBuf::from_bytes(script_code.to_vec()),
            &mut ss,
        ),
        Some(ctx) => match ctx.annex {
            Some(annex) => {
                ss.input(&[1u8]);
                let mut a = sha256::Hash::engine();
                encode(&annex.to_vec(), &mut a);
                ss.input(sha256::Hash::from_engine(a).as_byte_array());
            }
            None => ss.input(&[0u8]),
        },
    }
    if output_type == SIGHASH_SINGLE {
        let out = tx.output.get(input_index)?;
        let mut single = sha256::Hash::engine();
        encode(out, &mut single);
        ss.input(sha256::Hash::from_engine(single).as_byte_array());
    }
    if script_type == UnifiedScriptType::Tapscript {
        let (leaf, codesep) = taproot?.leaf?;
        ss.input(&leaf);
        ss.input(&[0u8]); // key version
        ss.input(&codesep.to_le_bytes());
    }
    Some(sha256::Hash::from_engine(ss).to_byte_array())
}

/// The implied P2PKH `scriptCode` of a P2WPKH program (BIP143), for script type 1.
pub fn p2wpkh_script_code(keyhash: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(25);
    v.extend_from_slice(&[0x76, 0xa9, 0x14]);
    v.extend_from_slice(keyhash);
    v.extend_from_slice(&[0x88, 0xac]);
    v
}

#[cfg(test)]
mod knots_vectors {
    use super::*;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::TapLeafHash;

    /// Bitcoin Knots `src/test/data/unified_sighash.json` (MIT): scriptCode,
    /// rawTx, inIdx, hashType, scriptType, spentOutputs, sighash (raw order).
    const JSON: &str = include_str!("knots_unified_sighash.json");

    #[test]
    fn all_166_knots_vectors_match() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(JSON).unwrap();
        let mut n = 0;
        let mut by_type = [0usize; 4];
        for row in rows.iter().skip(1) {
            let script_code = rbitcoin_primitives::hex_decode(row[0].as_str().unwrap()).unwrap();
            let raw = rbitcoin_primitives::hex_decode(row[1].as_str().unwrap()).unwrap();
            let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
            let idx = row[2].as_u64().unwrap() as usize;
            let hash_type = row[3].as_u64().unwrap() as u8;
            let script_type = match row[4].as_u64().unwrap() {
                0 => UnifiedScriptType::Base,
                1 => UnifiedScriptType::WitnessV0,
                2 => UnifiedScriptType::Taproot,
                3 => UnifiedScriptType::Tapscript,
                t => panic!("script type {t}"),
            };
            let spent: Vec<TxOut> = row[5]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| TxOut {
                    value: bitcoin::Amount::from_sat(o[0].as_u64().unwrap()),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(
                        rbitcoin_primitives::hex_decode(o[1].as_str().unwrap()).unwrap(),
                    ),
                })
                .collect();
            let want = rbitcoin_primitives::hex_decode(row[6].as_str().unwrap()).unwrap();
            let agg = UnifiedAggregates::compute(&tx, &spent);
            let leaf = TapLeafHash::from_script(
                bitcoin::Script::from_bytes(&script_code),
                LeafVersion::TapScript,
            )
            .to_byte_array();
            let ctx = TaprootContext {
                annex: None,
                leaf: (script_type == UnifiedScriptType::Tapscript).then_some((leaf, 0xffff_ffff)),
            };
            let got = unified_sighash(
                &tx,
                &spent,
                idx,
                hash_type,
                script_type,
                &script_code,
                Some(&ctx),
                &agg,
            )
            .unwrap_or_else(|| {
                panic!("vector {n} (type {script_type:?}, hash type {hash_type:#x}) refused")
            });
            assert_eq!(got.as_slice(), want.as_slice(), "vector {n}");
            by_type[script_type as usize] += 1;
            n += 1;
        }
        assert_eq!(n, 166);
        assert_eq!(by_type, [76, 66, 12, 12]);
    }

    #[test]
    fn refusals_follow_knots() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(JSON).unwrap();
        let row = &rows[1];
        let raw = rbitcoin_primitives::hex_decode(row[1].as_str().unwrap()).unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let spent: Vec<TxOut> = row[5]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| TxOut {
                value: bitcoin::Amount::from_sat(o[0].as_u64().unwrap()),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(
                    rbitcoin_primitives::hex_decode(o[1].as_str().unwrap()).unwrap(),
                ),
            })
            .collect();
        let agg = UnifiedAggregates::compute(&tx, &spent);
        let ctx = TaprootContext {
            annex: None,
            leaf: None,
        };
        let run = |hash_type: u8, script_type: UnifiedScriptType, idx: usize| {
            unified_sighash(
                &tx,
                &spent,
                idx,
                hash_type,
                script_type,
                b"",
                Some(&ctx),
                &agg,
            )
        };
        // The bit is what selects this message.
        assert!(run(0x01, UnifiedScriptType::Base, 0).is_none());
        // Taproot refuses bytes BIP341 does not define; base takes any byte.
        assert!(run(0x24, UnifiedScriptType::Taproot, 0).is_none());
        assert!(run(0x20, UnifiedScriptType::Taproot, 0).is_none());
        assert!(run(0x60, UnifiedScriptType::Taproot, 0).is_none());
        assert!(run(0x24, UnifiedScriptType::Base, 0).is_some());
        assert!(run(0x20, UnifiedScriptType::Base, 0).is_some());
        // SINGLE with no output at the index is invalid, unlike the legacy ONE.
        let n_out = tx.output.len();
        assert!(
            tx.input.len() > n_out,
            "fixture has more inputs than outputs"
        );
        assert!(run(0x23, UnifiedScriptType::Base, n_out).is_none());
        assert!(run(0x21, UnifiedScriptType::Base, n_out).is_some());
        // Tapscript needs its leaf; taproot needs its context.
        assert!(run(0x21, UnifiedScriptType::Tapscript, 0).is_none());
        assert!(unified_sighash(
            &tx,
            &spent,
            0,
            0x21,
            UnifiedScriptType::Taproot,
            b"",
            None,
            &agg
        )
        .is_none());
    }
}

#[cfg(test)]
mod testnet4_spends {
    use super::*;
    use crate::block::{ScriptCheckJob, ScriptVerifyFlags};
    use crate::ConsensusError;

    /// `btc:testnet4-blake2b` 150,328: a taproot key-path spend signed
    /// `SIGHASH_ALL | SIGHASH_UNIFIED` (witness signature ends in `0x21`).
    const P2TR_TX: &str = "0200000000010139382bdedc269f5619b355c3a1a35fd0eaf5e2cdbb519d2a464315847c30743e0100000000feffffff02fbed00000000000022512042cbbc48095e40a27a7435c5f00de131097d8136ad297e7a09daa51da0805cef60770200000000002251209ef54bd84baced5d1fc48174699893f7576bcdd68872ae75abe906111e3ae1d50141c33ca18f7e478ca7270cd32c2456174bbde31d30f1b13e5376d7f27b1907a0188e4e990ab190dec6f763651ee1f297b2708860ba409b778d477f0addbb7eea74213f4b0200";
    const P2TR_PREV: (u64, &str) = (
        227_565,
        "5120c54bc3c5a67e1cf0096dc52fbe54bbc24b1858bb83da43e0c539953d6d355675",
    );
    /// `btc:testnet4-blake2b` 150,376: a P2PKH spend, same hash type.
    const P2PKH_TX: &str = "02000000011d22f4c9fbefc73c8ada5d0adb3b4b8cce2f42743a3898c7835ddbd473904ea4000000006a47304402203a4b56fd48297f998cdceb89b749fa4ea1d297bdac69c6ab9fa1f3aec24fe8d2022071d540a5a96deac0c17460be498d01da9f7c3b069979e0f634da30bb0c3cd2b2212103f12c2e417a1d01f80053a4c9f507646f014b05e2b29df353d5648ddcda4e90aeffffffff018db71300000000001976a914307719088bf8c0d04ecad7a8d0b3b33f4166151588ac00000000";
    const P2PKH_PREV: (u64, &str) = (
        1_292_364,
        "76a914cf7ef7831da1f883f3baab4126926c96c915b1f288ac",
    );

    fn job(tx_hex: &str, prev: (u64, &str), unified: bool) -> ScriptCheckJob {
        let tx: Transaction =
            bitcoin::consensus::deserialize(&rbitcoin_primitives::hex_decode(tx_hex).unwrap())
                .unwrap();
        let prevout = TxOut {
            value: bitcoin::Amount::from_sat(prev.0),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(
                rbitcoin_primitives::hex_decode(prev.1).unwrap(),
            ),
        };
        let mut flags = ScriptVerifyFlags::buried(true, true, true, true, true);
        flags.unified_sighash = unified;
        ScriptCheckJob::new(vec![prevout], tx, flags)
    }

    #[test]
    fn real_opted_in_spends_verify_only_under_the_fork() {
        for (name, tx, prev) in [
            ("p2tr", P2TR_TX, P2TR_PREV),
            ("p2pkh", P2PKH_TX, P2PKH_PREV),
        ] {
            crate::script::verify_job_all_inputs(&job(tx, prev, true))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let err = crate::script::verify_job_all_inputs(&job(tx, prev, false)).unwrap_err();
            assert!(
                matches!(&err, ConsensusError::Script(m) if m.contains("sighash type") || m.contains("ecdsa")),
                "{name} without the flag reads the byte under the legacy rules: {err}"
            );
        }
    }
}
