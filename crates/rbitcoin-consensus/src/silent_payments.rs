//! BIP-352 Silent Payments **tweak server** (scan-side `A_tweak` only).
//!
//! libsecp256k1 has a `silentpayments` C module; rust-secp256k1 0.29 (bitcoin
//! 0.32) does not bind it. This module uses `PublicKey::combine_keys` +
//! `mul_tweak` plus script extract. Tweak *index* never stores a scan key.
//! Frigate `blockchain.silentpayments.subscribe` may pass a scan private key
//! in RAM for the session only.

use bitcoin::hashes::{hash160, sha256, Hash, HashEngine};
use bitcoin::key::{Parity, XOnlyPublicKey};
use bitcoin::script::{Instruction, Script};
use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{OutPoint, Transaction, TxOut, Witness};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::Query;
use rbitcoin_store::{IndexWindow, InputRecord, LoadedTweakTx, OutputRecord, StoreError};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use crate::error::ConsensusError;
use crate::params::ChainParams;

/// BIP341 NUMS internal key *H* (SHA256 of uncompressed *G* as x-only).
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// One Taproot output listed for Electrum tweaks `output_pubkeys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootOut {
    pub vout: u32,
    pub xonly: [u8; 32],
    pub value: u64,
}

/// Server tweak plus Taproot outs for one eligible tx.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxTweak {
    /// `input_hash · ΣA` — 33-byte compressed.
    pub tweak: [u8; 33],
    pub output_pubkeys: Vec<TaprootOut>,
}

fn secp() -> &'static Secp256k1<All> {
    static S: OnceLock<Secp256k1<All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

/// Compute the BIP-352 server tweak for `tx` given prevout scripts.
///
/// `prevouts.len()` must equal `tx.input.len()`. Returns `None` if the tx is
/// not silent-payment eligible (or the pubkey sum is infinity / invalid hash).
pub fn tweak_from_tx(tx: &Transaction, prevouts: &[TxOut]) -> Option<TxTweak> {
    if tx.input.len() != prevouts.len() {
        return None;
    }
    let output_pubkeys = taproot_outs(tx);
    if output_pubkeys.is_empty() {
        return None;
    }
    if prevouts
        .iter()
        .any(|p| witness_version(p.script_pubkey.as_bytes()) > Some(1))
    {
        return None;
    }

    let mut keys = Vec::new();
    for (vin, prev) in tx.input.iter().zip(prevouts.iter()) {
        if let Some(pk) = extract_input_pubkey(
            prev.script_pubkey.as_script(),
            vin.script_sig.as_script(),
            &vin.witness,
        ) {
            keys.push(pk);
        }
    }
    if keys.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let a = PublicKey::combine_keys(&refs).ok()?;
    let tweak = input_hash_mul_a(tx, &a)?;
    Some(TxTweak {
        tweak,
        output_pubkeys,
    })
}

/// Prefer the thin index (no parent peeks). Hole / no table → [`tweaks_for_height`].
pub fn tweaks_at_height(
    query: &Query,
    params: &ChainParams,
    height: Height,
) -> Result<BTreeMap<[u8; 32], TxTweak>, ConsensusError> {
    if !params.taproot_active_at(height.0) {
        return Ok(BTreeMap::new());
    }
    match query.load_thin_tweaks(height) {
        Ok(Some(rows)) => {
            let mut out = BTreeMap::new();
            for r in rows {
                out.insert(
                    r.txid,
                    TxTweak {
                        tweak: r.tweak,
                        output_pubkeys: r
                            .p2tr
                            .into_iter()
                            .map(|(vout, xonly, value)| TaprootOut { vout, xonly, value })
                            .collect(),
                    },
                );
            }
            return Ok(out);
        }
        Ok(None) => {
            rbitcoin_log::debug!(
                "sp_tweaks: naive fallback h={} (hole or index off)",
                height.0
            );
        }
        Err(e) => return Err(e.into()),
    }
    tweaks_for_height(query, params, height)
}

/// Confirmed height → eligible txid (internal order) → tweak.
///
/// Pre-Taproot and missing heights return an empty map (no error). Does not
/// reconstruct a wire block. Walks packed bodies **and parent outs**.
pub fn tweaks_for_height(
    query: &Query,
    params: &ChainParams,
    height: Height,
) -> Result<BTreeMap<[u8; 32], TxTweak>, ConsensusError> {
    query.require_sp_tweaks_unpruned()?;
    if !params.taproot_active_at(height.0) {
        return Ok(BTreeMap::new());
    }
    let fks = match query.block_tx_fks(height) {
        Ok(f) => f,
        Err(StoreError::NotFound) => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    if fks.is_empty() {
        return Ok(BTreeMap::new());
    }

    let wave = rbitcoin_store::load_tweak_wave(&query.store().txs, &fks)?;
    let mut by_fk: HashMap<Fk, ([u8; 32], &[OutputRecord])> = HashMap::new();
    for t in &wave.txs {
        by_fk.insert(t.fk, (t.rec.txid, &t.outs));
    }
    for (fk, (txid, outs)) in &wave.parents {
        by_fk.entry(Fk(*fk)).or_insert((*txid, outs));
    }
    let txs: Vec<&LoadedTweakTx> = wave.txs.iter().collect();
    let tweaks = tweaks_for_txs(&txs, &|fk| by_fk.get(&fk).copied())?;
    Ok(txs
        .iter()
        .zip(tweaks)
        .filter_map(|(t, tw)| Some((t.rec.txid, tw?)))
        .collect())
}

/// Tweak records of `window.blocks[i]` in block order (`None` = ineligible).
pub fn tweak_records_from_window(
    window: &IndexWindow,
    i: usize,
) -> Result<Vec<Option<[u8; 33]>>, ConsensusError> {
    let txs: Vec<&LoadedTweakTx> = window.blocks[i].txs.iter().collect();
    let tweaks = tweaks_for_txs(&txs, &|fk| Some((window.txid(fk)?, window.outs(fk)?)))?;
    Ok(tweaks.into_iter().map(|t| t.map(|t| t.tweak)).collect())
}

/// Txid and outputs of a spent create.
type ParentLookup<'a> = dyn Fn(Fk) -> Option<([u8; 32], &'a [OutputRecord])> + 'a;

/// Per-tx tweak (`None` = ineligible) for `txs` in order. Only P2TR-output
/// txs with loaded inputs are candidates; EC math runs on the caller.
fn tweaks_for_txs<'a>(
    txs: &[&'a LoadedTweakTx],
    parent: &ParentLookup<'a>,
) -> Result<Vec<Option<TxTweak>>, ConsensusError> {
    let mut out = vec![None; txs.len()];
    for (i, t) in txs.iter().enumerate() {
        if !t.need_seqsigwit {
            continue;
        }
        let Some(inputs) = t.inputs.as_ref() else {
            continue;
        };
        let (tx, prevouts) = build_tx_and_prevouts(inputs, &t.outs, parent)?;
        out[i] = tweak_from_tx(&tx, &prevouts);
    }
    Ok(out)
}

#[allow(clippy::type_complexity)] // packed row / pin / script-hash tuple is the on-disk shape
/// Tweaks-wire `TxTweak` from a stored 33-byte tweak + this tx’s packed outs.
///
/// No parent IO. `Some(tweak)` with missing packed outs is corrupt.
pub fn tweaks_from_thin_and_body(
    rows: &[([u8; 32], Option<[u8; 33]>, Option<&[OutputRecord]>)],
) -> Result<BTreeMap<[u8; 32], TxTweak>, StoreError> {
    let mut out = BTreeMap::new();
    for (txid, tweak, outs) in rows {
        let Some(tweak) = tweak else {
            continue;
        };
        let Some(outs) = outs else {
            return Err(StoreError::Corrupt(
                "invariant: thin tweak missing packed body",
            ));
        };
        out.insert(
            *txid,
            TxTweak {
                tweak: *tweak,
                output_pubkeys: taproot_outs_from_records(outs),
            },
        );
    }
    Ok(out)
}

fn taproot_outs_from_records(outputs: &[OutputRecord]) -> Vec<TaprootOut> {
    let mut out = Vec::new();
    for (i, o) in outputs.iter().enumerate() {
        if !is_p2tr(&o.script) {
            continue;
        }
        if o.script.len() < 34 {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&o.script[2..34]);
        let value = if o.value < 0 { 0 } else { o.value as u64 };
        out.push(TaprootOut {
            vout: i as u32,
            xonly,
            value,
        });
    }
    out
}

/// A spent parent missing from the lookup is an invariant break, not an
/// ineligible tx.
fn build_tx_and_prevouts(
    inputs: &[InputRecord],
    outputs: &[OutputRecord],
    parent: &ParentLookup<'_>,
) -> Result<(Transaction, Vec<TxOut>), StoreError> {
    let mut prevouts = Vec::with_capacity(inputs.len());
    let mut txins = Vec::with_capacity(inputs.len());
    for inp in inputs {
        let (prev_txid, prev_script, prev_value) = if inp.is_coinbase() {
            ([0u8; 32], Vec::new(), 0i64)
        } else {
            const MISSING: &str = "invariant: sp_tweaks spent parent missing";
            let (tid, outs) = parent(inp.create_fk).ok_or(StoreError::Corrupt(MISSING))?;
            let o = outs
                .get(inp.prev_index as usize)
                .ok_or(StoreError::Corrupt(MISSING))?;
            (tid, o.script.clone(), o.value)
        };
        let wit_refs: Vec<&[u8]> = inp.witness.iter().map(|w| w.as_slice()).collect();
        txins.push(bitcoin::TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(prev_txid),
                vout: inp.prev_index,
            },
            script_sig: bitcoin::ScriptBuf::from_bytes(inp.script_sig.clone()),
            sequence: bitcoin::Sequence::from_consensus(inp.sequence),
            witness: Witness::from_slice(&wit_refs),
        });
        let value = if prev_value < 0 {
            bitcoin::Amount::ZERO
        } else {
            bitcoin::Amount::from_sat(prev_value as u64)
        };
        prevouts.push(TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(prev_script),
        });
    }
    let mut txouts = Vec::with_capacity(outputs.len());
    for o in outputs {
        let value = if o.value < 0 {
            bitcoin::Amount::ZERO
        } else {
            bitcoin::Amount::from_sat(o.value as u64)
        };
        txouts.push(TxOut {
            value,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(o.script.clone()),
        });
    }
    Ok((
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: txins,
            output: txouts,
        },
        prevouts,
    ))
}

fn input_hash_mul_a(tx: &Transaction, a: &PublicKey) -> Option<[u8; 33]> {
    let mut smallest = outpoint_bytes(&tx.input[0].previous_output);
    for vin in tx.input.iter().skip(1) {
        let b = outpoint_bytes(&vin.previous_output);
        if b < smallest {
            smallest = b;
        }
    }
    let ser_a = a.serialize();
    let mut msg = [0u8; 36 + 33];
    msg[..36].copy_from_slice(&smallest);
    msg[36..].copy_from_slice(&ser_a);
    let h = tagged_hash(b"BIP0352/Inputs", &msg);
    if h == [0u8; 32] {
        return None;
    }
    let scalar = Scalar::from_be_bytes(h).ok()?;
    let tweaked = a.mul_tweak(secp(), &scalar).ok()?;
    Some(tweaked.serialize())
}

/// BIP-352 `P_k = B_spend + t_k·G` for tweak `A` and integer `k`.
pub fn taproot_matches_scan(
    tweak_compressed: &[u8; 33],
    output_xonly: &[u8; 32],
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    k: u32,
) -> bool {
    let Ok(a) = PublicKey::from_slice(tweak_compressed) else {
        return false;
    };
    let Ok(scan_scalar) = Scalar::from_be_bytes(scan_sk.secret_bytes()) else {
        return false;
    };
    let Ok(shared) = a.mul_tweak(secp(), &scan_scalar) else {
        return false;
    };
    let mut payload = [0u8; 37];
    payload[..33].copy_from_slice(&shared.serialize());
    payload[33..].copy_from_slice(&k.to_be_bytes());
    let t = tagged_hash(b"BIP0352/SharedSecret", &payload);
    let Ok(tk) = SecretKey::from_slice(&t) else {
        return false;
    };
    let tg = PublicKey::from_secret_key(secp(), &tk);
    let Ok(p) = PublicKey::combine_keys(&[spend_pk, &tg]) else {
        return false;
    };
    p.x_only_public_key().0.serialize() == *output_xonly
}

fn tagged_hash(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let tagh = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tagh.as_ref());
    eng.input(tagh.as_ref());
    eng.input(payload);
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn outpoint_bytes(op: &OutPoint) -> [u8; 36] {
    let mut b = [0u8; 36];
    b[..32].copy_from_slice(op.txid.as_byte_array());
    b[32..].copy_from_slice(&op.vout.to_le_bytes());
    b
}

fn taproot_outs(tx: &Transaction) -> Vec<TaprootOut> {
    let mut out = Vec::new();
    for (i, o) in tx.output.iter().enumerate() {
        let spk = o.script_pubkey.as_bytes();
        if !is_p2tr(spk) {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&spk[2..34]);
        out.push(TaprootOut {
            vout: i as u32,
            xonly,
            value: o.value.to_sat(),
        });
    }
    out
}

fn is_p2tr(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14
}

fn is_p2pkh(spk: &[u8]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
}

fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87
}

fn witness_version(spk: &[u8]) -> Option<u8> {
    if spk.len() < 4 || spk.len() > 42 {
        return None;
    }
    let version = match spk[0] {
        0x00 => 0u8,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return None,
    };
    let n = spk[1] as usize;
    if !(2..=40).contains(&n) || spk.len() != 2 + n {
        return None;
    }
    Some(version)
}

fn extract_input_pubkey(
    prev: &Script,
    script_sig: &Script,
    witness: &Witness,
) -> Option<PublicKey> {
    let spk = prev.as_bytes();
    if is_p2tr(spk) {
        return extract_p2tr(spk, witness);
    }
    if is_p2wpkh(spk) {
        return last_compressed_witness_pubkey(witness);
    }
    if is_p2sh(spk) {
        if !is_p2sh_p2wpkh_redeem(script_sig) {
            return None;
        }
        return last_compressed_witness_pubkey(witness);
    }
    if is_p2pkh(spk) {
        return p2pkh_script_pubkey(spk, script_sig);
    }
    None
}

fn extract_p2tr(spk: &[u8], witness: &Witness) -> Option<PublicKey> {
    if nums_h_script_path(witness) {
        return None;
    }
    let xonly = XOnlyPublicKey::from_slice(&spk[2..34]).ok()?;
    // Even-Y lift (BIP340 / BIP-352 taproot inputs).
    Some(xonly.public_key(Parity::Even))
}

fn nums_h_script_path(witness: &Witness) -> bool {
    let items = witness_items_no_annex(witness);
    if items.len() < 2 {
        return false;
    }
    let cb = items[items.len() - 1];
    if cb.len() < 33 {
        return false;
    }
    cb[1..33] == NUMS_H
}

fn witness_items_no_annex(witness: &Witness) -> Vec<&[u8]> {
    let mut items: Vec<&[u8]> = witness.iter().collect();
    if items.len() >= 2 {
        if let Some(last) = items.last() {
            if !last.is_empty() && last[0] == 0x50 {
                items.pop();
            }
        }
    }
    items
}

fn last_compressed_witness_pubkey(witness: &Witness) -> Option<PublicKey> {
    let items = witness_items_no_annex(witness);
    let last = items.last()?;
    compressed_pubkey(last)
}

/// P2PKH scriptSigs are third-party malleable. Take the compressed key whose
/// HASH160 matches the prevout (BIP-352: parse even if the template is wrapped).
fn p2pkh_script_pubkey(spk: &[u8], script_sig: &Script) -> Option<PublicKey> {
    if spk.len() != 25 {
        return None;
    }
    let want = &spk[3..23];
    let mut last = None;
    for ins in script_sig.instructions() {
        let Ok(Instruction::PushBytes(b)) = ins else {
            continue;
        };
        if let Some(pk) = compressed_pubkey(b.as_bytes()) {
            let h = hash160::Hash::hash(&pk.serialize());
            if h.as_byte_array() == want {
                last = Some(pk);
            }
        }
    }
    last
}

fn compressed_pubkey(b: &[u8]) -> Option<PublicKey> {
    if b.len() == 33 && (b[0] == 0x02 || b[0] == 0x03) {
        PublicKey::from_slice(b).ok()
    } else {
        None
    }
}

fn is_p2sh_p2wpkh_redeem(script_sig: &Script) -> bool {
    let mut push: Option<Vec<u8>> = None;
    let mut n = 0usize;
    for ins in script_sig.instructions() {
        match ins {
            Ok(Instruction::PushBytes(b)) => {
                n += 1;
                push = Some(b.as_bytes().to_vec());
            }
            Ok(_) => return false,
            Err(_) => return false,
        }
    }
    if n != 1 {
        return false;
    }
    let Some(r) = push else {
        return false;
    };
    r.len() == 22 && r[0] == 0x00 && r[1] == 0x14
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Milestone;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Sequence, TxIn};
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, TxRecord};
    use serde_json::Value;
    use std::str::FromStr;
    #[test]
    fn taproot_matches_scan_rejects_invalid_tweak() {
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(secp(), &sk);
        assert!(!taproot_matches_scan(&[0u8; 33], &[0u8; 32], &sk, &pk, 0));
        assert!(!taproot_matches_scan(&[2u8; 33], &[0u8; 32], &sk, &pk, 7));
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        rbitcoin_primitives::hex_decode(s).expect("hex")
    }

    fn decode_witness(s: &str) -> Witness {
        if s.is_empty() {
            return Witness::new();
        }
        let b = hex_bytes(s);
        deserialize::<Witness>(&b).unwrap_or_else(|_| Witness::from_slice(&[&b]))
    }

    fn tx_from_receiving(given: &Value) -> (Transaction, Vec<TxOut>) {
        let vin = given["vin"].as_array().expect("vin");
        let mut input = Vec::new();
        let mut prevouts = Vec::new();
        for v in vin {
            let txid = bitcoin::Txid::from_str(v["txid"].as_str().unwrap()).unwrap();
            let vout = v["vout"].as_u64().unwrap() as u32;
            let script_sig =
                ScriptBuf::from_bytes(hex_bytes(v["scriptSig"].as_str().unwrap_or("")));
            let wit = match &v["txinwitness"] {
                Value::String(s) => decode_witness(s),
                Value::Array(items) => {
                    let stacks: Vec<Vec<u8>> = items
                        .iter()
                        .filter_map(|x| x.as_str().map(hex_bytes))
                        .collect();
                    let refs: Vec<&[u8]> = stacks.iter().map(|s| s.as_slice()).collect();
                    Witness::from_slice(&refs)
                }
                _ => Witness::new(),
            };
            input.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig,
                sequence: Sequence::MAX,
                witness: wit,
            });
            let prev_hex = v["prevout"]["scriptPubKey"]["hex"].as_str().unwrap();
            prevouts.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(hex_bytes(prev_hex)),
            });
        }
        let mut output = Vec::new();
        if let Some(outs) = given["outputs"].as_array() {
            for o in outs {
                let x = hex_bytes(o.as_str().unwrap());
                assert_eq!(x.len(), 32);
                let mut spk = vec![0x51, 0x20];
                spk.extend_from_slice(&x);
                output.push(TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(spk),
                });
            }
        }
        if output.is_empty() {
            output.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut s = vec![0x51, 0x20];
                    s.extend_from_slice(&[0u8; 32]);
                    s
                }),
            });
        }
        (
            Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input,
                output,
            },
            prevouts,
        )
    }

    #[test]
    fn official_vectors_receiving_tweaks() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/bip352_send_and_receive_test_vectors.json"
        ));
        let cases: Value = serde_json::from_str(raw).expect("vectors json");
        let mut n = 0u32;
        for case in cases.as_array().unwrap() {
            let comment = case["comment"].as_str().unwrap_or("");
            for rec in case["receiving"].as_array().unwrap() {
                let given = &rec["given"];
                let expected = &rec["expected"];
                let (tx, prev) = tx_from_receiving(given);
                let got = tweak_from_tx(&tx, &prev);
                match expected.get("tweak") {
                    Some(Value::String(exp)) => {
                        let t = got.unwrap_or_else(|| panic!("expected tweak for {comment}"));
                        assert_eq!(
                            rbitcoin_primitives::hex_encode(t.tweak),
                            exp.to_ascii_lowercase(),
                            "tweak mismatch: {comment}"
                        );
                        n += 1;
                    }
                    _ => {
                        assert!(
                            got.is_none(),
                            "expected skip for {comment}, got {:?}",
                            got.map(|g| rbitcoin_primitives::hex_encode(g.tweak))
                        );
                        n += 1;
                    }
                }
                let unlabeled = given["labels"]
                    .as_array()
                    .map(|a| a.is_empty())
                    .unwrap_or(true);
                if unlabeled {
                    if let Some(scan_hex) = given["key_material"]["scan_priv_key"].as_str() {
                        if let Some(tweak_hex) = expected["tweak"].as_str() {
                            let scan = SecretKey::from_slice(&hex_bytes(scan_hex)).unwrap();
                            let spend_sk = SecretKey::from_slice(&hex_bytes(
                                given["key_material"]["spend_priv_key"].as_str().unwrap(),
                            ))
                            .unwrap();
                            let spend_pk = PublicKey::from_secret_key(secp(), &spend_sk);
                            let mut tw = [0u8; 33];
                            tw.copy_from_slice(&hex_bytes(tweak_hex));
                            if let Some(outs) = expected["outputs"].as_array() {
                                for o in outs {
                                    let Some(pk) = o["pub_key"].as_str() else {
                                        continue;
                                    };
                                    let mut x = [0u8; 32];
                                    x.copy_from_slice(&hex_bytes(pk));
                                    assert!(
                                        (0u32..8).any(|k| {
                                            taproot_matches_scan(&tw, &x, &scan, &spend_pk, k)
                                        }),
                                        "scan miss {comment}"
                                    );
                                    n += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(n >= 28, "ran {n} receiving cases");
    }

    #[test]
    fn skip_witness_v2_input() {
        let tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut s = vec![0x51, 0x20];
                    s.extend_from_slice(&[1u8; 32]);
                    s
                }),
            }],
        };
        let mut v2 = vec![0x52, 0x14];
        v2.extend_from_slice(&[0u8; 20]);
        let prev = vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(v2),
        }];
        assert!(tweak_from_tx(&tx, &prev).is_none());
    }

    fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled("sp-tweaks")
    }

    fn header(h: u32, prev_fk: Fk, prev_hash: Option<[u8; 32]>) -> HeaderRecord {
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xec;
        let hash = match prev_hash {
            None => merkle,
            Some(ph) => rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207f_ffff, h),
        };
        HeaderRecord {
            prev_fk,
            version: 1,
            timestamp: h + 1,
            bits: 0x207f_ffff,
            nonce: h,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
            v2: None,
        }
    }

    #[test]
    fn thin_compose_matches_engine_outs_without_parents() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        // Reuse the P2WPKH→P2TR spend from the walk test via a tiny local chain.
        use bitcoin::hashes::hash160;
        use bitcoin::secp256k1::SecretKey;
        let secp_ctx = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp_ctx, &sk);
        let ser = pk.serialize();
        let h160 = hash160::Hash::hash(&ser);
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(h160.as_ref());
        let (xonly, _) = pk.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&xonly.serialize());
        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: genesis_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 1,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
                }],
            )
            .unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let h1 = header(1, fk0, Some(h0.hash));
        q.connect_block(
            Height(1),
            &h1,
            &[TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 2,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 1,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                inputs: vec![InputRecord {
                    prev_txid: genesis_txid,
                    create_fk,
                    prev_index: 0,
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![vec![0u8; 64], ser.to_vec()],
                }],
                outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
            }],
        )
        .unwrap();

        let naive = tweaks_for_height(&q, &params, Height(1)).unwrap();
        let t = naive.get(&spend_txid).unwrap();
        let spend_fk = q.block_tx_fks(Height(1)).unwrap()[0];
        let (_rec, _ins, outs) = q.store().get_tx_full(spend_fk).unwrap();
        let composed =
            tweaks_from_thin_and_body(&[(spend_txid, Some(t.tweak), Some(outs.as_slice()))])
                .unwrap();
        let c = composed.get(&spend_txid).unwrap();
        assert_eq!(c.tweak, t.tweak);
        assert_eq!(c.output_pubkeys, t.output_pubkeys);

        let miss = tweaks_from_thin_and_body(&[(spend_txid, Some(t.tweak), None)]);
        assert!(
            matches!(miss, Err(StoreError::Corrupt(m)) if m.contains("invariant")),
            "got {miss:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tweaks_for_height_unknown_is_empty() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        assert!(tweaks_for_height(&q, &params, Height(0))
            .unwrap()
            .is_empty());
        let main = ChainParams::mainnet();
        assert!(tweaks_for_height(&q, &main, Height(100))
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connect with tweaks on seals that height. Disconnect truncates, and
    /// the replacement block is sealed on the next connect.
    #[test]
    fn live_connect_seals_tweaks_and_reorg_truncates() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        crate::prepare_live_indexes(&q).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
        let thin0 = q.load_thin_tweaks(Height(0)).unwrap().expect("indexed");
        assert!(
            thin0.is_empty(),
            "coinbase is not eligible — no Class A join"
        );

        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));

        q.disconnect_tip().unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_none());

        let b1b = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 601, 2);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1b, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(2)));
        assert!(q.load_thin_tweaks(Height(1)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Contiguous connects seal tweaks. The materialize does not rewrite them.
    #[test]
    fn live_connect_seals_tweaks_builder_leaves_them() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        crate::prepare_live_indexes(&q).unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        crate::accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE)
            .unwrap();
        let b1 = crate::mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
        crate::accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        let b2 = crate::mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
        crate::accept_and_connect_block(&q, &params, Height(2), &b2, Milestone::NONE).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(3)));

        q.release_index_writebehind(Height(2));
        crate::build_indexes_released(&q).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(3)));
        for h in 0..=2 {
            assert!(
                q.load_thin_tweaks(Height(h)).unwrap().is_some(),
                "height {h}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct SpKeys {
        p2wpkh: Vec<u8>,
        p2tr: Vec<u8>,
        pubkey: Vec<u8>,
    }

    fn sp_keys() -> SpKeys {
        use bitcoin::hashes::hash160;
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(secp(), &sk);
        let ser = pk.serialize();
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(hash160::Hash::hash(&ser).as_ref());
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&pk.x_only_public_key().0.serialize());
        SpKeys {
            p2wpkh,
            p2tr,
            pubkey: ser.to_vec(),
        }
    }

    fn sp_spend(
        tag: u8,
        prev: ([u8; 32], Fk, u32),
        witness: Vec<Vec<u8>>,
        outs: Vec<OutputRecord>,
    ) -> TxApply {
        let mut txid = [0u8; 32];
        txid[0] = tag;
        TxApply {
            tx: TxRecord {
                txid,
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: outs.len() as u32,
            },
            inputs: vec![InputRecord {
                prev_txid: prev.0,
                create_fk: prev.1,
                prev_index: prev.2,
                sequence: u32::MAX,
                script_sig: vec![],
                witness,
            }],
            outputs: outs,
        }
    }

    fn seal_tweaks(q: &Query, through: u32) {
        q.release_index_writebehind(Height(through));
        crate::build_indexes_released(q).unwrap();
        assert_eq!(q.sptweaks_next_height(), Some(Height(through + 1)));
    }

    /// Height 1 carries two eligible P2WPKH→P2TR spends around a spend with
    /// fat seqsigwit and a fat output script. The naive walk, the index
    /// window reader, the engine on the rebuilt wire tx, and the served
    /// index all give the same tweaks, and the served read spans the
    /// middle txout but not its seqsigwit.
    fn pin_tweaks_agree_and_thin_serve_skips_fat_witness(
        q: &Query,
        params: &ChainParams,
        keys: &SpKeys,
        a: [u8; 32],
        b: [u8; 32],
    ) {
        let naive = tweaks_for_height(q, params, Height(1)).unwrap();
        assert_eq!(naive.len(), 2, "the OP_TRUE spend is not eligible");
        let fks = q.block_tx_fks(Height(1)).unwrap();
        let wire_a = q.reconstruct_tx(fks[0]).unwrap();
        let engine_prev = [TxOut {
            value: Amount::from_sat(20_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(keys.p2wpkh.clone()),
        }];
        let engine = tweak_from_tx(&wire_a, &engine_prev).unwrap();
        assert_eq!(naive[&a].tweak, engine.tweak);
        assert_eq!(naive[&a].output_pubkeys, engine.output_pubkeys);

        let want = vec![Some(naive[&a].tweak), None, Some(naive[&b].tweak)];
        for start in [0, 1] {
            let heights = q.index_heights(start, 1, Some(0)).unwrap();
            let window = q.read_index_window(&heights).unwrap();
            let i = window.blocks.len() - 1;
            assert_eq!(
                tweak_records_from_window(&window, i).unwrap(),
                want,
                "window from {start}: the parent inside or outside the window"
            );
        }

        let mid_seqsigwit = q.store().tx_seqsigwit_range(fks[1]).unwrap().1;
        let mid_txout = q.store().txs.body_range(fks[1]).unwrap().1;
        let _ = q.sample_reset_thin_tweak_body_bytes();
        let rows = q.load_thin_tweaks(Height(1)).unwrap().expect("indexed");
        let read = q.sample_reset_thin_tweak_body_bytes();
        assert_eq!(
            rows.iter().map(|r| r.txid).collect::<Vec<_>>(),
            [a, b],
            "ineligible txs are not joined from Class A"
        );
        assert_eq!((rows[0].p2tr.len(), rows[1].p2tr.len()), (2, 1));
        assert!(
            read >= mid_txout,
            "the txout span covers the ineligible hole (read={read} txout={mid_txout})"
        );
        assert!(
            read < mid_seqsigwit,
            "the fat seqsigwit stays out (read={read} seqsigwit={mid_seqsigwit})"
        );
        let indexed = tweaks_at_height(q, params, Height(1)).unwrap();
        for txid in [a, b] {
            assert_eq!(indexed[&txid].tweak, naive[&txid].tweak);
            assert_eq!(indexed[&txid].output_pubkeys, naive[&txid].output_pubkeys);
        }
    }

    fn pin_thin_range_limits_and_hole(q: &Query, a: [u8; 32], c: [u8; 32]) {
        use rbitcoin_query::ThinTweakRangeLimits;

        let all = q
            .load_thin_tweaks_range(Height(0), ThinTweakRangeLimits::default())
            .unwrap();
        assert_eq!(
            all.iter()
                .map(|(h, rows)| (h.0, rows.len()))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 2), (2, 1)]
        );
        assert_eq!(all[2].1[0].txid, c);
        for (h, rows) in &all {
            let single = q.load_thin_tweaks(*h).unwrap().expect("indexed");
            assert_eq!(single.len(), rows.len());
            for (s, r) in single.iter().zip(rows) {
                assert_eq!((s.txid, s.tweak, &s.p2tr), (r.txid, r.tweak, &r.p2tr));
            }
        }
        let limited = |max_heights, max_eligible| {
            q.load_thin_tweaks_range(
                Height(1),
                ThinTweakRangeLimits {
                    max_heights,
                    max_eligible,
                    ..ThinTweakRangeLimits::default()
                },
            )
            .unwrap()
        };
        assert_eq!(limited(1, 8192).len(), 1);
        assert_eq!(
            limited(10, 1).len(),
            1,
            "the eligible budget stops after the first height that spends it"
        );
        assert!(q
            .load_thin_tweaks_range(Height(3), ThinTweakRangeLimits::default())
            .unwrap()
            .is_empty());
        let only2 = q
            .load_thin_tweaks_range(Height(2), ThinTweakRangeLimits::default())
            .unwrap();
        assert_eq!(only2.len(), 1);
        assert_eq!(only2[0].0, Height(2));

        let cut = |cut_through| {
            q.load_thin_tweaks_range(
                Height(1),
                ThinTweakRangeLimits {
                    cut_through,
                    ..ThinTweakRangeLimits::default()
                },
            )
            .unwrap()
        };
        let kept = cut(true);
        let row_a = kept[0].1.iter().find(|r| r.txid == a).unwrap();
        assert_eq!(
            row_a.p2tr.iter().map(|o| o.0).collect::<Vec<_>>(),
            [1],
            "cut-through drops the P2TR output spent at height 2"
        );
        let hist = cut(false);
        assert_eq!(
            hist[0].1.iter().find(|r| r.txid == a).unwrap().p2tr.len(),
            2
        );
    }

    /// One synthetic chain through the index builder: coinbase at 0, two
    /// eligible spends around a fat ineligible one at 1, a spend of one of
    /// those P2TR outputs plus a third eligible spend at 2 (sealed with 1 in
    /// one window), and at 3 the spend that leaves the first tx all spent.
    #[test]
    fn sp_tweaks_confirm_life() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let keys = sp_keys();
        q.set_sptweaks_enabled(true, Height(0)).unwrap();
        let sig_wit = || vec![vec![0u8; 64], keys.pubkey.clone()];
        let p2tr = |sat| OutputRecord::unspent(sat, keys.p2tr.clone());

        let mut cb_txid = [0u8; 32];
        cb_txid[31] = 0xcb;
        let h0 = header(0, Fk::NULL, None);
        let fk0 = q
            .connect_block(
                Height(0),
                &h0,
                &[TxApply {
                    tx: TxRecord {
                        txid: cb_txid,
                        version: 1,
                        locktime: 0,
                        input_start_fk: Fk::NULL,
                        input_count: 1,
                        output_start_fk: Fk::NULL,
                        output_count: 4,
                    },
                    inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
                    outputs: vec![
                        OutputRecord::unspent(20_0000_0000, keys.p2wpkh.clone()),
                        OutputRecord::unspent(20_0000_0000, keys.p2wpkh.clone()),
                        OutputRecord::unspent(5_0000_0000, vec![0x51]),
                        OutputRecord::unspent(5_0000_0000, keys.p2wpkh.clone()),
                    ],
                }],
            )
            .unwrap();
        seal_tweaks(&q, 0);
        assert!(
            q.load_thin_tweaks(Height(0)).unwrap().unwrap().is_empty(),
            "a coinbase is not eligible"
        );
        let cb = q.block_tx_fks(Height(0)).unwrap()[0];

        let spend_a = sp_spend(
            0xaa,
            (cb_txid, cb, 0),
            sig_wit(),
            vec![p2tr(12_0000_0000), p2tr(7_0000_0000)],
        );
        let fat = sp_spend(
            0xfe,
            (cb_txid, cb, 2),
            vec![vec![0u8; 16_384]],
            vec![OutputRecord::unspent(4_0000_0000, vec![0x51; 4096])],
        );
        let spend_b = sp_spend(0xbb, (cb_txid, cb, 1), sig_wit(), vec![p2tr(19_0000_0000)]);
        let (a, b) = (spend_a.tx.txid, spend_b.tx.txid);
        let h1 = header(1, fk0, Some(h0.hash));
        let fk1 = q
            .connect_block(Height(1), &h1, &[spend_a, fat, spend_b])
            .unwrap();
        let a_fk = q.block_tx_fks(Height(1)).unwrap()[0];

        let spend_c = sp_spend(0xcc, (cb_txid, cb, 3), sig_wit(), vec![p2tr(4_0000_0000)]);
        let c = spend_c.tx.txid;
        let spend_a0 = sp_spend(
            0xd0,
            (a, a_fk, 0),
            vec![vec![0u8; 64]],
            vec![OutputRecord::unspent(11_0000_0000, keys.p2wpkh.clone())],
        );
        let h2 = header(2, fk1, Some(h1.hash));
        let fk2 = q
            .connect_block(Height(2), &h2, &[spend_c, spend_a0])
            .unwrap();
        assert_eq!(
            q.sptweaks_next_height(),
            Some(Height(1)),
            "confirm writes none"
        );
        seal_tweaks(&q, 2);

        pin_tweaks_agree_and_thin_serve_skips_fat_witness(&q, &params, &keys, a, b);
        pin_thin_range_limits_and_hole(&q, a, c);

        let spend_a1 = sp_spend(
            0xd1,
            (a, a_fk, 1),
            vec![vec![0u8; 64]],
            vec![OutputRecord::unspent(6_0000_0000, vec![0x51])],
        );
        let h3 = header(3, fk2, Some(h2.hash));
        q.connect_block(Height(3), &h3, &[spend_a1]).unwrap();
        seal_tweaks(&q, 3);
        let gone = q
            .load_thin_tweaks_range(
                Height(1),
                rbitcoin_query::ThinTweakRangeLimits {
                    cut_through: true,
                    ..rbitcoin_query::ThinTweakRangeLimits::default()
                },
            )
            .unwrap();
        assert_eq!(
            gone[0].1.iter().map(|r| r.txid).collect::<Vec<_>>(),
            [b],
            "an all-spent eligible tx is omitted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
