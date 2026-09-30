//! Knots RDTS (`SCRIPT_VERIFY_REDUCED_DATA`) outside tapscript: element sizes
//! on P2WSH and P2SH, the redeemScript exemption, unknown witness versions.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::block::{ScriptCheckJob, ScriptVerifyFlags};
use crate::script;

fn job(spk: Vec<u8>, script_sig: Vec<u8>, witness: &[&[u8]], reduced: bool) -> ScriptCheckJob {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let prevout = TxOut {
        value: Amount::from_sat(2),
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let mut flags = ScriptVerifyFlags::buried(true, true, true, true, true);
    flags.reduced_data = reduced;
    ScriptCheckJob::new(vec![prevout], tx, flags)
}

fn p2wsh_spk(witness_script: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend_from_slice(&bitcoin::hashes::sha256::Hash::hash(witness_script).to_byte_array());
    v
}

fn p2sh_spk(redeem: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa9, 0x14];
    v.extend_from_slice(&script::crypto::hash160(redeem));
    v.push(0x87);
    v
}

fn push(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    match data.len() {
        0..=75 => v.push(data.len() as u8),
        76..=255 => {
            v.push(0x4c);
            v.push(data.len() as u8);
        }
        _ => {
            v.push(0x4d);
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
    }
    v.extend_from_slice(data);
    v
}

#[test]
fn p2wsh_initial_elements_are_256_bytes_under_rdts() {
    let ws = [0x75u8, 0x51]; // OP_DROP OP_1
    let big = vec![0u8; 300];
    script::verify_job_all_inputs(&job(p2wsh_spk(&ws), vec![], &[&big, &ws], false))
        .expect("300 bytes without RDTS");
    let err = script::verify_job_all_inputs(&job(p2wsh_spk(&ws), vec![], &[&big, &ws], true))
        .expect_err("300 bytes under RDTS");
    assert!(format!("{err}").contains("PUSH_SIZE"));
    let small = vec![0u8; 256];
    script::verify_job_all_inputs(&job(p2wsh_spk(&ws), vec![], &[&small, &ws], true))
        .expect("256 bytes is the limit");
    let mut exempt = job(p2wsh_spk(&ws), vec![], &[&big, &ws], true);
    exempt.rdts_exempt = vec![true];
    script::verify_job_all_inputs(&exempt).expect("pre-fork input is exempt");
}

#[test]
fn p2sh_redeem_script_push_is_exempt_but_other_pushes_are_not() {
    // A 271-byte redeemScript with no push over 25 bytes: ten `<25 bytes> OP_DROP`, then OP_1.
    let mut redeem = Vec::new();
    for _ in 0..10 {
        redeem.extend_from_slice(&push(&[0xab; 25]));
        redeem.push(0x75);
    }
    redeem.push(0x51);
    assert!(redeem.len() > 256);
    script::verify_job_all_inputs(&job(p2sh_spk(&redeem), push(&redeem), &[], true))
        .expect("the redeemScript push may exceed 256 bytes");

    // Any other scriptSig push is held to the reduced limit.
    let tiny = [0x75u8, 0x51];
    let mut ss = push(&[0u8; 300]);
    ss.extend_from_slice(&push(&tiny));
    script::verify_job_all_inputs(&job(p2sh_spk(&tiny), ss.clone(), &[], false))
        .expect("300-byte push without RDTS");
    let err = script::verify_job_all_inputs(&job(p2sh_spk(&tiny), ss, &[], true))
        .expect_err("300-byte push under RDTS");
    assert!(format!("{err}").contains("PUSH_SIZE"));

    // Inside the redeemScript the reduced limit applies.
    let mut fat = push(&[0xcd; 300]);
    fat.extend_from_slice(&[0x75, 0x51]);
    script::verify_job_all_inputs(&job(p2sh_spk(&fat), push(&fat), &[], false))
        .expect("300-byte push in redeem without RDTS");
    let err = script::verify_job_all_inputs(&job(p2sh_spk(&fat), push(&fat), &[], true))
        .expect_err("300-byte push in redeem under RDTS");
    assert!(format!("{err}").contains("push too large"));
}

#[test]
fn unknown_witness_versions_are_invalid_under_rdts() {
    let mut spk = vec![0x52, 0x20];
    spk.extend_from_slice(&[0x33; 32]);
    script::verify_job_all_inputs(&job(spk.clone(), vec![], &[&[0x01]], false))
        .expect("v2 program is anyone-can-spend without RDTS");
    let err = script::verify_job_all_inputs(&job(spk, vec![], &[&[0x01]], true))
        .expect_err("v2 program under RDTS");
    assert!(format!("{err}").contains("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"));
}

/// `btc:testnet4-blake2b` 150,870 spends a pay-to-anchor output under RDTS;
/// Knots takes `IsPayToAnchor` before the upgradable-program rule.
#[test]
fn pay_to_anchor_spends_under_rdts_with_an_empty_witness() {
    let anchor = vec![0x51, 0x02, 0x4e, 0x73];
    script::verify_job_all_inputs(&job(anchor.clone(), vec![], &[], true)).expect("anchor spend");
    let err = script::verify_job_all_inputs(&job(anchor, vec![], &[&[0x01]], true))
        .expect_err("an anchor with a witness item is an unknown program");
    assert!(format!("{err}").contains("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"));
}
