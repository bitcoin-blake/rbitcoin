//! Spend annotations lost after the tip seal must not make that output spendable.

use std::io::{Seek, SeekFrom, Write};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Block, Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Txid, Witness,
};

use crate::block::bip34_height_script;
use crate::{accept_and_connect_block, ChainParams, ConsensusError, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_store::spent_abs;

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend_one(prev: Txid, val: Amount) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: val,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn mine(prev: bitcoin::BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut txdata = vec![coinbase(height)];
    txdata.extend(extra);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time,
            bits,
            nonce: 0,
            v2: None,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    block
}

#[test]
fn zeroed_spend_slot_after_tip_seal_rejects_respend() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-durable");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;

    for h in 2..=maturity + 2 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    let h_spend = maturity + 3;
    let tx = spend_one(c1, Amount::from_sat(49_0000_0000));
    let block = mine(tip, tip_time + 600, h_spend, vec![tx]);
    accept_and_connect_block(&q, &params, Height(h_spend), &block, ms).unwrap();
    assert!(q.is_outpoint_spent(c1.as_byte_array(), 0).unwrap());
    let create_fk = q.tx_fk_by_txid(c1.as_byte_array()).unwrap().unwrap();
    let (off, _) = q.store().tx_spent_range(create_fk).unwrap();
    let abs = spent_abs(off, 0);
    let store = q.store().path().to_path_buf();
    drop(q);

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.join("spent.body"))
            .unwrap();
        f.seek(SeekFrom::Start(abs)).unwrap();
        f.write_all(&[0u8; 8]).unwrap();
    }
    let _ = std::fs::remove_file(store.join(rbitcoin_store::SPEND_DURABLE_NAME));

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let tip_h = q.tip_height().unwrap();
    let replayed = crate::replay_spend_annotations(&q).unwrap();
    assert_eq!(
        replayed, tip_h.0,
        "a missing marker replays every height above genesis"
    );
    let tip_hash = q.header_at_height(tip_h).unwrap().unwrap().1.hash;
    let respend = mine(
        bitcoin::BlockHash::from_byte_array(tip_hash),
        tip_time + 1_200,
        tip_h.0 + 1,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h.0 + 1), &respend, ms)
        .expect_err("a sealed spend must stay spent after its slot is zeroed");
    assert!(
        matches!(err, ConsensusError::PrevoutSpent),
        "reopen must reject the respend, got {err}"
    );
    let _ = dir;
}

#[test]
fn missing_marker_with_matching_tip_spends_does_not_replay() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-window");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 2 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let tx = spend_one(c1, Amount::from_sat(49_0000_0000));
    let block = mine(tip, tip_time + 600, maturity + 3, vec![tx]);
    accept_and_connect_block(&q, &params, Height(maturity + 3), &block, ms).unwrap();
    let store = q.store().path().to_path_buf();
    let tip_h = q.tip_height().unwrap().0;
    drop(q);
    let _ = std::fs::remove_file(store.join(rbitcoin_store::SPEND_DURABLE_NAME));
    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let replayed = crate::replay_spend_annotations(&q).unwrap();
    assert_eq!(
        replayed, 0,
        "a matching tip window must not rewrite the chain"
    );
    assert_eq!(q.store().spend_annotated_through().unwrap(), Some(tip_h));
    let _ = dir;
}

#[test]
fn replay_status_is_ten_seconds() {
    assert!(!super::write::replay_status_due(9_999));
    assert!(super::write::replay_status_due(10_000));
}
