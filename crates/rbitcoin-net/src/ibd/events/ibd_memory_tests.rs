//! Header-path and body-intake bounds (findings C03, C05).

use super::super::state::IbdWorkState;
use super::{accepted_prefix_after_failure, apply_block_framed, on_headers_batch};
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::BlockHash;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
};
use std::sync::atomic::AtomicU32;

fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, crate::chain::ChainHub) {
    crate::chain::tiny_regtest_hub_labeled("ibd-memory")
}

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        rbitcoin_consensus::bip34_height_script(height)
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

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time,
            bits,
            nonce: 0,
            v2: None,
        },
        txdata: vec![coinbase(height)],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    block
}

#[test]
fn rejected_header_batch_does_not_grow_path_or_explore() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let path_before = st.hash_height.len();
    let mut bad = mine(gen, 1_500_010_000, 1);
    bad.header.time = 0;
    on_headers_batch(&mut st, &hub, 0, vec![bad.header]);
    assert_eq!(
        st.hash_height.len(),
        path_before,
        "invalid header must not enter the work path"
    );
    assert!(st.reorg.explore_need_hashes().is_empty());
    assert!(st.reorg.explore_tips().is_empty());

    let good = mine(gen, 1_500_010_000, 1);
    on_headers_batch(&mut st, &hub, 0, vec![good.header]);
    assert!(
        st.hash_height.contains_key(&good.block_hash()),
        "a valid header still records path state"
    );
    let tipped = hub
        .query
        .milestone_best_work_be()
        .expect("a header on the tip passes chain work into the milestone path");
    let expect = (hub.chain_work().unwrap() + good.header.work()).to_be_bytes();
    assert_eq!(tipped, expect);

    let mut child = mine(good.block_hash(), 1_500_010_600, 2);
    child.header.time = 0;
    let broken = child.header.block_hash();
    on_headers_batch(&mut st, &hub, 0, vec![good.header, child.header]);
    assert!(
        st.hash_height.contains_key(&good.block_hash()),
        "the valid prefix stays on the path"
    );
    assert!(
        !st.hash_height.contains_key(&broken),
        "header after a failed validation must not be noted"
    );

    // `good` was stored before this pair, so a search that returns nothing
    // still leaves it on the path. A fresh prefix has to be found by the
    // binary search or it never enters the work path.
    let fresh = mine(good.block_hash(), 1_500_011_200, 2);
    let mut bad_tail = mine(fresh.block_hash(), 1_500_011_800, 3);
    bad_tail.header.time = 0;
    let fresh_hash = fresh.block_hash();
    let tail_hash = bad_tail.header.block_hash();
    let added = on_headers_batch(&mut st, &hub, 0, vec![fresh.header, bad_tail.header]);
    assert!(
        st.hash_height.contains_key(&fresh_hash),
        "binary search must keep the valid prefix of a rejected tail"
    );
    assert!(added >= 1, "the valid prefix is enqueued");
    assert!(
        !st.hash_height.contains_key(&tail_hash),
        "rejected tail must not be noted"
    );

    let second = mine(fresh.block_hash(), 1_500_012_200, 3);
    let mut bad_third = mine(second.block_hash(), 1_500_012_800, 4);
    bad_third.header.time = 0;
    let second_hash = second.block_hash();
    on_headers_batch(
        &mut st,
        &hub,
        0,
        vec![fresh.header, second.header, bad_third.header],
    );
    assert!(
        st.hash_height.contains_key(&second_hash),
        "both headers before a rejected tail stay on the path"
    );
    assert!(!st.hash_height.contains_key(&bad_third.header.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unsolicited_body_is_not_copied_into_the_queue() {
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let block = mine(gen, 1_500_020_000, 1);
    let hash = block.block_hash();
    let payload = serialize(&block);
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    st.record_height(hash, 1);
    st.header_fks.insert(hash, rbitcoin_primitives::Fk(1));
    let before = hub.query.block_queue_stats().1;
    let write_next = AtomicU32::new(0);
    apply_block_framed(&mut st, &hub, &write_next, None, 0, hash, payload.clone());
    assert_eq!(
        hub.query.block_queue_stats().1,
        before,
        "unsolicited body must not be copied into the queue"
    );

    st.inflight
        .insert(hash, super::super::state::InflightReq::new(0));
    apply_block_framed(&mut st, &hub, &write_next, None, 0, hash, payload);
    assert!(
        hub.query.block_queue_stats().1 > before,
        "a requested body is still queued"
    );
    let queued = hub.query.block_queue_stats().1;
    st.inflight
        .insert(hash, super::super::state::InflightReq::new(0));
    apply_block_framed(&mut st, &hub, &write_next, None, 0, hash, serialize(&block));
    assert_eq!(
        hub.query.block_queue_stats().1,
        queued,
        "a second copy of a queued hash is dropped"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// One genesis chain. A re-sent stored run does not walk, an unmapped run
/// walks once, an unknown parent is not retried, and a lowered walk cap keeps
/// the stored prefix while a run past the cap still walks once.
#[test]
fn stored_header_resends_walk_once() {
    const CAP: u32 = 4;
    let (dir, hub) = tmp_hub();
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let mut chain = Vec::new();
    let mut prev = gen;
    for height in 1..=240u32 {
        let header = mine(prev, 1_500_030_000 + height * 600, height).header;
        prev = header.block_hash();
        chain.push(header);
    }
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    on_headers_batch(&mut st, &hub, 0, chain[..200].to_vec());
    let _ = hub.take_stored_height_walk_steps();
    on_headers_batch(&mut st, &hub, 0, chain[100..200].to_vec());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        0,
        "a re-sent run of stored headers walks no ancestors"
    );
    on_headers_batch(&mut st, &hub, 0, chain.clone());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        0,
        "a stored prefix before new headers walks no ancestors"
    );
    for (height, header) in (1u32..).zip(&chain) {
        assert_eq!(
            st.hash_height.get(&header.block_hash()),
            Some(&height),
            "every header, stored or new, stays on the path at its height"
        );
    }

    let mut fresh = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let _ = hub.take_stored_height_walk_steps();
    on_headers_batch(&mut fresh, &hub, 0, chain[..200].to_vec());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        1,
        "a stored run outside header_fks walks only its first header"
    );
    for (height, header) in (1u32..).zip(&chain[..200]) {
        assert_eq!(
            fresh.hash_height.get(&header.block_hash()),
            Some(&height),
            "every stored header is on the path at its height"
        );
    }

    let unknown = BlockHash::from_byte_array([0x7d; 32]);
    let mut side = Vec::new();
    let mut prev = unknown;
    for height in 1..=20u32 {
        let header = mine(prev, 1_500_050_000 + height * 600, height).header;
        prev = header.block_hash();
        side.push(header);
    }
    let mut side_st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    on_headers_batch(&mut side_st, &hub, 0, side.clone());
    assert!(side_st.header_fks.is_empty());
    for header in &side {
        assert!(!side_st.hash_height.contains_key(&header.block_hash()));
    }

    hub.set_stored_height_walk_cap(CAP);
    let parent = chain[(CAP + 7) as usize].block_hash();
    let mut rejected = mine(parent, 1_500_030_000 + (CAP + 9) * 600, CAP + 9).header;
    rejected.time = 0;
    let mut batch = chain[CAP as usize..(CAP as usize + 8)].to_vec();
    batch.push(rejected);
    let mut tail = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let _ = hub.take_stored_height_walk_steps();
    on_headers_batch(&mut tail, &hub, 0, batch);
    assert!(hub.take_stored_height_walk_steps() >= u64::from(CAP));
    for header in &chain[CAP as usize..CAP as usize + 8] {
        assert!(tail.header_fks.contains_key(&header.block_hash()));
    }
    assert!(!tail.header_fks.contains_key(&rejected.block_hash()));

    let above = (CAP as usize)..(CAP as usize + 2);
    let mut past = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let _ = hub.take_stored_height_walk_steps();
    on_headers_batch(&mut past, &hub, 0, chain[above.clone()].to_vec());
    assert_eq!(
        hub.take_stored_height_walk_steps(),
        u64::from(CAP),
        "a stored run past the walk cap walks once, not once per header"
    );
    for header in &chain[above] {
        assert!(
            past.header_fks.contains_key(&header.block_hash()),
            "a header past the cap is still accepted"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn failed_first_prefix_stops_search() {
    let mut probes = Vec::new();
    let (lo, values): (usize, Vec<u32>) = accepted_prefix_after_failure(2000, |mid| {
        probes.push(mid);
        Err(crate::error::NetError::Protocol("first header rejected"))
    });
    assert_eq!(lo, 0);
    assert!(values.is_empty());
    assert_eq!(
        probes,
        vec![1],
        "do not retry longer prefixes after first header fails"
    );

    let mut probes = Vec::new();
    let (lo, values) = accepted_prefix_after_failure(2000, |mid| {
        probes.push(mid);
        if mid <= 731 {
            Ok((1..=mid).collect::<Vec<_>>())
        } else {
            Err(crate::error::NetError::Protocol("rejected tail"))
        }
    });
    assert_eq!(lo, 731);
    assert_eq!(values.len(), lo);
    assert_eq!(values[0], 1);
    assert_eq!(values[lo - 1], 731);
    assert_eq!(probes[0], 1);
}
