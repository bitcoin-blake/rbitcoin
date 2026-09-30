use crate::error::ConsensusError;
use crate::params::{check_genesis_hash, ChainParams};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{CompactTarget, Target};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;

/// Validate header linkage, checkpoint, MTP, difficulty bits, and proof-of-work.
pub fn validate_header(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConsensusError> {
    validate_header_hashed(
        query,
        params,
        height,
        header,
        header.block_hash().to_byte_array(),
    )
}

/// [`validate_header`] using a caller-computed header hash (lookup already hashed).
pub(crate) fn validate_header_hashed(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header: &Header,
    hash: [u8; 32],
) -> Result<(), ConsensusError> {
    let hash_bh = bitcoin::BlockHash::from_byte_array(hash);

    if height.0 == 0 {
        if !check_genesis_hash(params, hash_bh) {
            return Err(ConsensusError::BadHeader("genesis hash mismatch"));
        }
    } else {
        let prev_height = Height(height.0 - 1);
        let (_prev_fk, prev_rec) = query
            .header_at_height(prev_height)?
            .ok_or(ConsensusError::BadPrev)?;
        if prev_rec.hash != header.prev_blockhash.to_byte_array() {
            return Err(ConsensusError::BadPrev);
        }

        let mtp = median_time_past(query, prev_height)?;
        if header.time <= mtp {
            return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
        }
        check_timewarp(params, height, prev_rec.timestamp, header.time)?;
        check_header_version_and_future_time(params, height, header)?;
    }

    if let Some(cp) = params.checkpoint_at(height) {
        if cp != hash_bh {
            return Err(ConsensusError::BadHeader("checkpoint mismatch"));
        }
    }

    let expected_bits = expected_next_bits(query, params, height, header.time)?;
    if header.bits != expected_bits {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }

    pow_hash_meets_target(hash, header.bits, params.pow_limit)
}

/// Contextual checks when the parent is a known header, not necessarily on the
/// best chain (`header_at_height` would miss).
pub fn validate_header_on_parent(
    params: &ChainParams,
    height: Height,
    header: &Header,
    parent_time: u32,
    parent_mtp: u32,
    expected_bits: CompactTarget,
) -> Result<(), ConsensusError> {
    if header.time <= parent_mtp {
        return Err(ConsensusError::BadHeader("timestamp <= median-time-past"));
    }
    check_timewarp(params, height, parent_time, header.time)?;
    check_header_version_and_future_time(params, height, header)?;
    if header.bits != expected_bits {
        return Err(ConsensusError::BadHeader("incorrect proof of work bits"));
    }
    pow_hash_meets_target(
        header.block_hash().to_byte_array(),
        header.bits,
        params.pow_limit,
    )
}

/// POW vs a **caller-computed** header hash (no second SHA256d).
pub(crate) fn pow_hash_meets_target(
    hash: [u8; 32],
    bits: CompactTarget,
    pow_limit: Target,
) -> Result<(), ConsensusError> {
    let target = Target::from_compact(bits);
    if target > pow_limit {
        return Err(ConsensusError::BadHeader("target above pow limit"));
    }
    if !target.is_met_by(bitcoin::BlockHash::from_byte_array(hash)) {
        return Err(ConsensusError::InvalidPow);
    }
    Ok(())
}

/// BIP94 timewarp floor: how far below its parent the first block of a
/// retarget period may be timestamped (Core `MAX_TIMEWARP`).
pub const MAX_TIMEWARP: u32 = 600;

/// BIP94: the first block of a retarget period is not earlier than its parent
/// by more than [`MAX_TIMEWARP`] (Core `ContextualCheckBlockHeader`).
pub(crate) fn check_timewarp(
    params: &ChainParams,
    height: Height,
    prev_time: u32,
    header_time: u32,
) -> Result<(), ConsensusError> {
    if !params.enforce_bip94() {
        return Ok(());
    }
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.0.is_multiple_of(interval) {
        return Ok(());
    }
    if header_time < prev_time.saturating_sub(MAX_TIMEWARP) {
        return Err(ConsensusError::BadHeader(
            "timestamp too early on retarget block (timewarp)",
        ));
    }
    Ok(())
}

/// Knots `CheckBlockHeader` / `ContextualCheckBlockHeaderVolatile` for the v2
/// header: v2 exactly from the fork height, no reserved flag bits, and the
/// header's own height field is the chain height.
pub fn check_header_v2_rules(
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConsensusError> {
    match header.v2 {
        Some(ext) => {
            if !params.blake2b_active_at(height.0) {
                return Err(ConsensusError::BadHeader("bad-version-sha256d"));
            }
            if ext.flags & 0xc0 != 0 {
                return Err(ConsensusError::BadHeader("bad-flags-highbits"));
            }
            if ext.height != height.0 as i32 {
                return Err(ConsensusError::BadHeader("bad-header-height"));
            }
        }
        None => {
            if params.blake2b_active_at(height.0) {
                return Err(ConsensusError::BadHeader("bad-version-blake2b"));
            }
        }
    }
    Ok(())
}

/// Knots `ApplyBlake2bTargetShift`: at the fork height the computed target is
/// shifted left by the chain's `target_shift`, clamped to the pow limit. Every
/// other height passes through.
pub fn blake2b_shift_at(params: &ChainParams, height: u32, bits: CompactTarget) -> CompactTarget {
    match params.blake2b {
        Some(b) if b.fork_height == height => {
            shift_compact_target(bits, b.target_shift, params.pow_limit)
        }
        _ => bits,
    }
}

/// `bits << shift` in Core's compact form (`arith_uint256::SetCompact`, `<<=`,
/// `GetCompact`), or the pow limit's compact when the result would pass it.
fn shift_compact_target(bits: CompactTarget, shift: u8, pow_limit: Target) -> CompactTarget {
    let raw = bits.to_consensus();
    let mut exp = i64::from(raw >> 24);
    let mut mant = u64::from(raw & 0x007f_ffff);
    mant <<= u32::from(shift % 8);
    exp += i64::from(shift / 8);
    while mant > 0x00ff_ffff {
        mant >>= 8;
        exp += 1;
    }
    if mant & 0x0080_0000 != 0 {
        mant >>= 8;
        exp += 1;
    }
    let shifted = CompactTarget::from_consensus(((exp as u32) << 24) | mant as u32);
    if Target::from_compact(shifted) > pow_limit {
        pow_limit.to_compact_lossy()
    } else {
        shifted
    }
}

/// BIP34/66/65 `nVersion` floors, the v2-header rules and the 2-hour
/// future-time cap (wall clock).
///
/// Core `ContextualCheckBlockHeader`. Assemble uses this instead of a second
/// [`validate_header`] (MTP walk + header rehash).
pub(crate) fn check_header_version_and_future_time(
    params: &ChainParams,
    height: Height,
    header: &Header,
) -> Result<(), ConsensusError> {
    const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;
    check_header_v2_rules(params, height, header)?;
    let now = crate::clock::current_now();
    if u64::from(header.time) > now.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        return Err(ConsensusError::BadHeader("timestamp too far in future"));
    }
    let ver = header.version.to_consensus();
    if (params.bip34_active_at(height.0) && ver < 2)
        || (params.bip66_active_at(height.0) && ver < 3)
        || (params.bip65_active_at(height.0) && ver < 4)
    {
        return Err(ConsensusError::BadVersion(ver));
    }
    Ok(())
}

/// Median timestamp of up to 11 blocks ending at `height` (inclusive).
///
/// **Confirm load path:** BIP68/BIP113 run during multi-block assemble while
/// mid-batch heights are not yet in `confirmed[]`. Prefer the durable confirmed
/// chain, then load-stage header plans (same hybrid as [`crate::confirm_run`]
/// header MTP). Heights still above tip with no plan are retryable load
/// incomplete — not permanent `BadPrev` (that silently split batches to n=1).
pub fn median_time_past(query: &Query, height: Height) -> Result<u32, ConsensusError> {
    if let Some((n, buf)) = query.store().mtp_times_at(height) {
        return Ok(median_time_past_times(&buf[..n as usize]));
    }
    let mut times = Vec::with_capacity(11);
    let start = height.0.saturating_sub(10);
    let tip = query.tip_height().map(|h| h.0).unwrap_or(0);
    for h in start..=height.0 {
        if let Some((_fk, rec)) = query.header_at_height(Height(h))? {
            times.push(rec.timestamp);
            continue;
        }
        if let Some(plan) = query.confirm_parent_cache().get_header_plan(h) {
            times.push(plan.header_rec.timestamp);
            continue;
        }
        if h > tip {
            return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "confirm: load incomplete (parent header plan missing above tip)",
            )));
        }
        return Err(ConsensusError::BadPrev);
    }
    Ok(median_time_past_times(&times))
}

/// MTP from the confirmed chain only (write structural). Tip-ahead heights
/// must be carried on [`crate::confirm_run`] `Prepared::prev_mtp`.
pub fn median_time_past_store(query: &Query, height: Height) -> Result<u32, ConsensusError> {
    if let Some((n, buf)) = query.store().mtp_times_at(height) {
        return Ok(median_time_past_times(&buf[..n as usize]));
    }
    let mut times = Vec::with_capacity(11);
    let start = height.0.saturating_sub(10);
    for h in start..=height.0 {
        if let Some((_fk, rec)) = query.header_at_height(Height(h))? {
            times.push(rec.timestamp);
            continue;
        }
        return Err(ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
            "confirm: write MTP missing confirmed header (carry prev_mtp)",
        )));
    }
    Ok(median_time_past_times(&times))
}

pub use rbitcoin_primitives::median_time_past_times;

/// Expected `nBits` for a new header at `height`.
///
/// `header_time` is the candidate block's timestamp (Core `pblock->GetBlockTime()`).
pub fn expected_next_bits(
    query: &Query,
    params: &ChainParams,
    height: Height,
    header_time: u32,
) -> Result<CompactTarget, ConsensusError> {
    if height.0 == 0 {
        let g = crate::params::genesis_block(params);
        return Ok(g.header.bits);
    }

    let prev_height = Height(height.0 - 1);
    let (_fk, prev_rec) = query
        .header_at_height(prev_height)?
        .ok_or(ConsensusError::BadPrev)?;
    let prev_bits = CompactTarget::from_consensus(prev_rec.bits);
    let period_first = period_first(query, params, height.0)?;
    next_work_bits(
        params,
        height.0,
        prev_bits,
        prev_rec.timestamp,
        header_time,
        period_first,
        |h| {
            header_bits_at(query, Height(h))
                .ok()
                .map(CompactTarget::from_consensus)
        },
    )
    .ok_or(ConsensusError::BadPrev)
}

/// The header at `height - interval` of a retarget boundary: its time spans
/// the period, and under BIP94 its `nBits` is the retarget base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodFirst {
    pub time: u32,
    pub bits: CompactTarget,
}

/// Difficulty for the header at `height`, from the parent and the period start,
/// with the one-off BLAKE2b fork shift applied at the fork height.
///
/// `period_first` is the header at `height - interval` when `height` is a
/// retarget boundary. `bits_at` supplies earlier `nBits` for the testnet
/// min-difficulty walk. `None` means an ancestor is missing.
pub fn next_work_bits(
    params: &ChainParams,
    height: u32,
    prev_bits: CompactTarget,
    prev_time: u32,
    header_time: u32,
    period_first: Option<PeriodFirst>,
    mut bits_at: impl FnMut(u32) -> Option<CompactTarget>,
) -> Option<CompactTarget> {
    if height == 0 {
        return None;
    }
    let interval = params.difficulty_adjustment_interval();
    let bits = if interval == 0 || !height.is_multiple_of(interval) {
        min_diff_bits(
            params,
            height,
            prev_bits,
            prev_time,
            header_time,
            &mut bits_at,
        )?
    } else if params.no_pow_retargeting() {
        prev_bits
    } else {
        retarget_bits(params, prev_bits, prev_time, period_first?)
    };
    Some(blake2b_shift_at(params, height, bits))
}

/// Retarget at a period boundary from the parent and the period's first header
/// (Core `CalculateNextWorkRequired`).
pub fn retarget_bits(
    params: &ChainParams,
    prev_bits: CompactTarget,
    prev_time: u32,
    first: PeriodFirst,
) -> CompactTarget {
    let timespan = u64::from(prev_time.saturating_sub(first.time));
    // BIP94: the period's first block never took the min-difficulty exception,
    // so its bits are the real difficulty; the parent's may be the pow limit.
    let base = if params.enforce_bip94() {
        first.bits
    } else {
        prev_bits
    };
    CompactTarget::from_next_work_required(base, timespan, &params.btc)
}

fn period_first(
    query: &Query,
    params: &ChainParams,
    height: u32,
) -> Result<Option<PeriodFirst>, ConsensusError> {
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.is_multiple_of(interval) || params.no_pow_retargeting() {
        return Ok(None);
    }
    let (_fk, first_rec) = query
        .header_at_height(Height(height - interval))?
        .ok_or(ConsensusError::BadHeader("missing retarget first header"))?;
    Ok(Some(PeriodFirst {
        time: first_rec.timestamp,
        bits: CompactTarget::from_consensus(first_rec.bits),
    }))
}

fn min_diff_bits(
    params: &ChainParams,
    height: u32,
    prev_bits: CompactTarget,
    prev_time: u32,
    header_time: u32,
    bits_at: &mut impl FnMut(u32) -> Option<CompactTarget>,
) -> Option<CompactTarget> {
    if !params.allow_min_difficulty_blocks() {
        return Some(prev_bits);
    }
    let limit = params.pow_limit.to_compact_lossy();
    let spacing = params.btc.pow_target_spacing;
    if u64::from(header_time) > u64::from(prev_time).saturating_add(spacing.saturating_mul(2)) {
        return Some(limit);
    }
    let interval = params.difficulty_adjustment_interval();
    let mut h = height - 1;
    let mut bits = prev_bits;
    while interval > 0 && !h.is_multiple_of(interval) && bits == limit {
        if h == 0 {
            break;
        }
        h -= 1;
        bits = bits_at(h)?;
    }
    Some(bits)
}

fn header_bits_at(query: &Query, height: Height) -> Result<u32, ConsensusError> {
    if let Some((_fk, rec)) = query.header_at_height(height)? {
        return Ok(rec.bits);
    }
    if let Some(plan) = query.confirm_parent_cache().get_header_plan(height.0) {
        return Ok(plan.header_rec.bits);
    }
    Err(ConsensusError::BadPrev)
}

#[cfg(test)]
mod median_time_past_tests {
    use super::*;
    use bitcoin::block::Version;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_query::{Query, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn pow_hash_meets_target_meet_miss_and_limit() {
        let rt = ChainParams::regtest();
        let easy = CompactTarget::from_consensus(0x207f_ffff);
        pow_hash_meets_target([0u8; 32], easy, rt.pow_limit).unwrap();
        let mainnet_bits = CompactTarget::from_consensus(0x1d00_ffff);
        let miss = pow_hash_meets_target([0xff; 32], mainnet_bits, Target::MAX_ATTAINABLE_MAINNET)
            .unwrap_err();
        assert!(matches!(miss, ConsensusError::InvalidPow), "{miss:?}");
        let err =
            pow_hash_meets_target([0u8; 32], easy, ChainParams::mainnet().pow_limit).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadHeader(s) if s.contains("pow limit")),
            "{err:?}"
        );
    }

    #[test]
    fn mtp_times_picks_middle_of_sorted() {
        assert_eq!(median_time_past_times(&[3, 1, 2]), 2);
        assert_eq!(median_time_past_times(&[10]), 10);
        // Even length: Core takes sorted[len/2] (upper middle).
        assert_eq!(median_time_past_times(&[1, 2, 3, 4]), 3);
    }

    fn temp_q() -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-hdr-mtp-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        (dir, q)
    }

    /// Write-gate-safe synthetic coinbase: non-null `prev_fk` must commit `parent_hash`.
    fn coinbase(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
        let version = 1;
        let timestamp = 1_000 + h * 10;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[4] = 0xcd;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
            v2: None,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
            tx: TxRecord {
                txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: [0u8; 32],
                create_fk: Fk::NULL,
                prev_index: u32::MAX,
                sequence: u32::MAX,
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50, vec![0x51])],
        };
        (header, ta)
    }

    #[test]
    fn mtp_from_confirmed_chain_and_missing_above_tip() {
        let (dir, q) = temp_q();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..3u32 {
            let (hdr, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(hdr.hash);
            prev = q.connect_block(Height(h), &hdr, &[ta]).unwrap();
        }
        let mtp = median_time_past(&q, Height(2)).unwrap();
        // times: 1000, 1010, 1020 → middle 1010
        assert_eq!(mtp, 1010);
        let (n, buf) = q
            .store()
            .mtp_times_at(Height(2))
            .expect("ring covers confirmed tip");
        assert_eq!(n, 3);
        assert_eq!(median_time_past_times(&buf[..3]), 1010);

        // Height above tip with no plan → incomplete load error (not BadPrev).
        let err = median_time_past(&q, Height(5)).unwrap_err();
        assert!(
            matches!(err, ConsensusError::Store(_)) || matches!(err, ConsensusError::BadPrev),
            "got {err:?}"
        );

        // expected_next_bits: height 0 + regtest no-retarget.
        let params = ChainParams::regtest();
        let gbits = expected_next_bits(&q, &params, Height(0), 0).unwrap();
        assert_eq!(gbits, crate::params::genesis_block(&params).header.bits);
        let b1 = expected_next_bits(&q, &params, Height(1), 0).unwrap();
        let (_fk, rec0) = q.header_at_height(Height(0)).unwrap().unwrap();
        assert_eq!(b1.to_consensus(), rec0.bits);

        // Bad prev header height.
        assert!(expected_next_bits(&q, &params, Height(99), 0).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sequential_tip_mtp_matches_ring_and_survives_pop() {
        let (dir, q) = temp_q();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut times = Vec::new();
        for h in 0..12u32 {
            let (hdr, ta) = coinbase(h, prev, parent_hash);
            times.push(hdr.timestamp);
            parent_hash = Some(hdr.hash);
            prev = q.connect_block(Height(h), &hdr, &[ta]).unwrap();
        }
        let want11 = median_time_past_times(&times[1..]);
        assert_eq!(median_time_past_store(&q, Height(11)).unwrap(), want11);
        assert_eq!(median_time_past(&q, Height(11)).unwrap(), want11);
        let (n, buf) = q.store().mtp_times_at(Height(11)).expect("ring at tip");
        assert_eq!(n, 11);
        assert_eq!(median_time_past_times(&buf[..11]), want11);
        assert!(
            q.store().mtp_times_at(Height(5)).is_none(),
            "historical MTP is not the tip ring"
        );
        assert_eq!(
            median_time_past_store(&q, Height(5)).unwrap(),
            median_time_past_times(&times[0..=5])
        );

        q.disconnect_tip().unwrap();
        let want10 = median_time_past_times(&times[0..=10]);
        assert_eq!(median_time_past_store(&q, Height(10)).unwrap(), want10);
        let (n, buf) = q
            .store()
            .mtp_times_at(Height(10))
            .expect("ring rebuilt after pop");
        assert_eq!(median_time_past_times(&buf[..n as usize]), want10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_header_genesis_and_bad_prev() {
        let (dir, q) = temp_q();
        let params = ChainParams::regtest();
        let g = crate::params::genesis_block(&params);
        // Wrong genesis hash at height 0.
        let mut bad = g.header;
        bad.nonce ^= 1;
        let err = validate_header(&q, &params, Height(0), &bad).unwrap_err();
        assert!(matches!(err, ConsensusError::BadHeader(_)), "{err:?}");

        // Synthetic tip for prev linkage (child hash commits to parent).
        let (h0, ta0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let (h1, ta1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();

        // Header with wrong prev hash at height 1.
        let mut hdr = g.header;
        hdr.prev_blockhash = bitcoin::BlockHash::from_byte_array([0xee; 32]);
        hdr.time = 2_000;
        hdr.bits = bitcoin::CompactTarget::from_consensus(0x207fffff);
        let err = validate_header(&q, &params, Height(1), &hdr).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::BadPrev
                    | ConsensusError::BadHeader(_)
                    | ConsensusError::BadVersion(_)
            ),
            "{err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn testnet_min_difficulty_after_20_minute_gap() {
        let (dir, q) = temp_q();
        let params = ChainParams::testnet();
        assert!(params.allow_min_difficulty_blocks());
        let (h0, ta0) = coinbase(0, Fk::NULL, None);
        let prev_fk = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let limit = params.pow_limit.to_compact_lossy();
        assert_ne!(CompactTarget::from_consensus(h0.bits), limit);

        let spacing = params.btc.pow_target_spacing as u32;
        let gap =
            expected_next_bits(&q, &params, Height(1), h0.timestamp + 2 * spacing + 1).unwrap();
        assert_eq!(gap, limit);
        let eq_boundary =
            expected_next_bits(&q, &params, Height(1), h0.timestamp + 2 * spacing).unwrap();
        assert_eq!(eq_boundary.to_consensus(), h0.bits);

        let (mut h1, ta1) = coinbase(1, prev_fk, Some(h0.hash));
        h1.timestamp = h0.timestamp + 2 * spacing + 1;
        h1.bits = limit.to_consensus();
        h1.hash = rbitcoin_store::block_header_hash(
            h1.version,
            &h0.hash,
            &h1.merkle_root,
            h1.timestamp,
            h1.bits,
            h1.nonce,
        );
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();
        let walked = expected_next_bits(&q, &params, Height(2), h1.timestamp + 100).unwrap();
        assert_eq!(walked.to_consensus(), h0.bits);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn knots_v2_header() -> Header {
        // Bitcoin Knots `block_header_v2.json`, vector `profile_0_time_offset` (height 840000).
        let raw = rbitcoin_primitives::hex_decode("000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab").unwrap();
        bitcoin::consensus::deserialize(&raw).unwrap()
    }

    #[test]
    fn v2_header_rules_follow_the_fork_height() {
        let mut params = ChainParams::testnet4_blake2b();
        params.blake2b = Some(crate::params::Blake2bParams {
            fork_height: 840_000,
            ..crate::params::TESTNET4_BLAKE2B
        });
        let v2 = knots_v2_header();
        let mut classic = v2;
        classic.v2 = None;
        let reason = |r: Result<(), ConsensusError>| match r {
            Err(ConsensusError::BadHeader(m)) => m,
            other => panic!("expected BadHeader, got {other:?}"),
        };
        assert!(check_header_v2_rules(&params, Height(840_000), &v2).is_ok());
        assert!(check_header_v2_rules(&params, Height(839_999), &classic).is_ok());
        assert_eq!(
            reason(check_header_v2_rules(&params, Height(839_999), &v2)),
            "bad-version-sha256d"
        );
        assert_eq!(
            reason(check_header_v2_rules(&params, Height(840_000), &classic)),
            "bad-version-blake2b"
        );
        assert_eq!(
            reason(check_header_v2_rules(&params, Height(840_001), &v2)),
            "bad-header-height"
        );
        let mut high = v2;
        high.v2.as_mut().unwrap().flags |= 0x40;
        assert_eq!(
            reason(check_header_v2_rules(&params, Height(840_000), &high)),
            "bad-flags-highbits"
        );
        // A SHA256d chain never takes a v2 header and never demands one.
        let t4 = ChainParams::testnet4();
        assert_eq!(
            reason(check_header_v2_rules(&t4, Height(840_000), &v2)),
            "bad-version-sha256d"
        );
        assert!(check_header_v2_rules(&t4, Height(840_000), &classic).is_ok());
    }

    #[test]
    fn blake2b_target_shift_matches_core_compact_math() {
        let limit = Target::MAX_ATTAINABLE_TESTNET;
        let sh = |bits: u32, shift: u8| {
            shift_compact_target(CompactTarget::from_consensus(bits), shift, limit).to_consensus()
        };
        // Pinned against arith_uint256 SetCompact / <<= / GetCompact.
        assert_eq!(sh(0x1a00_82a5, 20), 0x1c08_2a50);
        assert_eq!(sh(0x1702_905c, 22), 0x1a00_a417);
        assert_eq!(sh(0x1a12_3456, 3), 0x1b00_91a2, "sign-bit renormalisation");
        assert_eq!(sh(0x1a00_ffff, 20), 0x1c0f_fff0);
        for at_or_over in [0x1d00_ffffu32, 0x1c00_ffff, 0x1b00_ffff] {
            assert_eq!(sh(at_or_over, 20), 0x1d00_ffff, "clamped to the pow limit");
        }
        // Only the fork height is shifted.
        let t4b = ChainParams::testnet4_blake2b();
        let full = CompactTarget::from_consensus(0x1a00_82a5);
        assert_eq!(
            blake2b_shift_at(&t4b, 150_308, full).to_consensus(),
            0x1c08_2a50
        );
        assert_eq!(blake2b_shift_at(&t4b, 150_307, full), full);
        assert_eq!(blake2b_shift_at(&t4b, 150_309, full), full);
        assert_eq!(
            blake2b_shift_at(&ChainParams::testnet4(), 150_308, full),
            full
        );
        assert_eq!(
            blake2b_shift_at(
                &ChainParams::mainnet_blake2b(),
                961_640,
                CompactTarget::from_consensus(0x1702_905c)
            )
            .to_consensus(),
            0x1a00_a417
        );
    }

    #[test]
    fn testnet4_fork_block_bits_are_the_shifted_minimum() {
        // Knots testnet4 150,307 → 150,308: 81,000 s gap takes the 20-minute
        // exception, then the shift clamps at the limit. Times from the chain.
        let t4b = ChainParams::testnet4_blake2b();
        let limit = t4b.pow_limit.to_compact_lossy();
        let bits = next_work_bits(
            &t4b,
            150_308,
            limit,
            1_788_049_475,
            1_788_130_417,
            None,
            |_| Some(limit),
        )
        .unwrap();
        assert_eq!(bits.to_consensus(), 0x1d00_ffff);
    }

    #[test]
    fn bip94_timewarp_floor_on_retarget_block() {
        let t4 = ChainParams::testnet4();
        let interval = t4.difficulty_adjustment_interval();
        let bits = t4.pow_limit.to_compact_lossy();
        let parent_time = 1_000_000u32;
        let header_at = |time: u32| Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce: 0,
            v2: None,
        };
        let check = |params: &ChainParams, height: u32, time: u32| {
            validate_header_on_parent(
                params,
                Height(height),
                &header_at(time),
                parent_time,
                1,
                bits,
            )
        };
        let too_early = parent_time - MAX_TIMEWARP - 1;
        assert!(matches!(
            check(&t4, interval, too_early),
            Err(ConsensusError::BadHeader(m)) if m.contains("timewarp")
        ));
        // At the floor, and off the boundary, the header reaches the pow check.
        assert!(matches!(
            check(&t4, interval, parent_time - MAX_TIMEWARP),
            Err(ConsensusError::InvalidPow)
        ));
        assert!(matches!(
            check(&t4, interval + 1, too_early),
            Err(ConsensusError::InvalidPow)
        ));
        assert!(matches!(
            check(&ChainParams::testnet(), interval, too_early),
            Err(ConsensusError::InvalidPow)
        ));
    }

    #[test]
    fn bip94_retargets_from_period_first_bits() {
        let t4 = ChainParams::testnet4();
        let t3 = ChainParams::testnet();
        let interval = t4.difficulty_adjustment_interval();
        let limit = t4.pow_limit.to_compact_lossy();
        let full = CompactTarget::from_consensus(0x1d00_eeee);
        let spacing = t4.btc.pow_target_spacing as u32;
        let first = PeriodFirst {
            time: 1_000_000,
            bits: full,
        };
        // The parent took the 20-minute exception; the period ran on schedule.
        let prev_time = first.time + spacing * (interval - 1);
        let args = |params: &ChainParams| {
            next_work_bits(
                params,
                interval,
                limit,
                prev_time,
                prev_time + spacing,
                Some(first),
                |_| None,
            )
            .unwrap()
        };
        let timespan = u64::from(prev_time - first.time);
        assert_eq!(
            args(&t4),
            CompactTarget::from_next_work_required(full, timespan, &t4.btc)
        );
        assert_eq!(
            args(&t3),
            CompactTarget::from_next_work_required(limit, timespan, &t3.btc)
        );
        assert_ne!(args(&t4), args(&t3));
        assert!(t4.enforce_bip94());
        assert!(!t3.enforce_bip94());
        assert!(!ChainParams::mainnet().enforce_bip94());
    }

    #[test]
    fn next_work_bits_walks_back_past_min_difficulty() {
        let params = ChainParams::testnet();
        let limit = params.pow_limit.to_compact_lossy();
        let full = CompactTarget::from_consensus(0x1d00_eeee);
        assert_ne!(full, limit);
        let prev_time = 1_000_000u32;
        let walked = next_work_bits(
            &params,
            3,
            limit,
            prev_time,
            prev_time + 100,
            None,
            |h| match h {
                1 => Some(limit),
                0 => Some(full),
                _ => None,
            },
        )
        .unwrap();
        assert_eq!(walked, full);

        let spacing = params.btc.pow_target_spacing;
        let gap = next_work_bits(
            &params,
            3,
            full,
            prev_time,
            prev_time + (spacing as u32) * 2 + 1,
            None,
            |_| None,
        )
        .unwrap();
        assert_eq!(gap, limit);

        let mainnet = ChainParams::mainnet();
        let kept = next_work_bits(
            &mainnet,
            3,
            full,
            prev_time,
            prev_time + (spacing as u32) * 2 + 1,
            None,
            |_| Some(limit),
        )
        .unwrap();
        assert_eq!(kept, full);
    }

    #[test]
    fn check_header_version_and_future_time_regtest() {
        let params = ChainParams::regtest();
        let mut h = crate::params::genesis_block(&params).header;
        h.version = Version::from_consensus(1);
        crate::clock::with_now(1_700_000_000, || {
            h.time = 1_700_000_000;
            let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
            h.version = Version::from_consensus(4);
            h.time = 1_700_000_000 + 3 * 60 * 60;
            let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
            assert!(
                matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
                "{err:?}"
            );
            h.time = 1_700_000_000 + 60 * 60;
            check_header_version_and_future_time(&params, Height(1), &h).unwrap();
        });
    }

    #[test]
    fn h8_timestamp_exactly_two_hours_accepts_plus_one_rejects() {
        let params = ChainParams::regtest();
        let mut h = crate::params::genesis_block(&params).header;
        h.version = Version::from_consensus(4);
        crate::clock::with_now(1_700_000_000, || {
            h.time = 1_700_000_000 + 2 * 60 * 60;
            check_header_version_and_future_time(&params, Height(1), &h).unwrap();
            h.time = 1_700_000_000 + 2 * 60 * 60 + 1;
            let err = check_header_version_and_future_time(&params, Height(1), &h).unwrap_err();
            assert!(
                matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
                "{err:?}"
            );
        });
    }

    #[test]
    fn h9_version_floors_at_bip34_66_65() {
        let rt = ChainParams::regtest();
        let mut h = crate::params::genesis_block(&rt).header;
        crate::clock::with_now(1_700_000_000, || {
            h.time = 1_700_000_000;
            h.version = Version::from_consensus(3);
            let err = check_header_version_and_future_time(&rt, Height(1), &h).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
            h.version = Version::from_consensus(4);
            check_header_version_and_future_time(&rt, Height(1), &h).unwrap();
        });

        let main = ChainParams::mainnet();
        let mut mh = crate::params::genesis_block(&main).header;
        crate::clock::with_now(1_700_000_000, || {
            mh.time = 1_700_000_000;
            let bip34 = main.btc.bip34_height;
            mh.version = Version::from_consensus(1);
            check_header_version_and_future_time(&main, Height(bip34 - 1), &mh).unwrap();
            let err = check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(1)), "{err:?}");
            mh.version = Version::from_consensus(2);
            check_header_version_and_future_time(&main, Height(bip34), &mh).unwrap();

            let bip66 = main.btc.bip66_height;
            mh.version = Version::from_consensus(2);
            let err = check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(2)), "{err:?}");
            mh.version = Version::from_consensus(3);
            check_header_version_and_future_time(&main, Height(bip66), &mh).unwrap();

            let bip65 = main.btc.bip65_height;
            mh.version = Version::from_consensus(3);
            let err = check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap_err();
            assert!(matches!(err, ConsensusError::BadVersion(3)), "{err:?}");
            mh.version = Version::from_consensus(4);
            check_header_version_and_future_time(&main, Height(bip65), &mh).unwrap();
        });
    }
}
