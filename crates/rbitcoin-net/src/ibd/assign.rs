//! Getdata assign for the **unified body-queue → lookup → load → scripts → write** path.
//!
//! Policy (operator-facing):
//! - **Tip batch** (tip+1 .. tip+[`TIP_HOLE_MAX`]=32, one confirm run): always
//!   request missing hashes (even if soft body-queue depth is over free floor).
//!   Multi-peer race up to [`TIP_HOLE_MAX_PEERS`] **on tip+1 only** when the
//!   body queue meets any of: 1/4 of the confirm-time block window, 1/4 of
//!   the configured assign-stop (default 1 GiB), or
//!   [`rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS`] bodies. Fullness is the
//!   queue's total blocks and bytes; gaps count. Below all three the gap is
//!   the frontier: one owner, and densify continues. Ranked by expected
//!   drain time (`(queue+1)/bps`), not queue count. Later contiguous holes
//!   in that gap get one racer until the prefix is in hand. An owner
//!   with other inflight hashes still has densify in the peer FIFO — drop them
//!   from this hash (getdata cannot be cancelled) and race a peer that can
//!   start the hole. Confirm is frozen until tip+1 is claim-ready.
//!   When that prefix is in hand, at most one extra racer on the **first**
//!   later gap in the 32-window, and only if that owner is missing, aged, or
//!   ≤ pack-median/4.
//! - **Densify** (tip+1 outward, closest first): fill missing heights up to
//!   [`CONTIG_DENSIFY_AHEAD`]. Two soft assign limits (no hysteresis):
//!   - BQ payload **≤ ~100 MiB** → usual densify ahead to the height horizon
//!   - BQ payload **> ~100 MiB** → only heights confirm will consume in the
//!     next **~1 min** at current tip rate ([`rbitcoin_query::soft_densify_band_hi`])
//!   - BQ payload **≥ assign-stop** (default 1 GiB) → holes only within the
//!     ~1 min tip-rate window **and** not past fetched_hi (do not grow past
//!     fetched; do not densify far holes outside the window)
//!   - While a quarter-full tip hole is open: **no new densify** (cap 0) so
//!     peer getdata queues can drain for tip+1. A thinner queue is the
//!     frontier and densify keeps filling ahead.
//! - Never request beyond densify horizon; events refuse far bodies too.
//! - One body-queue copy per height (receive path drops duplicates).

use super::assign_plan::densify_slots_for_peer;
use super::dial::{
    median_u64, relative_slow_pick, RelativeSlowSample, RELATIVE_SLOW_CLUSTER_SPREAD,
};
use super::peer_io::{ibd_mono_ms, PeerCmd, PeerSlot};
use super::state::{self, IbdWorkState};
use super::status::LoopStats;
use super::{
    IbdConfig, CONTIG_DENSIFY_AHEAD, FAR_SCAN_BUDGET, PENDING_STALE, PRE_HOLE_MAX_PEERS,
    TIP_HOLE_MAX, TIP_HOLE_MAX_PEERS,
};
use crate::chain::ChainHub;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// After this long with no confirm progress and nothing useful to fetch, stop getdata.
pub(crate) const STUCK_GATE_AFTER: Duration = Duration::from_secs(30);

/// True when confirm cannot advance and there is no valid body still worth fetching.
pub(crate) fn download_gate_closed(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let Some(since) = st.confirm_stuck_since else {
        return false;
    };
    if since.elapsed() < STUCK_GATE_AFTER {
        return false;
    }
    !need_any_valid_body_download(st, hub)
}

fn need_any_valid_body_download(st: &IbdWorkState, hub: &ChainHub) -> bool {
    let tip = hub.tip_height().unwrap_or(0);
    let path_lo = if hub.tip_height().is_none() {
        0u32
    } else {
        tip.saturating_add(1)
    };
    let occupant_dead = st
        .height_to_hash
        .get(&path_lo)
        .is_some_and(|h| need_body_dead(st, h));
    if need_path_lo_alt(st, hub, path_lo) {
        return true;
    }
    if occupant_dead {
        return false;
    }
    if need_contig_ahead(st, hub, path_lo) {
        return true;
    }
    need_reorg_getdata(st, hub)
}

fn need_body_dead(st: &IbdWorkState, h: &BlockHash) -> bool {
    st.reorg.invalid.contains(h.to_byte_array()) || st.body.is_rejected(h)
}

fn need_body_in_hand(st: &IbdWorkState, hub: &ChainHub, h: &BlockHash) -> bool {
    hub.has_block(h)
        || st.body.is_known_archived(h)
        || hub.query.block_queue_has_hash(&h.to_byte_array())
}

fn need_path_lo_alt(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
    for (&h, &ht) in &st.hash_height {
        if ht != path_lo {
            continue;
        }
        if need_body_dead(st, &h) {
            continue;
        }
        if need_body_in_hand(st, hub, &h) {
            continue;
        }
        return true;
    }
    false
}

fn need_contig_ahead(st: &IbdWorkState, hub: &ChainHub, path_lo: u32) -> bool {
    for ht in path_lo..=path_lo.saturating_add(CONTIG_DENSIFY_AHEAD) {
        let Some(&h) = st.height_to_hash.get(&ht) else {
            break;
        };
        if need_body_dead(st, &h) {
            continue;
        }
        if hub.has_block(&h) {
            continue;
        }
        if st.body.is_known_archived(&h) || hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        return true;
    }
    false
}

fn need_reorg_getdata(st: &IbdWorkState, hub: &ChainHub) -> bool {
    for h in st.reorg.need_getdata() {
        if need_body_dead(st, &h) {
            continue;
        }
        if hub.has_block(&h) || hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        return true;
    }
    false
}

/// How much assign work to do this call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssignDepth {
    /// Tip-batch multi-peer only (BQ soft window covered / no densify room).
    Critical,
    /// Tip batch + densify (gap always; frontier when soft depth allows).
    Full,
}

/// Drop `hash` from global inflight and every peer's in_flight set.
pub(crate) fn clear_hash_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hash: BlockHash,
) {
    inflight.remove(&hash);
    for s in slots.iter_mut() {
        s.in_flight.remove(&hash);
    }
}

/// Free peer/global slots for hashes already on the confirmed tip (RAM set).
pub(crate) fn prune_satisfied_inflight(
    slots: &mut [PeerSlot],
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hub: &ChainHub,
) {
    inflight.retain(|h, _| !hub.has_block(h));
    for s in slots.iter_mut() {
        s.in_flight.retain(|h| !hub.has_block(h));
    }
}

/// Drop getdata that cannot feed the work path or a live awaiting-reorg gather.
///
/// Speculative `explore_need` is not kept: assign re-issues it while remainder
/// is live. Off-path leftovers otherwise sat in inflight forever (mainnet
/// 08:16:23 / 04:14).
pub(crate) fn prune_off_path_inflight(st: &mut IbdWorkState) {
    let drop: Vec<BlockHash> = st
        .inflight
        .keys()
        .copied()
        .filter(|h| {
            if st.ordered_set.contains(h) {
                return false;
            }
            if let Some(&ht) = st.hash_height.get(h) {
                if st.is_on_path(h, ht) {
                    return false;
                }
            }
            true
        })
        .collect();
    for h in drop {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, h);
    }
}

/// Record `peer` as requesting `hash` (tip-hole / park race may accumulate peers).
pub(crate) fn inflight_add_peer(
    inflight: &mut HashMap<BlockHash, state::InflightReq>,
    hash: BlockHash,
    peer: usize,
) {
    inflight
        .entry(hash)
        .or_insert_with(|| state::InflightReq::new(peer))
        .add_peer(peer);
}

/// True when soft BQ confirm window is already covered and getdata inflight
/// is low → Critical (tip race only, skip densify walk).
pub(crate) fn bq_pipeline_saturated(inflight_len: usize, bq_confirm_window_covered: bool) -> bool {
    inflight_len < 16 && bq_confirm_window_covered
}

/// Assign getdata for the body-queue pipeline.
///
/// `tip_rate_blocks_per_s`: tip confirm rate for the soft confirm-time window
/// when BQ payload is over [`rbitcoin_query::BQ_SOFT_FREE_BYTES`].
pub(crate) fn assign_work_ordered(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    loop_stats: &LoopStats,
    depth: AssignDepth,
    tip_rate_blocks_per_s: Option<f64>,
) {
    let t0 = Instant::now();
    let mut issued = 0u64;
    let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
    if alive.is_empty() {
        return;
    }

    let (bq_stop, bq_bytes, bq_count) = hub.query.block_queue_stats();
    st.intake_stop = bq_stop;
    st.intake_queued = bq_bytes;

    if download_gate_closed(st, hub) {
        static GATE_LOG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = GATE_LOG.fetch_add(1, Ordering::Relaxed) + 1;
        if n <= 3 || n.is_multiple_of(50) {
            rbitcoin_log::warn!(
                "ibd: download gate closed (confirm stuck {:?}, no valid body to fetch, n={n})",
                st.confirm_stuck_since
                    .map(|t| t.elapsed())
                    .unwrap_or_default()
            );
        }
        finish_assign(loop_stats, t0, 0);
        return;
    }

    prune_satisfied_inflight(&mut st.slots, &mut st.inflight, hub);
    prune_off_path_inflight(st);

    let _ = super::reorg::consider_disconnected_heavier(st, hub);

    let tip = hub.tip_height().unwrap_or(0);
    let path_lo = if hub.tip_height().is_none() {
        0u32
    } else {
        tip.saturating_add(1)
    };
    let tip_batch_hi = path_lo.saturating_add(TIP_HOLE_MAX.saturating_sub(1) as u32);

    // Stale pending in tip batch only → re-get (don't thrash far pending).
    let tip_expired = st.body.expire_stale_pending_if(PENDING_STALE, |h| {
        st.hash_height
            .get(h)
            .is_some_and(|&ht| ht >= path_lo && ht <= tip_batch_hi)
    });
    for h in tip_expired {
        clear_hash_inflight(&mut st.slots, &mut st.inflight, h);
    }

    let tip_holes = contiguous_tip_holes(st, hub, TIP_HOLE_MAX);
    let ahead_n = u32::try_from(bq_count).unwrap_or(u32::MAX);
    let race_tip = !tip_holes.is_empty()
        && rbitcoin_query::soft_ahead_quarter_full(
            ahead_n,
            bq_bytes,
            tip_rate_blocks_per_s,
            bq_stop,
        );
    if race_tip {
        issued += cover_tip_batch_holes(st, hub, cfg, &alive, &tip_holes);
    }
    if tip_holes.is_empty() {
        issued += cover_first_pre_hole(st, hub, cfg, &alive);
    }
    issued += assign_reorg_need(st, hub, cfg, &alive);

    if matches!(depth, AssignDepth::Critical) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    assign_densify(
        st,
        hub,
        cfg,
        &alive,
        DensifyCtx {
            loop_stats,
            t0,
            issued,
            path_lo,
            tip_batch_hi,
            race_tip,
            tip_rate_blocks_per_s,
        },
    );
}

fn assign_reorg_need(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
) -> u64 {
    let reorg_need = st.reorg.need_getdata();
    if reorg_need.is_empty() {
        return 0;
    }
    use bitcoin::hashes::Hash as _;
    let reserve = reorg_need.len().min(8);
    let mut room = cfg.window.saturating_sub(st.inflight.len()).max(reserve);
    let mut peer_i = st.assign_rot;
    let mut issued = 0u64;
    for h in reorg_need {
        if room == 0 {
            break;
        }
        if st.inflight.contains_key(&h) {
            continue;
        }
        if hub.has_block(&h) {
            continue;
        }
        if hub.query.block_queue_has_hash(&h.to_byte_array()) {
            continue;
        }
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, st.hash_height.get(&h).copied());
        if st.body.skip_download(hub, &h) {
            continue;
        }
        for _ in 0..alive.len() {
            let pid = alive[peer_i % alive.len()];
            peer_i += 1;
            if !peer_has_slot(st, pid, cfg.per_peer) {
                continue;
            }
            if issue_one(st, pid, h, &mut room, &mut issued) {
                break;
            }
        }
    }
    st.assign_rot = peer_i;
    issued
}

struct DensifyCtx<'a> {
    loop_stats: &'a LoopStats,
    t0: Instant,
    issued: u64,
    path_lo: u32,
    tip_batch_hi: u32,
    race_tip: bool,
    tip_rate_blocks_per_s: Option<f64>,
}

fn assign_densify(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    ctx: DensifyCtx<'_>,
) {
    let DensifyCtx {
        loop_stats,
        t0,
        mut issued,
        path_lo,
        tip_batch_hi,
        race_tip,
        tip_rate_blocks_per_s,
    } = ctx;
    let tip_hole = race_tip;
    let (pack_median, pack_tight) = pack_ewma_bps(&st.slots, alive);
    let caps: HashMap<usize, usize> = alive
        .iter()
        .map(|&pid| {
            (
                pid,
                densify_cap_for(
                    &st.slots,
                    pid,
                    cfg.per_peer,
                    tip_hole,
                    pack_median,
                    pack_tight,
                ),
            )
        })
        .collect();
    issued += steal_hung_densify(st, hub, alive, tip_batch_hi, &caps);

    let mut room = cfg.window.saturating_sub(st.inflight.len());
    // Window is full and no retired holder is waiting for a racer. Skip the
    // densify height walk.
    if room == 0 && !st.inflight.values().any(inflight_needs_racer) {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let densify_hi = path_lo.saturating_add(CONTIG_DENSIFY_AHEAD);
    let depth_bytes = hub.query.block_queue_stats().1;
    let fetched_hi = hub
        .query
        .block_queue_max_height()
        .into_iter()
        .chain(hub.query.lookup_taken_hi())
        .max();
    let band_hi = rbitcoin_query::soft_densify_band_hi(
        path_lo,
        densify_hi,
        depth_bytes,
        tip_rate_blocks_per_s,
        rbitcoin_query::bq_assign_stop_bytes(),
        fetched_hi,
    );

    if path_lo < st.assign_path_lo {
        st.densify_scan_lo = path_lo;
    }
    st.assign_path_lo = path_lo;
    st.densify_scan_lo = st.densify_scan_lo.max(path_lo);
    if !alive
        .iter()
        .any(|&pid| peer_has_slot(st, pid, caps.get(&pid).copied().unwrap_or(1)))
    {
        finish_assign(loop_stats, t0, issued);
        return;
    }
    let densify_lo = path_lo.max(st.densify_scan_lo);
    let collect_cap = if room == 0 { 1 } else { room };
    let densify = collect_height_band(st, hub, densify_lo, band_hi, collect_cap, room);
    if densify.is_empty() {
        finish_assign(loop_stats, t0, issued);
        return;
    }

    let ranked = rank_peers_by_speed(&st.slots, alive, &HashSet::new());
    let mut densify_q = densify;
    'peers: for &pid in &ranked {
        if densify_q.is_empty() {
            break;
        }
        let cap = caps.get(&pid).copied().unwrap_or(1);
        while !densify_q.is_empty() {
            if !peer_has_slot(st, pid, cap) {
                break;
            }
            let Some(h) = pop_need(&mut densify_q, st, hub) else {
                break;
            };
            if st.inflight.get(&h).is_some_and(|req| req.holds(pid)) {
                densify_q.push_front(h);
                break;
            }
            if !densify_issue_allowed(room, st.inflight.get(&h)) {
                densify_q.push_front(h);
                break 'peers;
            }
            if !issue_one(st, pid, h, &mut room, &mut issued) {
                densify_q.push_front(h);
                break;
            }
        }
    }

    finish_assign(loop_stats, t0, issued);
}

pub(crate) fn finish_assign(loop_stats: &LoopStats, t0: Instant, issued: u64) {
    loop_stats
        .assign_ns
        .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    if issued > 0 {
        loop_stats
            .assign_issued
            .fetch_add(issued, Ordering::Relaxed);
    }
}

/// Single-peer need list over an inclusive height band.
///
/// Walks closest-to-tip first. Already-pending / body-queue / archived heights
/// are skipped without consuming [`FAR_SCAN_BUDGET`] “need” slots — only the
/// raw walk length is capped — so a full tip buffer no longer blocks densify
/// from seeing the rest of the [`CONTIG_DENSIFY_AHEAD`] band.
fn collect_height_band(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    lo: u32,
    hi: u32,
    cap: usize,
    room: usize,
) -> VecDeque<BlockHash> {
    let mut out = VecDeque::new();
    if lo > hi || cap == 0 {
        return out;
    }
    let hi = hi.min(st.max_ordered_height.max(lo));
    let mut prefix = lo;
    let mut tracking = true;
    for (walked, ht) in (lo..=hi).enumerate() {
        if out.len() >= cap || walked >= FAR_SCAN_BUDGET {
            break;
        }
        let need = need_hash_at(st, hub, ht, room);
        if tracking {
            if need.is_none() && densify_prefix_filled(st, hub, ht) {
                prefix = ht.saturating_add(1);
            } else {
                tracking = false;
            }
        }
        if let Some(h) = need {
            out.push_back(h);
        }
    }
    st.densify_scan_lo = prefix.max(st.densify_scan_lo);
    out
}

fn densify_prefix_filled(st: &mut IbdWorkState, hub: &ChainHub, ht: u32) -> bool {
    let Some(&h) = st.height_to_hash.get(&ht) else {
        return false;
    };
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return true;
    }
    if st.inflight.contains_key(&h) {
        return true;
    }
    st.body.is_known_archived(&h)
}

/// Body-queue wire at `ht` for `want`: `Ready` when matching; wrong first-wins
/// is dequeued (`Gap`); empty slot is `Gap`. Shared by densify and tip-hole cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BqWireAt {
    Ready,
    Gap,
}

fn bq_wire_for_hash(hub: &ChainHub, ht: u32, want: BlockHash) -> BqWireAt {
    use bitcoin::hashes::Hash as _;
    match hub.query.block_queue_hash_at_height(ht) {
        Some(bq_h) if bq_h == want.to_byte_array() => BqWireAt::Ready,
        Some(_) => {
            let _ = hub.query.block_queue_dequeue_height(ht);
            BqWireAt::Gap
        }
        None => BqWireAt::Gap,
    }
}

/// Hash at `ht` that still needs a new single-peer getdata (not inflight/pending/done).
///
/// Order matters: BQ hash-match before pending. Pending with matching wire is done;
/// **zombie** pending (flag set, wrong/no wire) must demote and re-get — skipping
/// all pending first left densify-ahead heights frozen (tip advances past tip-batch
/// cover, soft filled, conf stuck on a later hole).
fn inflight_needs_racer(req: &state::InflightReq) -> bool {
    req.peers.is_empty() && !req.retired.is_empty()
}

/// A free getdata window slot, or a racer for a hash whose only holders are
/// retired. A retired holder already occupies a window slot, so the racer
/// does not.
fn densify_issue_allowed(room: usize, req: Option<&state::InflightReq>) -> bool {
    room > 0 || req.is_some_and(inflight_needs_racer)
}

fn need_hash_at(st: &mut IbdWorkState, hub: &ChainHub, ht: u32, room: usize) -> Option<BlockHash> {
    use bitcoin::hashes::Hash as _;
    let &h = st.height_to_hash.get(&ht)?;
    if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
        return None;
    }
    if st.inflight.get(&h).is_some_and(|req| !req.peers.is_empty())
        || st.body.is_rejected(&h)
        || st.reorg.invalid.contains(h.to_byte_array())
    {
        return None;
    }
    if !densify_issue_allowed(room, st.inflight.get(&h)) {
        return None;
    }
    // Class A seed: densify skips re-walk; tip-hole cover re-gets tip batch.
    if st.body.is_known_archived(&h) {
        return None;
    }
    if bq_wire_for_hash(hub, ht, h) == BqWireAt::Ready {
        return None;
    }
    demote_zombie_pending_for_fetch(&mut st.body, hub, h, Some(ht));
    if st.body.skip_download(hub, &h) {
        return None;
    }
    Some(h)
}

pub(crate) fn pop_need(
    q: &mut VecDeque<BlockHash>,
    st: &mut IbdWorkState,
    hub: &ChainHub,
) -> Option<BlockHash> {
    while let Some(h) = q.pop_front() {
        if st.body.skip_download(hub, &h)
            || st.inflight.get(&h).is_some_and(|req| !req.peers.is_empty())
        {
            continue;
        }
        return Some(h);
    }
    None
}

fn peer_has_slot(st: &IbdWorkState, pid: usize, per_peer: usize) -> bool {
    st.slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .is_some_and(|s| s.in_flight.len() < per_peer)
}

pub(crate) fn issue_one(
    st: &mut IbdWorkState,
    pid: usize,
    h: BlockHash,
    room: &mut usize,
    issued: &mut u64,
) -> bool {
    issue_batch(st, pid, vec![h], room, issued)
}

/// Bytes reserved per outstanding getdata hash when the peer did not announce a size.
pub(crate) const GETDATA_RESERVE_BYTES: u64 = 4 * 1024 * 1024;

/// `inflight_after` unique hashes, each counted at [`GETDATA_RESERVE_BYTES`],
/// plus the snapshotted queue, fit in the assign-stop budget.
fn intake_reserve_fits(st: &IbdWorkState, inflight_after: usize) -> bool {
    if st.intake_stop == u64::MAX {
        return true;
    }
    let reserved = (inflight_after as u64).saturating_mul(GETDATA_RESERVE_BYTES);
    st.intake_queued.saturating_add(reserved) <= st.intake_stop
}

pub(crate) fn issue_batch(
    st: &mut IbdWorkState,
    pid: usize,
    batch: Vec<BlockHash>,
    room: &mut usize,
    issued: &mut u64,
) -> bool {
    if batch.is_empty() {
        return false;
    }
    // A peer answering getheaders is not also a block source for this window.
    if super::header_scan::peer_awaits_headers(st, pid) {
        return false;
    }
    let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
        return false;
    };
    let mut projected = st.inflight.len();
    let batch: Vec<BlockHash> = batch
        .into_iter()
        .filter(|h| {
            if st.slots[idx].in_flight.contains(h) {
                return false;
            }
            if st.inflight.contains_key(h) {
                return true;
            }
            let next = projected.saturating_add(1);
            if !intake_reserve_fits(st, next) {
                return false;
            }
            projected = next;
            true
        })
        .collect();
    if batch.is_empty() {
        return false;
    }
    let empty = st.slots[idx].in_flight.is_empty();
    for &h in &batch {
        st.slots[idx].in_flight.insert(h);
    }
    if empty {
        st.slots[idx].rate.note_work_started(ibd_mono_ms());
    }
    let _ = st.slots[idx].cmd_tx.send(PeerCmd::GetData {
        hashes: batch.clone(),
    });
    for &h in &batch {
        inflight_add_peer(&mut st.inflight, h, pid);
    }
    *issued += batch.len() as u64;
    let new_unique = batch
        .iter()
        .filter(|h| {
            st.inflight
                .get(*h)
                .is_some_and(|e| e.len() == 1 && e.retired.is_empty())
        })
        .count();
    *room = room.saturating_sub(new_unique);
    true
}

/// Contiguous tip+1.. hashes that still need getdata (assign tip-hole race).
///
/// Stops at the first **claim-ready** body (body-queue wire / confirmed) so
/// densify priority matches operator `hole=` (fetch gap, not confirm backlog).
pub(crate) fn contiguous_tip_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    max: usize,
) -> Vec<BlockHash> {
    use super::progress::claim_ready;
    let path_lo = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let mut holes = Vec::new();
    let limit = path_lo
        .saturating_add(max as u32 * 4)
        .max(path_lo.saturating_add(max as u32));
    for ht in path_lo..=limit {
        if holes.len() >= max {
            break;
        }
        let Some(&hash) = st.height_to_hash.get(&ht) else {
            break;
        };
        if st.body.is_rejected(&hash) {
            break;
        }
        if claim_ready(hub, &mut st.body, ht, &hash) {
            break;
        }
        holes.push(hash);
    }
    holes
}

/// First non-claim-ready height in `path_lo .. path_lo+max-1` (after a ready prefix).
pub(crate) fn first_pre_hole(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    max: usize,
) -> Option<BlockHash> {
    use super::progress::claim_ready;
    let path_lo = match hub.tip_height() {
        None => 0u32,
        Some(t) => t.saturating_add(1),
    };
    let hi = path_lo.saturating_add(max.saturating_sub(1) as u32);
    for ht in path_lo..=hi {
        let &hash = st.height_to_hash.get(&ht)?;
        if st.body.is_rejected(&hash) {
            continue;
        }
        if claim_ready(hub, &mut st.body, ht, &hash) {
            continue;
        }
        return Some(hash);
    }
    None
}

/// Extra racer on a pre-hole only when there is no owner, every current owner
/// has held the hash for [`TIP_HOLE_RX_STALE`], or an owner's EWMA is ≤ pack
/// median / 4.
pub(crate) fn pre_hole_should_extra_racer(
    st: &IbdWorkState,
    hash: BlockHash,
    alive: &[usize],
) -> bool {
    let Some(req) = st.inflight.get(&hash) else {
        return true;
    };
    if req.peers.is_empty() {
        return true;
    }
    let now = Instant::now();
    let aged = req.peers.iter().all(|&pid| {
        let since = req.owner_asked_at(pid).unwrap_or(req.started_at);
        now.duration_since(since) >= TIP_HOLE_RX_STALE
    });
    if aged {
        return true;
    }
    let (Some(median), _) = pack_ewma_bps(&st.slots, alive) else {
        return false;
    };
    if median == 0 {
        return false;
    }
    let slow = median / 4;
    req.peers.iter().any(|&pid| {
        st.slots
            .iter()
            .find(|s| s.id == pid && s.alive)
            .and_then(|s| s.rate.bps())
            .is_some_and(|bps| bps <= slow)
    })
}

fn cover_first_pre_hole(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
) -> u64 {
    let Some(h) = first_pre_hole(st, hub, TIP_HOLE_MAX) else {
        return 0;
    };
    let want = if pre_hole_should_extra_racer(st, h, alive) {
        PRE_HOLE_MAX_PEERS
    } else {
        1
    };
    cover_tip_holes(st, hub, cfg, alive, &[h], want)
}

/// Demote zombie `pending` (flag set, no **matching** body-queue wire) so getdata
/// can re-issue.
///
/// Confirm intake and reorg gather need real wire (BQ / held). `mark_pending`
/// alone is not enough — without BQ it is a zombie that would `skip_download`
/// forever. Tip-hole cover and reorg densify (1b) share this; only walks the
/// small hole/need lists (not the full pending map).
#[inline]
fn demote_zombie_pending_for_fetch(
    body: &mut super::body::BodyPresence,
    hub: &ChainHub,
    hash: BlockHash,
    height: Option<u32>,
) {
    use bitcoin::hashes::Hash as _;
    if !body.is_pending(&hash) {
        return;
    }
    if hub.has_block(&hash) {
        return;
    }
    // Only keep pending when BQ holds **this** hash at its height (not a
    // different first-wins occupant).
    if let Some(ht) = height {
        if hub
            .query
            .block_queue_hash_at_height(ht)
            .is_some_and(|h| h == hash.to_byte_array())
        {
            return;
        }
    }
    body.mark_missing(hash);
}

/// Stream rx older than this is not “recent” for tip-hole owner eviction.
/// Matches the absolute stall floor so slow-but-steady 64 KiB ticks stay live.
const TIP_HOLE_RX_STALE: Duration = Duration::from_secs(30);

fn peer_has_recent_rx(slot: &PeerSlot, now_ms: u64) -> bool {
    slot.rate
        .has_recent_rx(now_ms, TIP_HOLE_RX_STALE.as_millis() as u64)
}

fn peer_queue_len(slots: &[PeerSlot], pid: usize) -> usize {
    slots
        .iter()
        .find(|s| s.id == pid)
        .map(|s| s.in_flight.len())
        .unwrap_or(usize::MAX)
}

/// Owner still has densify (or other) getdata in front of this hole.
fn hole_owner_fifo_blocked(slot: &PeerSlot) -> bool {
    slot.in_flight.len() > 1
}

/// A FIFO-blocked owner is not dropped until it has held the hash this long.
/// Every peer has other getdata in flight during IBD, so without a hold time
/// the rule fires on every assign pass.
const TIP_HOLE_FIFO_MIN_HOLD: Duration = Duration::from_secs(5);

/// A free peer must be expected to start the hash in at most 1/this of the
/// owner's drain time before a FIFO-blocked owner is dropped for it.
const TIP_HOLE_FIFO_FASTER: u128 = 2;

/// Drop an owner whose peer FIFO is not on this hash when it has held the hash
/// for [`TIP_HOLE_FIFO_MIN_HOLD`] and a free peer would start it at least
/// [`TIP_HOLE_FIFO_FASTER`]× sooner by `(queue+1)/bps`.
fn fifo_blocked_owner_to_drop(
    req: &state::InflightReq,
    hash: &BlockHash,
    slots: &[PeerSlot],
    per_peer: usize,
) -> Option<usize> {
    if slots.iter().filter(|s| s.alive).count() <= 1 {
        return None;
    }
    let (free_q, free_bps) = slots
        .iter()
        .filter(|s| {
            s.alive
                && !req.holds(s.id)
                && !s.in_flight.contains(hash)
                && s.in_flight.len() < per_peer
        })
        .map(|s| (s.in_flight.len(), peer_bps(slots, s.id)))
        .min_by(|&(qa, ba), &(qb, bb)| tip_hole_drain_cmp(qa, ba, qb, bb))?;
    let now = Instant::now();
    req.peers
        .iter()
        .copied()
        .filter(|&id| {
            let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
                return false;
            };
            if !hole_owner_fifo_blocked(slot) {
                return false;
            }
            let held_long = req
                .owner_asked_at(id)
                .is_some_and(|t| now.duration_since(t) >= TIP_HOLE_FIFO_MIN_HOLD);
            // free wait <= owner wait / FASTER, cross-multiplied as in tip_hole_drain_cmp.
            let free_wait = (free_q as u128 + 1)
                .saturating_mul(TIP_HOLE_FIFO_FASTER)
                .saturating_mul(u128::from(peer_bps(slots, id).max(1)));
            let owner_wait =
                (slot.in_flight.len() as u128).saturating_mul(u128::from(free_bps.max(1)));
            held_long && free_wait <= owner_wait
        })
        .max_by(|&a, &b| {
            peer_queue_len(slots, a)
                .cmp(&peer_queue_len(slots, b))
                .then_with(|| peer_bps(slots, b).cmp(&peer_bps(slots, a)))
                .then_with(|| a.cmp(&b))
        })
}

/// Which current owner of a tip-hole hash to drop from **this hash** (not disconnect).
///
/// - Owner `in_flight.len() > 1` → densify may be in front; drop when it has
///   held the hash ≥ [`TIP_HOLE_FIFO_MIN_HOLD`] and a free peer would start it
///   clearly sooner (peer-level 64 KiB ticks are not progress on this hash).
/// - No owner has recent rx → none (too early / first 64 KiB still in flight).
/// - Some have recent rx, some do not → drop a no-rx owner (quick dead-racer).
/// - All have recent rx → [`relative_slow_pick`] among those owners (`min_samples` =
///   owner count). Tight cluster → none.
/// - Solo owner: drop when it has held the hash (its own ask time)
///   ≥ [`TIP_HOLE_RX_STALE`] and another alive peer exists. Getdata
///   cannot be cancelled, so we stop counting that owner and race a faster
///   drain instead. One live peer stays so we do not drop the only remaining
///   request.
pub(crate) fn tip_hole_owner_to_drop(
    req: &state::InflightReq,
    hash: &BlockHash,
    slots: &[PeerSlot],
    per_peer: usize,
) -> Option<usize> {
    let owners: Vec<usize> = req.peers.iter().copied().collect();
    let owners = owners.as_slice();
    if owners.is_empty() {
        return None;
    }
    if let Some(id) = fifo_blocked_owner_to_drop(req, hash, slots, per_peer) {
        return Some(id);
    }
    let solo_since = owners
        .first()
        .and_then(|&pid| req.owner_asked_at(pid))
        .unwrap_or(req.started_at);
    let now_ms = ibd_mono_ms();
    let mut recent = Vec::new();
    let mut stale = Vec::new();
    for &id in owners {
        let Some(slot) = slots.iter().find(|s| s.id == id && s.alive) else {
            stale.push(id);
            continue;
        };
        if peer_has_recent_rx(slot, now_ms) {
            recent.push(id);
        } else {
            stale.push(id);
        }
    }
    if owners.len() == 1 {
        let aged = Instant::now().duration_since(solo_since) >= TIP_HOLE_RX_STALE;
        let other_alive = slots.iter().filter(|s| s.alive).count() > 1;
        if !recent.is_empty() {
            if aged && other_alive {
                return Some(owners[0]);
            }
            return None;
        }
        if aged {
            return Some(owners[0]);
        }
        return None;
    }
    if recent.is_empty() {
        return None;
    }
    if let Some(&id) = stale.iter().min() {
        return Some(id);
    }
    let samples: Vec<RelativeSlowSample> = owners
        .iter()
        .filter_map(|&id| {
            let s = slots.iter().find(|s| s.id == id && s.alive)?;
            Some(RelativeSlowSample {
                peer_id: id,
                bps: s.rate.eviction_bps(now_ms).unwrap_or(0),
                has_inflight: true,
            })
        })
        .collect();
    relative_slow_pick(&samples, samples.len())
}

/// Stop counting `pid` as a racer on `hash`. Getdata cannot be cancelled, so
/// the peer keeps the request in its `in_flight` and is not asked again.
fn retire_hash_owner(st: &mut IbdWorkState, hash: BlockHash, pid: usize) {
    if let Some(req) = st.inflight.get_mut(&hash) {
        req.retire_peer(pid);
    }
}

fn peer_bps(slots: &[PeerSlot], pid: usize) -> u64 {
    slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .and_then(|s| s.rate.bps())
        .unwrap_or(0)
}

fn pack_ewma_bps(slots: &[PeerSlot], alive: &[usize]) -> (Option<u64>, bool) {
    let mut samples: Vec<u64> = alive
        .iter()
        .filter_map(|&pid| {
            slots
                .iter()
                .find(|s| s.id == pid && s.alive)
                .and_then(|s| s.rate.bps())
        })
        .collect();
    if samples.is_empty() {
        return (None, true);
    }
    samples.sort_unstable();
    let lo = samples[0];
    let hi = samples[samples.len() - 1];
    let tight = if lo == 0 {
        hi == 0
    } else {
        hi <= lo.saturating_mul(RELATIVE_SLOW_CLUSTER_SPREAD)
    };
    (Some(median_u64(&samples)), tight)
}

fn densify_cap_for(
    slots: &[PeerSlot],
    pid: usize,
    per_peer: usize,
    tip_hole: bool,
    pack_median: Option<u64>,
    pack_tight: bool,
) -> usize {
    let bps = slots
        .iter()
        .find(|s| s.id == pid && s.alive)
        .and_then(|s| s.rate.bps());
    densify_slots_for_peer(per_peer, tip_hole, bps, pack_median, pack_tight)
}

/// Move hung single-peer densify getdata to a faster peer with a free slot.
fn steal_hung_densify(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    alive: &[usize],
    tip_batch_hi: u32,
    densify_caps: &HashMap<usize, usize>,
) -> u64 {
    let now = Instant::now();
    let now_ms = ibd_mono_ms();
    let candidates: Vec<(BlockHash, u32, usize, Instant)> = st
        .inflight
        .iter()
        .filter_map(|(h, req)| {
            if req.len() != 1 {
                return None;
            }
            let &ht = st.hash_height.get(h)?;
            if ht <= tip_batch_hi {
                return None;
            }
            let &pid = req.peers.iter().next()?;
            Some((*h, ht, pid, req.owner_asked_at(pid)?))
        })
        .collect();
    let hung: Vec<BlockHash> = candidates
        .into_iter()
        .filter(|(h, ht, pid, started)| {
            if super::progress::claim_ready(hub, &mut st.body, *ht, h) {
                return false;
            }
            let Some(slot) = st.slots.iter().find(|s| s.id == *pid && s.alive) else {
                return false;
            };
            if peer_has_recent_rx(slot, now_ms) {
                return false;
            }
            now.duration_since(*started) >= TIP_HOLE_RX_STALE
        })
        .map(|(h, _, _, _)| h)
        .collect();
    let mut issued = 0u64;
    for h in hung {
        let Some(owner) = st
            .inflight
            .get(&h)
            .and_then(|req| req.peers.iter().copied().next())
        else {
            continue;
        };
        let owner_bps = peer_bps(&st.slots, owner);
        let mut faster: Vec<usize> = alive
            .iter()
            .copied()
            .filter(|&pid| {
                pid != owner
                    && peer_bps(&st.slots, pid) > owner_bps
                    && !st.inflight.get(&h).is_some_and(|r| r.holds(pid))
            })
            .collect();
        if faster.is_empty() {
            continue;
        }
        faster.sort_by_key(|&b| std::cmp::Reverse(peer_bps(&st.slots, b)));
        let dest = faster
            .into_iter()
            .find(|&pid| peer_has_slot(st, pid, densify_caps.get(&pid).copied().unwrap_or(1)));
        let ht = st.hash_height.get(&h).copied();
        retire_hash_owner(st, h, owner);
        if let Some(pid) = dest {
            let mut room = 1usize;
            let _ = issue_one(st, pid, h, &mut room, &mut issued);
        } else if let Some(ht) = ht {
            st.densify_scan_lo = st.densify_scan_lo.min(ht);
        }
    }
    issued
}

/// Rank alive peer ids for densify getdata: prefer peers not in `avoid`, then
/// higher live EWMA bps, then lower id. Unsampled peers sort last
/// among non-avoided (bps=0).
pub(crate) fn rank_peers_by_speed(
    slots: &[PeerSlot],
    alive: &[usize],
    avoid: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut ranked: Vec<usize> = alive.to_vec();
    ranked.sort_by(|&a, &b| {
        let avoided_a = avoid.contains(&a) as u8;
        let avoided_b = avoid.contains(&b) as u8;
        avoided_a.cmp(&avoided_b).then_with(|| {
            let bps = |pid: usize| -> u64 { peer_bps(slots, pid) };
            bps(b).cmp(&bps(a)).then_with(|| a.cmp(&b))
        })
    });
    ranked
}

/// Rank for tip-hole getdata: lowest expected drain wait first, then higher EWMA.
///
/// Wait is `(queue+1)/bps` so a fast peer with leftover densify beats an idle
/// slow peer. Unsampled (`bps == 0`) uses 1 so unknown sorts behind any positive rate.
fn rank_peers_for_tip_hole(
    slots: &[PeerSlot],
    alive: &[usize],
    avoid: &std::collections::HashSet<usize>,
) -> Vec<usize> {
    let mut ranked: Vec<usize> = alive.to_vec();
    ranked.sort_by(|&a, &b| {
        let avoided_a = avoid.contains(&a) as u8;
        let avoided_b = avoid.contains(&b) as u8;
        avoided_a.cmp(&avoided_b).then_with(|| {
            let qa = peer_queue_len(slots, a);
            let qb = peer_queue_len(slots, b);
            let bps_a = peer_bps(slots, a);
            let bps_b = peer_bps(slots, b);
            tip_hole_drain_cmp(qa, bps_a, qb, bps_b)
                .then_with(|| bps_b.cmp(&bps_a).then_with(|| a.cmp(&b)))
        })
    });
    ranked
}

/// `wait_a < wait_b` iff `(qa+1)/bps_a < (qb+1)/bps_b`.
fn tip_hole_drain_cmp(qa: usize, bps_a: u64, qb: usize, bps_b: u64) -> std::cmp::Ordering {
    let a = bps_a.max(1);
    let b = bps_b.max(1);
    let wa = (qa as u128 + 1).saturating_mul(u128::from(b));
    let wb = (qb as u128 + 1).saturating_mul(u128::from(a));
    wa.cmp(&wb)
}

/// Full race on tip+1; one racer each on later contiguous holes in the same gap.
fn cover_tip_batch_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    holes: &[BlockHash],
) -> u64 {
    let Some((first, rest)) = holes.split_first() else {
        return 0;
    };
    let mut issued = cover_tip_holes(st, hub, cfg, alive, &[*first], TIP_HOLE_MAX_PEERS);
    issued += cover_tip_holes(st, hub, cfg, alive, rest, 1);
    issued
}

/// Cover each tip-hole hash with multi-peer getdata on short drain waits.
///
/// While the hole is open, at most one current owner of **this hash** is dropped
/// per call when a sibling is pulling, that owner is a relative-slow outlier
/// among owners, the owner's FIFO is still on densify, or a solo owner has held
/// it too long and another peer exists. The whole race set is never cleared on
/// request age. A dropped owner is retired: it keeps the request it was sent,
/// still counts toward its queue and toward the ask cap, and is not asked
/// for this hash again.
pub(crate) fn cover_tip_holes(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    cfg: &IbdConfig,
    alive: &[usize],
    holes: &[BlockHash],
    max_peers: usize,
) -> u64 {
    if holes.is_empty() || alive.is_empty() {
        return 0;
    }
    let mut issued = 0u64;

    for &h in holes {
        let ht = st.hash_height.get(&h).copied();
        if let Some(ht) = ht {
            if super::progress::claim_ready(hub, &mut st.body, ht, &h) {
                continue;
            }
            let _ = bq_wire_for_hash(hub, ht, h);
        } else if hub.has_block(&h) {
            continue;
        }
        demote_zombie_pending_for_fetch(&mut st.body, hub, h, ht);
        let mut avoid: HashSet<usize> = HashSet::new();
        if let Some(req) = st.inflight.get(&h) {
            if let Some(pid) = tip_hole_owner_to_drop(req, &h, &st.slots, cfg.per_peer) {
                retire_hash_owner(st, h, pid);
                avoid.insert(pid);
            }
        }
        let already = st.inflight.get(&h).map(|e| e.holders()).unwrap_or(0);
        let want = max_peers;
        if already >= want {
            continue;
        }
        let mut need = want - already;
        let mut placed_any = false;
        let ranked = rank_peers_for_tip_hole(&st.slots, alive, &avoid);
        for &pid in &ranked {
            if need == 0 {
                break;
            }
            if avoid.contains(&pid) {
                continue;
            }
            let Some(idx) = st.slots.iter().position(|s| s.id == pid && s.alive) else {
                continue;
            };
            if st.slots[idx].in_flight.contains(&h) {
                continue;
            }
            if st.inflight.get(&h).is_some_and(|e| e.holds(pid)) {
                continue;
            }
            if st.slots[idx].in_flight.len() >= cfg.per_peer {
                continue;
            }
            let mut room = 1usize;
            if issue_one(st, pid, h, &mut room, &mut issued) {
                placed_any = true;
                need = need.saturating_sub(1);
            }
        }
        if already == 0 && !placed_any {
            break;
        }
    }
    issued
}

#[cfg(test)]
pub(in crate::ibd) mod tests {
    use super::super::status::LoopStats;
    use super::*;
    use bitcoin::hashes::Hash;
    use rbitcoin_query::Query;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn densify_skips_at_or_below_lookup_taken_hi() {
        assert!(!Query::lookup_taken_covers(5, None));
        assert!(!Query::lookup_taken_covers(0, None));
        assert!(Query::lookup_taken_covers(5, Some(5)));
        assert!(Query::lookup_taken_covers(4, Some(5)));
        assert!(!Query::lookup_taken_covers(6, Some(5)));
        assert!(Query::lookup_taken_covers(0, Some(0)));
    }

    #[test]
    fn need_any_valid_body_download_empty_and_missing_tip_child() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
        assert!(
            !need_any_valid_body_download(&st, &hub),
            "genesis-only path has no body download"
        );
        let want = h(0x21);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        st.body.mark_missing(want);
        assert!(
            need_any_valid_body_download(&st, &hub),
            "missing tip+1 must keep download open"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_skips_taken_prefix() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        let want = h(0x11);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        st.body.mark_missing(want);
        hub.query.set_lookup_taken_hi(Some(ht));
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert!(
            holes.is_empty(),
            "taken tip+1 is not a fetch hole: {holes:?}"
        );
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[want], TIP_HOLE_MAX_PEERS);
        assert_eq!(issued, 0, "must not race getdata for a taken height");
        assert!(st.inflight.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn h(n: u32) -> BlockHash {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_byte_array(b)
    }

    fn dummy_slot(id: usize) -> PeerSlot {
        let (cmd_tx, _rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        PeerSlot {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444 + id as u16),
            net: crate::NetAddr::from_socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                18444 + id as u16,
            )),
            cmd_tx,
            in_flight: HashSet::new(),
            peer_height: 100,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            alive: true,
            task,
        }
    }

    fn plant_work_path(st: &mut IbdWorkState, lo: u32, hi: u32) {
        for ht in lo..=hi {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
    }

    fn seed_ewma(slot: &mut PeerSlot, bytes_per_sec: u64) {
        slot.rate.sample(0, 0, true);
        slot.rate
            .sample(5_000, bytes_per_sec.saturating_mul(5), true);
    }

    fn mark_tip_batch_ready(st: &mut IbdWorkState, hub: &ChainHub, path_lo: u32) {
        use bitcoin::hashes::Hash as _;
        for ht in path_lo..=32 {
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
            st.body.mark_pending(h(ht));
        }
    }

    fn mark_heights_ready(st: &mut IbdWorkState, hub: &ChainHub, lo: u32, hi: u32) {
        use bitcoin::hashes::Hash as _;
        for ht in lo..=hi {
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
            st.body.mark_pending(h(ht));
        }
    }

    /// 75×80-byte bodies past the tip window. At 5 blk/s the confirm window is
    /// 300 blocks, so this is a quarter of that window.
    fn plant_quarter_window(hub: &ChainHub, path_lo: u32) {
        use bitcoin::hashes::Hash as _;
        let start = path_lo.saturating_add(64);
        for i in 0..75u32 {
            let ht = start.saturating_add(i);
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
        }
    }

    fn tmp_hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
        crate::chain::tiny_regtest_hub_labeled("assign")
    }

    #[test]
    fn download_gate_stops_getdata_when_tip_plus_one_unconfirmable() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        plant_work_path(&mut st, 1, 20);
        st.body.mark_rejected(h(1));
        st.confirm_stuck_since = Instant::now().checked_sub(Duration::from_secs(60));
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.is_empty(),
            "gate must issue no getdata while tip+1 is unconfirmable; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_inflight_add_peer_pop_need_and_tip_holes() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let hash = h(10);
        st.slots[0].in_flight.insert(hash);
        st.slots[1].in_flight.insert(hash);
        inflight_add_peer(&mut st.inflight, hash, 0);
        inflight_add_peer(&mut st.inflight, hash, 1);
        assert_eq!(st.inflight[&hash].len(), 2);
        clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
        assert!(st.inflight.is_empty());
        assert!(st.slots[0].in_flight.is_empty());
        assert!(st.slots[1].in_flight.is_empty());

        let mut q = VecDeque::from([h(1), h(2)]);
        st.body.mark_pending(h(1));
        st.body.mark_missing(h(2));
        assert_eq!(pop_need(&mut q, &mut st, &hub), Some(h(2)));
        assert!(pop_need(&mut q, &mut st, &hub).is_none());

        st.height_to_hash.clear();
        let hole = h(21);
        let zombie = h(22);
        st.height_to_hash.insert(0, hole);
        st.height_to_hash.insert(1, zombie);
        st.body.mark_missing(hole);
        // Pending without body queue is a fetch hole (not claim-ready).
        st.body.mark_pending(zombie);
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![hole, zombie]);

        let mut room = 10usize;
        let mut issued = 0u64;
        assert!(!issue_one(&mut st, 99, h(30), &mut room, &mut issued));
        assert!(!issue_batch(&mut st, 0, vec![], &mut room, &mut issued));
        st.body.mark_missing(h(30));
        assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
        assert!(issued >= 1);
        assert!(st.inflight.contains_key(&h(30)));
        assert!(st.slots[0].in_flight.contains(&h(30)));

        st.slots.iter_mut().for_each(|s| s.alive = false);
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn issue_batch_does_not_count_as_rx() {
        let (dir, _hub) = tmp_hub();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        st.slots[0].rate.progress_ms = 42;
        st.slots[0].rate.work_started_ms = 7;
        let mut room = 10usize;
        let mut issued = 0u64;
        let t0 = super::super::peer_io::ibd_mono_ms();
        assert!(issue_one(&mut st, 0, h(30), &mut room, &mut issued));
        let t1 = super::super::peer_io::ibd_mono_ms();
        assert_eq!(st.slots[0].rate.progress_ms, 42);
        assert!(st.slots[0].rate.work_started_ms >= t0);
        assert!(st.slots[0].rate.work_started_ms <= t1);
        let _ = std::fs::remove_dir_all(dir);
    }
    /// Off-path getdata (mainnet 08:16:23: ordered empty, h2h=0, inflight=7)
    /// must not occupy slots; tip+1 and live awaiting-reorg need stay.
    /// Speculative explore-need at an empty remainder is leftover — drop it.
    #[test]
    fn prune_off_path_inflight_drops_orphans_keeps_path_and_reorg() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        assert!(st.ordered.is_empty());
        assert!(st.height_to_hash.is_empty() || st.height_to_hash.len() <= 1);

        for i in 0..7u32 {
            let hash = h(1000 + i);
            st.slots[0].in_flight.insert(hash);
            inflight_add_peer(&mut st.inflight, hash, 0);
        }
        let want = h(0x11);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(want, ht);
        st.slots[0].in_flight.insert(want);
        inflight_add_peer(&mut st.inflight, want, 0);
        let explore_h = h(0x22);
        st.reorg.register_explore(std::iter::once(explore_h), None);
        st.slots[0].in_flight.insert(explore_h);
        inflight_add_peer(&mut st.inflight, explore_h, 0);
        assert_eq!(st.inflight.len(), 9);

        prune_off_path_inflight(&mut st);

        assert!(st.inflight.contains_key(&want), "tip+1 occupant stays");
        assert!(
            !st.inflight.contains_key(&explore_h),
            "explore-need at empty remainder is leftover"
        );
        for i in 0..7u32 {
            let hash = h(1000 + i);
            assert!(!st.inflight.contains_key(&hash), "orphan {i} dropped");
            assert!(!st.slots[0].in_flight.contains(&hash));
        }
        assert_eq!(st.inflight.len(), 1, "orphans+explore dropped; path kept");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scale_and_saturated_helpers() {
        assert!(!bq_pipeline_saturated(20, false));
        assert!(!bq_pipeline_saturated(0, false));
        assert!(!bq_pipeline_saturated(0, false));
        assert!(bq_pipeline_saturated(0, true));
        assert!(bq_pipeline_saturated(15, true));
        assert!(!bq_pipeline_saturated(32, true));
    }

    #[test]
    fn densify_yields_peer_slots_while_tip_hole_open() {
        use super::super::assign_plan::far_slots_per_peer;
        assert_eq!(far_slots_per_peer(16, true), 0);
        assert!(far_slots_per_peer(16, true) < 16);
        assert_eq!(far_slots_per_peer(16, false), 8);
    }

    /// An empty body queue is the download frontier: tip+1 is only as far as
    /// getdata has reached. One owner, and densify keeps filling past the
    /// 32-block window.
    #[test]
    fn empty_body_queue_tip_gap_is_the_frontier() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n0, 1,
            "empty queue is the frontier; tip+1 gets one owner; n0={n0}"
        );
        let past = path_lo.saturating_add(TIP_HOLE_MAX as u32);
        assert!(
            st.inflight.contains_key(&h(past)),
            "densify continues past the tip window on the frontier"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Gaps count. 74 of a 300-block confirm window is under a quarter, so the
    /// tip gap stays the frontier even though bodies already sit further on.
    #[test]
    fn gapped_queue_under_quarter_window_is_the_frontier() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        // 74 ready bodies on the odd heights. The walk stops at the first
        // ready body, so the contiguous tip hole is only tip+1.
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
        for i in 0..74u32 {
            let ht = path_lo
                .saturating_add(1)
                .saturating_add(i.saturating_mul(2));
            mark_heights_ready(&mut st, &hub, ht, ht);
        }
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        // 5 blk/s → 300-block confirm window. 74 * 4 = 296 < 300.
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n0, 1,
            "under a quarter of the confirm window is still the frontier; n0={n0}"
        );
        let gap = path_lo.saturating_add(2);
        assert!(
            st.inflight.contains_key(&h(gap)),
            "densify fills the gap behind the first ready body"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 75 gapped bodies is a quarter of a 300-block window, so tip+1 is a hole
    /// even though the contiguous run is one block.
    #[test]
    fn gapped_quarter_window_is_a_tip_hole() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(400));
        for i in 0..75u32 {
            let ht = path_lo
                .saturating_add(1)
                .saturating_add(i.saturating_mul(2));
            mark_heights_ready(&mut st, &hub, ht, ht);
        }
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n0, 4,
            "a quarter of the confirm window, with gaps, is a tip hole; n0={n0}"
        );
        assert!(
            !st.inflight.contains_key(&h(path_lo.saturating_add(2))),
            "densify stays off while the quarter-full tip hole is open"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Rate unknown: a quarter of the configured assign-stop is the byte threshold.
    #[test]
    fn byte_quarter_full_queue_races_tip_and_stops_densify() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        // Quarter is 2 MiB. One new hash reserves 4 MiB, so the stop must
        // still fit that reserve on top of the queued quarter.
        let stop: u64 = 8 * 1024 * 1024;
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", stop.to_string());
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(80));
        let n = (stop / 4) as usize;
        let payload = vec![0u8; n];
        hub.query
            .block_queue_offer(
                path_lo.saturating_add(64),
                h(path_lo.saturating_add(64)).to_byte_array(),
                1,
                &payload,
            )
            .unwrap();
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n0, 4,
            "a quarter of the configured assign-stop is a tip hole; n0={n0}"
        );
        assert!(
            !st.inflight
                .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
            "densify stays off at the byte quarter"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Rate cold and bytes far under the assign-stop: 1000 queued bodies is
    /// still a hole. Early blocks are small, so the byte cap would not fill.
    #[test]
    fn ahead_block_count_with_cold_rate_is_a_tip_hole() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(40));
        let start = path_lo.saturating_add(64);
        for i in 0..rbitcoin_query::TIP_HOLE_MIN_AHEAD_BLOCKS {
            let ht = start.saturating_add(i);
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
        }
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n0, 4,
            "1000 queued bodies with a cold rate is a tip hole; n0={n0}"
        );
        assert!(
            !st.inflight
                .contains_key(&h(path_lo.saturating_add(TIP_HOLE_MAX as u32))),
            "densify stays off once the ahead-block floor is met"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_does_not_issue_far_while_tip_plus_one_hole() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        for ht in path_lo.saturating_add(1)..=path_lo.saturating_add(31) {
            hub.query
                .block_queue_offer(ht, h(ht).to_byte_array(), 1, &[0u8; 80])
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 2_000_000);
        plant_quarter_window(&hub, path_lo);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert!(
            st.inflight.contains_key(&h(path_lo)),
            "tip+1 must still be requested"
        );
        let extra: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .filter(|&ht| ht != path_lo)
            .collect();
        assert!(
            extra.is_empty(),
            "far densify must not issue while tip+1 is a fetch hole; extra={extra:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tip_hole_owner_to_drop_too_early_dead_racer_and_solo() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        fn req_with(owners: &[usize], since: Instant) -> InflightReq {
            let mut r = InflightReq::default();
            for &pid in owners {
                r.add_peer(pid);
                r.asked_at.insert(pid, since);
            }
            r
        }
        let hole = h(1);
        let per_peer = 16;
        let mut slots = vec![dummy_slot(0), dummy_slot(1)];
        let started = Instant::now();
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0, 1], started), &hole, &slots, per_peer),
            None,
            "no rx yet is too early"
        );
        slots[1].rate.note_rx(ibd_mono_ms().max(1));
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0, 1], started), &hole, &slots, per_peer),
            Some(0),
            "silent owner drops when sibling has rx"
        );
        slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let ago = |s| Instant::now() - Duration::from_secs(s);
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(7)), &hole, &slots, per_peer),
            None,
            "solo with live rx is kept when young"
        );
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(31)), &hole, &slots, per_peer),
            Some(0),
            "aged solo owner drops when another alive peer exists, even with densify ticks"
        );
        let mut one = vec![dummy_slot(0)];
        one[0].rate.note_rx(ibd_mono_ms().max(1));
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(31)), &hole, &one, per_peer),
            None,
            "truly solo (one live peer) with live rx stays"
        );
        slots[0].rate.progress_ms = 0;
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(31)), &hole, &slots, per_peer),
            Some(0),
            "solo hung with no rx after 30s is replaced"
        );
        let mut fifo = vec![dummy_slot(0), dummy_slot(1)];
        fifo[0].in_flight.insert(hole);
        fifo[0].in_flight.insert(h(2));
        fifo[0].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut fifo[0], 1_000_000);
        seed_ewma(&mut fifo[1], 1_000_000);
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], Instant::now()), &hole, &fifo, per_peer),
            None,
            "young owner with extra inflight stays: it has not had time to reach the hash"
        );
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(6)), &hole, &fifo, per_peer),
            Some(0),
            "owner held >= 5s with extra inflight drops when an empty peer would start sooner"
        );
        for n in 3..6 {
            fifo[1].in_flight.insert(h(n));
        }
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(6)), &hole, &fifo, per_peer),
            None,
            "owner held >= 5s stays when no free peer would clearly start sooner"
        );
        fifo[1].in_flight.clear();
        fifo[0].in_flight.clear();
        fifo[0].in_flight.insert(hole);
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(6)), &hole, &fifo, per_peer),
            None,
            "owner whose only inflight is the hole stays"
        );
        let mut solo_fifo = vec![dummy_slot(0)];
        solo_fifo[0].in_flight.insert(hole);
        solo_fifo[0].in_flight.insert(h(2));
        solo_fifo[0].rate.note_rx(ibd_mono_ms().max(1));
        assert_eq!(
            tip_hole_owner_to_drop(&req_with(&[0], ago(6)), &hole, &solo_fifo, per_peer),
            None,
            "truly solo extra-inflight owner stays (no one else to race)"
        );
    }

    /// Wrong first-wins body at tip+1 is not claim-ready; cover must dequeue and
    /// re-get the work-path hash (general hole=1 with bq soft growing ahead).
    #[test]
    fn cover_tip_holes_drops_wrong_bq_hash_and_regets() {
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let want = h(0xabc);
        let wrong = h(0xdef);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(want, ht);
        st.height_to_hash.insert(ht, want);
        // First-wins wrong wire at tip+1.
        hub.query
            .block_queue_offer(ht, wrong.to_byte_array(), 0, b"wrong")
            .unwrap();
        assert!(hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &want),
            "wrong BQ hash must not be claim-ready"
        );
        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![want]);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes, TIP_HOLE_MAX_PEERS);
        assert!(
            issued >= 1,
            "must re-get correct tip+1 hash; issued={issued}"
        );
        assert!(
            !hub.query.block_queue_has_height(ht)
                || hub
                    .query
                    .block_queue_hash_at_height(ht)
                    .is_some_and(|x| x == want.to_byte_array()),
            "wrong BQ body must be dequeued"
        );
        assert!(st.inflight.contains_key(&want));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Resume seed marks Class A tip+1 as known without BQ wire. Confirm intake is
    /// BQ-only → hole must still race getdata (mainnet stall: hole=1, known=1,
    /// feed ready only ahead of tip, inflight→0 forever).
    #[test]
    fn cover_tip_holes_regets_class_a_without_body_queue() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(1001);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.height_to_hash.insert(ht, hole);
        st.hash_height.insert(hole, ht);
        st.record_height(hole, ht);
        // Class A seed path: known, not pending, not in body queue.
        st.body.mark_archived(hole);
        assert!(st.body.is_known_archived(&hole));
        assert!(!st.body.is_pending(&hole));
        assert!(!hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &hole),
            "Class A alone must not be claim-ready"
        );

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(
            holes,
            vec![hole],
            "tip+1 Class A without BQ is a fetch hole"
        );

        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes, TIP_HOLE_MAX_PEERS);
        assert!(
            issued >= 1,
            "must re-getdata Class A tip hole (got issued={issued})"
        );
        assert!(
            st.inflight.contains_key(&hole),
            "tip hole must be inflight after cover"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Zombie pending (flag set, no BQ wire) must still be a tip hole and re-getdata.
    /// Mainnet ~97%: hole=0 + inflight=0 while tip+1 pending without claimable wire.
    #[test]
    fn cover_tip_holes_regets_zombie_pending_without_body_queue() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0xaa);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.height_to_hash.insert(ht, hole);
        st.hash_height.insert(hole, ht);
        st.record_height(hole, ht);
        // Soft-stall shape: pending set without body-queue wire.
        st.body.mark_pending(hole);
        assert!(st.body.is_pending(&hole));
        assert!(!hub.query.block_queue_has_height(ht));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, ht, &hole),
            "zombie pending must not be claim-ready"
        );

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        assert_eq!(holes, vec![hole], "zombie pending is a fetch hole");

        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes, TIP_HOLE_MAX_PEERS);
        assert!(
            issued >= 1,
            "must re-getdata zombie pending tip hole (got issued={issued})"
        );
        assert!(
            st.inflight.contains_key(&hole),
            "tip hole must be inflight after cover"
        );
        assert!(
            !st.body.is_pending(&hole),
            "cover demotes zombie pending to missing"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Request age does not clear the whole tip-hole race set.
    #[test]
    fn cover_tip_holes_does_not_clear_whole_set_on_started_at() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x51);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut frozen = InflightReq::new(0);
        frozen.add_peer(1);
        frozen.started_at = Instant::now() - Duration::from_secs(7);
        st.inflight.insert(hole, frozen);
        st.slots[0].in_flight.insert(hole);
        st.slots[1].in_flight.insert(hole);
        let now = ibd_mono_ms().max(1);
        st.slots[0].rate.note_rx(now);
        st.slots[1].rate.note_rx(now);
        seed_ewma(&mut st.slots[0], 1_000_000);
        seed_ewma(&mut st.slots[1], 1_100_000);
        seed_ewma(&mut st.slots[2], 1_050_000);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        let peers = &st.inflight[&hole].peers;
        assert!(
            peers.contains(&0) && peers.contains(&1),
            "tight pack with live rx must keep owners; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_drops_owner_with_no_rx_when_sibling_progresses() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x52);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.add_peer(1);
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[1].in_flight.insert(hole);
        st.slots[1].rate.note_rx(ibd_mono_ms().max(1));
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        let peers = &st.inflight[&hole].peers;
        assert!(
            !peers.contains(&0),
            "silent owner must leave this hash; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_drops_relative_slow_owner_among_progressing() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x53);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.add_peer(1);
        req.add_peer(2);
        st.inflight.insert(hole, req);
        for i in 0..3 {
            st.slots[i].in_flight.insert(hole);
            st.slots[i].rate.note_rx(ibd_mono_ms().max(1));
        }
        seed_ewma(&mut st.slots[0], 400_000);
        seed_ewma(&mut st.slots[1], 2_000_000);
        seed_ewma(&mut st.slots[2], 1_900_000);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        let peers = &st.inflight[&hole].peers;
        assert!(
            !peers.contains(&0),
            "quarter-median owner among progressing racers drops; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_solo_slow_but_rx_live_kept() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        let hole = h(0x54);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = vec![0];
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        assert!(
            st.inflight[&hole].peers.contains(&0),
            "solo slow-but-steady download stays"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_aged_solo_drops_when_other_peers_exist() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x55);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        req.asked_at.insert(0, req.started_at);
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut st.slots[1], 2_000_000);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = vec![0, 1];
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        let peers = &st.inflight[&hole].peers;
        assert!(
            !peers.contains(&0),
            "aged owner with densify ticks drops when another peer exists; peers={peers:?}"
        );
        assert!(
            peers.contains(&1),
            "short-queue peer must take the hole; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_prefers_fast_drain_over_empty_slow() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x56);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        seed_ewma(&mut st.slots[0], 10_000_000);
        seed_ewma(&mut st.slots[1], 100_000);
        for i in 0..4u32 {
            st.slots[0].in_flight.insert(h(1000 + i));
        }
        let mut cfg = IbdConfig::for_test();
        cfg.per_peer = 16;
        let alive: Vec<usize> = vec![0, 1];
        let ranked = rank_peers_for_tip_hole(&st.slots, &alive, &HashSet::new());
        assert_eq!(
            ranked[0], 0,
            "fast 4-deep FIFO drains sooner than idle 100KB/s; ranked={ranked:?}"
        );
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], 1);
        let peers = &st.inflight[&hole].peers;
        assert!(
            peers.contains(&0) && !peers.contains(&1),
            "single racer is the fast drain; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_drops_fifo_blocked_owner_for_empty_peer() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x57);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.asked_at
            .insert(0, Instant::now() - Duration::from_secs(6));
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[0].in_flight.insert(h(0x99));
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 10_000_000);
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = vec![0, 1];
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        let peers = &st.inflight[&hole].peers;
        assert!(
            !peers.contains(&0),
            "densify-FIFO owner leaves this hash; peers={peers:?}"
        );
        assert!(
            peers.contains(&1),
            "empty fast peer takes the hole; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Getdata cannot be cancelled: an owner dropped from a tip hole still
    /// holds the request, so later passes must not send it the hash again.
    #[test]
    fn cover_tip_holes_never_reasks_a_dropped_owner() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let mut wire = Vec::new();
        for s in st.slots.iter_mut() {
            let (tx, rx) = mpsc::unbounded_channel();
            s.cmd_tx = tx;
            wire.push(rx);
        }
        let hole = h(0x5a);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.asked_at
            .insert(0, Instant::now() - Duration::from_secs(6));
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[0].in_flight.insert(h(0x99));
        let now = ibd_mono_ms().max(1);
        for s in st.slots.iter_mut() {
            s.rate.note_rx(now);
            seed_ewma(s, 1_000_000);
        }
        let cfg = IbdConfig::for_test();
        let alive = vec![0, 1, 2];
        for _ in 0..5 {
            let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], TIP_HOLE_MAX_PEERS);
        }
        let asks: Vec<usize> = wire
            .iter_mut()
            .map(|rx| {
                let mut n = 0;
                while let Ok(cmd) = rx.try_recv() {
                    if let PeerCmd::GetData { hashes } = cmd {
                        n += hashes.iter().filter(|&&x| x == hole).count();
                    }
                }
                n
            })
            .collect();
        assert_eq!(asks, vec![0, 1, 1], "one getdata per peer per hash");
        assert!(
            st.slots[0].in_flight.contains(&hole),
            "dropped owner still counts the request it holds"
        );
        assert!(st.inflight[&hole].holds(0));
        assert!(!st.inflight[&hole].peers.contains(&0));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Peers who still owe a hash count toward its race cap. Dropping one
    /// must not free a slot for a peer that has never been asked.
    #[test]
    fn cover_tip_holes_ask_cap_includes_peers_who_still_owe_the_block() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2), dummy_slot(3)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let mut wire = Vec::new();
        for s in st.slots.iter_mut() {
            let (tx, rx) = mpsc::unbounded_channel();
            s.cmd_tx = tx;
            wire.push(rx);
        }
        let hole = h(0x5c);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.add_peer(1);
        req.asked_at
            .insert(0, Instant::now() - Duration::from_secs(6));
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[0].in_flight.insert(h(0x99));
        st.slots[1].in_flight.insert(hole);
        let now = ibd_mono_ms().max(1);
        for s in st.slots.iter_mut() {
            s.rate.note_rx(now);
            seed_ewma(s, 1_000_000);
        }
        let cfg = IbdConfig::for_test();
        let alive = vec![0, 1, 2, 3];
        for _ in 0..5 {
            let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], 2);
        }
        let asks: Vec<usize> = wire
            .iter_mut()
            .map(|rx| {
                let mut n = 0;
                while let Ok(cmd) = rx.try_recv() {
                    if let PeerCmd::GetData { hashes } = cmd {
                        n += hashes.iter().filter(|&&x| x == hole).count();
                    }
                }
                n
            })
            .collect();
        assert_eq!(
            asks,
            vec![0, 0, 0, 0],
            "two peers already owe the block; cap is 2"
        );
        let r = &st.inflight[&hole];
        assert!(r.holds(0) && r.holds(1));
        assert!(!r.holds(2) && !r.holds(3));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The aged-solo drop measures how long the current owner has held the
    /// hash, not how long the hash has been requested.
    #[test]
    fn cover_tip_holes_aged_solo_counts_from_owner_ask() {
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x5b);
        let ht = hub.tip_height().unwrap_or(0).saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        req.retire_peer(0);
        req.add_peer(1);
        st.inflight.insert(hole, req);
        st.slots[0].in_flight.insert(hole);
        st.slots[1].in_flight.insert(hole);
        st.slots[1].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut st.slots[1], 1_000_000);
        seed_ewma(&mut st.slots[2], 1_000_000);
        let cfg = IbdConfig::for_test();
        let alive = vec![0, 1, 2];
        let _ = cover_tip_holes(&mut st, &hub, &cfg, &alive, &[hole], 1);
        let r = &st.inflight[&hole];
        assert!(
            r.peers.contains(&1) && !r.peers.contains(&2),
            "owner asked just now is not aged; peers={:?}",
            r.peers
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn pre_hole_layout(
        n_peers: usize,
    ) -> (
        rbitcoin_query::testutil::TempDir,
        ChainHub,
        IbdWorkState,
        u32,
        BlockHash,
    ) {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let slots: Vec<PeerSlot> = (0..n_peers).map(dummy_slot).collect();
        let mut st = IbdWorkState::new(slots, hub.tip_hash(), hub.tip_height());
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(31));
        mark_heights_ready(&mut st, &hub, path_lo, path_lo.saturating_add(3));
        let gap_ht = path_lo.saturating_add(4);
        (dir, hub, st, gap_ht, h(gap_ht))
    }

    #[test]
    fn pre_hole_fast_young_owner_stays_solo() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub, mut st, gap_ht, gap) = pre_hole_layout(4);
        assert_eq!(
            first_pre_hole(&mut st, &hub, TIP_HOLE_MAX),
            Some(gap),
            "first in-window gap is tip+5 when 1..=4 are claim-ready"
        );
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 2_000_000);
        seed_ewma(&mut st.slots[2], 1_800_000);
        seed_ewma(&mut st.slots[3], 1_900_000);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(5);
        st.inflight.insert(gap, req);
        st.slots[0].in_flight.insert(gap);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n = st.inflight.get(&gap).map(|e| e.len()).unwrap_or(0);
        assert_eq!(n, 1, "fast young owner of first gap stays solo; n={n}");
        for ht in gap_ht.saturating_add(1)..=gap_ht.saturating_add(27) {
            let raced = st.inflight.get(&h(ht)).map(|e| e.len()).unwrap_or(0);
            assert!(
                raced <= 1,
                "must not race heights past first gap; ht={ht} n={raced}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pre_hole_slow_owner_adds_one_racer_not_window() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub, mut st, gap_ht, gap) = pre_hole_layout(4);
        seed_ewma(&mut st.slots[0], 250_000);
        seed_ewma(&mut st.slots[1], 1_000_000);
        seed_ewma(&mut st.slots[2], 1_000_000);
        seed_ewma(&mut st.slots[3], 1_000_000);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(5);
        st.inflight.insert(gap, req);
        st.slots[0].in_flight.insert(gap);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n = st.inflight.get(&gap).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n, 2,
            "quarter-median first-gap owner gets one extra racer; n={n}"
        );
        for ht in gap_ht.saturating_add(1)..=gap_ht.saturating_add(27) {
            let raced = st.inflight.get(&h(ht)).map(|e| e.len()).unwrap_or(0);
            assert!(
                raced <= 1,
                "must not race heights past first gap; ht={ht} n={raced}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pre_hole_aged_owner_adds_one_racer() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub, mut st, _gap_ht, gap) = pre_hole_layout(4);
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 1_500_000);
        seed_ewma(&mut st.slots[2], 1_600_000);
        seed_ewma(&mut st.slots[3], 1_700_000);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        req.asked_at.insert(0, req.started_at);
        st.inflight.insert(gap, req);
        st.slots[0].in_flight.insert(gap);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&gap];
        assert!(
            r.holds(0) && !r.peers.contains(&0),
            "aged owner is retired and still owes the block"
        );
        assert_eq!(
            r.len(),
            1,
            "one fresh racer replaces the aged owner; n={}",
            r.len()
        );
        assert_eq!(
            r.holders(),
            2,
            "original ask plus one extra stays within the pre-hole cap"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Request age for an extra racer is how long the current owner has held
    /// the hash. An old started_at with a fresh ask must stay solo.
    #[test]
    fn pre_hole_fresh_owner_is_not_aged_by_the_first_ask() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        let (dir, hub, mut st, _gap_ht, gap) = pre_hole_layout(4);
        seed_ewma(&mut st.slots[0], 2_000_000);
        seed_ewma(&mut st.slots[1], 1_500_000);
        seed_ewma(&mut st.slots[2], 1_600_000);
        seed_ewma(&mut st.slots[3], 1_700_000);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        st.inflight.insert(gap, req);
        st.slots[0].in_flight.insert(gap);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let n = st.inflight.get(&gap).map(|e| e.len()).unwrap_or(0);
        assert_eq!(
            n, 1,
            "owner asked just now is not aged by started_at; n={n}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prefix_hole_races_tip_plus_one_before_pre_hole() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(31));
        mark_heights_ready(
            &mut st,
            &hub,
            path_lo.saturating_add(1),
            path_lo.saturating_add(3),
        );
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        plant_quarter_window(&hub, path_lo);
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        let prefix = h(path_lo);
        let n = st.inflight.get(&prefix).map(|e| e.len()).unwrap_or(0);
        assert_eq!(n, 4, "frozen prefix races up to TIP_HOLE_MAX_PEERS; n={n}");
        let gap = h(path_lo.saturating_add(4));
        assert!(
            !st.inflight.contains_key(&gap),
            "pre-hole is not considered while the prefix hole is open"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_batch_races_only_first_hole() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![
                dummy_slot(0),
                dummy_slot(1),
                dummy_slot(2),
                dummy_slot(3),
                dummy_slot(4),
                dummy_slot(5),
            ],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, path_lo.saturating_add(31));
        for s in &mut st.slots {
            seed_ewma(s, 2_000_000);
        }
        plant_quarter_window(&hub, path_lo);
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        let n0 = st.inflight.get(&h(path_lo)).map(|e| e.len()).unwrap_or(0);
        let n1 = st
            .inflight
            .get(&h(path_lo.saturating_add(1)))
            .map(|e| e.len())
            .unwrap_or(0);
        let n2 = st
            .inflight
            .get(&h(path_lo.saturating_add(2)))
            .map(|e| e.len())
            .unwrap_or(0);
        assert_eq!(n0, 4, "tip+1 races TIP_HOLE_MAX_PEERS; n0={n0}");
        assert_eq!(n1, 1, "second contiguous hole gets one racer; n1={n1}");
        assert_eq!(n2, 1, "third contiguous hole gets one racer; n2={n2}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cover_tip_holes_prefers_fast_peers() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let hole = h(0x61);
        let tip = hub.tip_height().unwrap_or(0);
        let ht = tip.saturating_add(1);
        st.record_height(hole, ht);
        st.height_to_hash.insert(ht, hole);
        st.body.mark_missing(hole);

        // Peer 0 slow, peer 1 fast, peer 2 medium — inject mature EWMA samples.
        for (i, bytes_per_sec) in [(0usize, 100_000u64), (1, 10_000_000u64), (2, 1_000_000u64)] {
            st.slots[i].rate.sample(0, 0, true);
            st.slots[i]
                .rate
                .sample(5_000, bytes_per_sec.saturating_mul(5), true);
        }
        // Cap want to 2 so only the top two speeds get work if ranking works.
        // TIP_HOLE_MAX_PEERS is 4 but we only have 3 peers — all may get work.
        // Assert peer 1 (fastest) is among inflight and peer order: 1 before 0.
        let cfg = IbdConfig::for_test();
        let alive: Vec<usize> = st.slots.iter().filter(|s| s.alive).map(|s| s.id).collect();
        let avoid = HashSet::new();
        let ranked = rank_peers_by_speed(&st.slots, &alive, &avoid);
        assert_eq!(ranked[0], 1, "fastest peer first: ranked={ranked:?}");
        assert_eq!(ranked[1], 2, "medium second: ranked={ranked:?}");
        assert_eq!(ranked[2], 0, "slow last: ranked={ranked:?}");

        let holes = contiguous_tip_holes(&mut st, &hub, 8);
        let issued = cover_tip_holes(&mut st, &hub, &cfg, &alive, &holes, TIP_HOLE_MAX_PEERS);
        assert!(issued >= 1, "issued={issued}");
        let peers = &st.inflight[&hole].peers;
        assert!(
            peers.contains(&1),
            "fast peer must be in tip-hole race; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_hung_owner_stolen_to_faster_peer() {
        let _env = lock_default_assign_stop();
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        req.asked_at.insert(0, req.started_at);
        st.inflight.insert(hung, req);
        st.slots[0].in_flight.insert(hung);
        seed_ewma(&mut st.slots[1], 1_000_000);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let peers = &st.inflight[&hung].peers;
        assert!(
            peers.contains(&1) && !peers.contains(&0),
            "hung densify must move to faster peer; peers={peers:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A steal never picks a peer that already holds the hash.
    #[test]
    fn steal_hung_densify_skips_a_peer_that_already_holds_the_hash() {
        let _env = lock_default_assign_stop();
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let long_ago = Instant::now() - Duration::from_secs(31);
        let mut req = InflightReq::new(2);
        req.started_at = long_ago;
        req.retire_peer(2);
        req.add_peer(1);
        req.asked_at.insert(1, long_ago);
        st.inflight.insert(hung, req);
        st.slots[1].in_flight.insert(hung);
        st.slots[2].in_flight.insert(hung);
        seed_ewma(&mut st.slots[0], 1_000_000);
        seed_ewma(&mut st.slots[2], 5_000_000);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.peers.contains(&0) && !r.peers.contains(&2),
            "steal goes to the free faster peer; peers={:?}",
            r.peers
        );
        assert!(r.holds(2), "retired holder keeps its request");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// No free slot on a faster peer must not erase the hung getdata. Once a
    /// slot frees, another peer is asked, including when the hash already
    /// fills the getdata window, and the hung peer is not asked again.
    #[test]
    fn steal_hung_densify_keeps_the_request_when_no_slot_is_free() {
        let _env = lock_default_assign_stop();
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let mut wire = Vec::new();
        for s in st.slots.iter_mut() {
            let (tx, rx) = mpsc::unbounded_channel();
            s.cmd_tx = tx;
            wire.push(rx);
        }
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 2;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let long_ago = Instant::now() - Duration::from_secs(31);
        let mut req = InflightReq::new(0);
        req.started_at = long_ago;
        req.asked_at.insert(0, long_ago);
        st.inflight.insert(hung, req);
        st.slots[0].in_flight.insert(hung);
        for n in 0..2 {
            st.slots[1].in_flight.insert(h(300 + n));
            st.slots[2].in_flight.insert(h(400 + n));
        }
        seed_ewma(&mut st.slots[1], 5_000_000);
        seed_ewma(&mut st.slots[2], 4_000_000);
        st.densify_scan_lo = 50;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.holds(0) && r.peers.is_empty(),
            "no free faster slot retires the hung owner; peers={:?} retired={:?}",
            r.peers,
            r.retired
        );
        assert!(st.slots[0].in_flight.contains(&hung));
        seed_ewma(&mut st.slots[0], 9_000_000);
        st.slots[1].in_flight.clear();
        cfg.window = 1;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let r = &st.inflight[&hung];
        assert!(
            r.peers.contains(&1) && r.holds(0) && !r.peers.contains(&0),
            "the freed peer is asked; the hung peer stays retired; peers={:?}",
            r.peers
        );
        let asks: Vec<usize> = wire
            .iter_mut()
            .map(|rx| {
                let mut n = 0;
                while let Ok(cmd) = rx.try_recv() {
                    if let PeerCmd::GetData { hashes } = cmd {
                        n += hashes.iter().filter(|&&x| x == hung).count();
                    }
                }
                n
            })
            .collect();
        assert_eq!(asks, vec![0, 1, 0], "hung peer is not asked again");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_slow_but_rx_live_not_stolen() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        st.inflight.insert(hung, req);
        st.slots[0].in_flight.insert(hung);
        st.slots[0].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut st.slots[1], 1_000_000);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight[&hung].peers.contains(&0),
            "live rx must not be stolen; peers={:?}",
            st.inflight[&hung].peers
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_hung_no_faster_peer_does_not_steal() {
        let _env = lock_default_assign_stop();
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        st.inflight.insert(hung, req);
        st.slots[0].in_flight.insert(hung);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight[&hung].peers.contains(&0),
            "solo hung densify has no faster peer to steal to"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_hung_no_slot_rewinds_scan_lo() {
        let _env = lock_default_assign_stop();
        use super::super::peer_io::ibd_mono_ms;
        use super::super::state::InflightReq;
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 1;
        cfg.per_peer = 2;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 41);
        hub.query
            .block_queue_offer(path_lo, h(path_lo).to_byte_array(), 1, &[0u8; 80])
            .unwrap();
        st.body.mark_pending(h(path_lo));
        let hung = h(40);
        let other = h(41);
        let mut req = InflightReq::new(0);
        req.started_at = Instant::now() - Duration::from_secs(31);
        req.asked_at.insert(0, req.started_at);
        st.inflight.insert(hung, req);
        st.slots[0].in_flight.insert(hung);
        st.inflight.insert(other, InflightReq::new(1));
        st.slots[1].in_flight.insert(other);
        st.slots[1].rate.note_rx(ibd_mono_ms().max(1));
        seed_ewma(&mut st.slots[1], 1_000_000);
        st.densify_scan_lo = 90;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let hung_req = &st.inflight[&hung];
        assert!(
            hung_req.holds(0) && hung_req.peers.is_empty(),
            "hung owner stays recorded when no faster slot is free; peers={:?} retired={:?}",
            hung_req.peers,
            hung_req.retired
        );
        assert!(st.slots[0].in_flight.contains(&hung));
        assert!(
            st.densify_scan_lo <= 40,
            "scan_lo must rewind to hung height; scan_lo={}",
            st.densify_scan_lo
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_issues_to_fastest_peer_first() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 40);
        mark_tip_batch_ready(&mut st, &hub, path_lo);
        seed_ewma(&mut st.slots[0], 100_000);
        seed_ewma(&mut st.slots[1], 10_000_000);
        seed_ewma(&mut st.slots[2], 1_000_000);
        st.densify_scan_lo = 40;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let want = h(40);
        assert!(
            st.inflight.get(&want).is_some_and(|r| r.peers.contains(&1)),
            "first densify hash must go to fastest peer; inflight={:?}",
            st.inflight.get(&want).map(|r| &r.peers)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Work freed below the densify cursor is requested again once the cursor
    /// is rewound, not only when it becomes a tip hole. The path ends below the
    /// cursor so the first pass has nothing to request and peer slots stay free.
    #[test]
    fn densify_reissues_work_reopened_below_scan_lo() {
        let _env = lock_default_assign_stop();
        use super::super::dial::release_peer_block_work;
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 49);
        mark_tip_batch_ready(&mut st, &hub, path_lo);
        seed_ewma(&mut st.slots[1], 1_000_000);
        seed_ewma(&mut st.slots[2], 1_000_000);
        let lost = h(45);
        st.inflight.insert(lost, InflightReq::new(0));
        st.slots[0].in_flight.insert(lost);
        st.densify_scan_lo = 50;
        let freed = release_peer_block_work(&mut st.slots, &mut st.inflight, &mut st.body, 0);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            !st.inflight.contains_key(&lost),
            "below the cursor, densify does not see freed work"
        );
        st.reopen_for_densify(&freed);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&lost),
            "reopened work is requested again; scan_lo={}",
            st.densify_scan_lo
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_skips_band_walk_when_peers_at_cap() {
        let _env = lock_default_assign_stop();
        use super::super::state::InflightReq;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 70);
        mark_tip_batch_ready(&mut st, &hub, path_lo);
        for i in 0..16u32 {
            let ht = 40 + i;
            let hash = h(ht);
            let pid = (i % 2) as usize;
            st.inflight.insert(hash, InflightReq::new(pid));
            st.slots[pid].in_flight.insert(hash);
        }
        st.densify_scan_lo = 40;
        let before_keys: HashSet<_> = st.inflight.keys().copied().collect();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        let after_keys: HashSet<_> = st.inflight.keys().copied().collect();
        assert_eq!(after_keys, before_keys, "no new densify when peers at cap");
        assert_eq!(
            st.densify_scan_lo, 40,
            "band walk must not advance scan_lo; scan_lo={}",
            st.densify_scan_lo
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_fast_peer_receives_more_than_eight() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(
            vec![dummy_slot(0), dummy_slot(1), dummy_slot(2)],
            hub.tip_hash(),
            hub.tip_height(),
        );
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;
        let path_lo = hub.tip_height().unwrap_or(0).saturating_add(1);
        plant_work_path(&mut st, path_lo, 52);
        mark_tip_batch_ready(&mut st, &hub, path_lo);
        seed_ewma(&mut st.slots[0], 5_000_000);
        seed_ewma(&mut st.slots[1], 15_000_000);
        seed_ewma(&mut st.slots[2], 5_000_000);
        st.densify_scan_lo = 33;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert_eq!(
            st.slots[1].in_flight.len(),
            16,
            "2×-median outlier must get full densify cap"
        );
        assert!(
            st.slots[0].in_flight.len() <= 8,
            "non-outlier stays at half cap; n={}",
            st.slots[0].in_flight.len()
        );
        assert!(
            st.slots[2].in_flight.len() <= 8,
            "non-outlier stays at half cap; n={}",
            st.slots[2].in_flight.len()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Densify-ahead zombie pending (flag set, no matching BQ) must re-get.
    /// Regression: need_hash_at used to skip all pending before BQ check, so
    /// heights past tip-batch cover never demoted and conf froze mid-IBD.
    #[test]
    fn densify_zombie_pending_regets_work_path() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 32;
        cfg.per_peer = 8;
        let want1 = h(0x31);
        let want2 = h(0x32);
        st.record_height(want1, 1);
        st.record_height(want2, 2);
        st.height_to_hash.insert(1, want1);
        st.height_to_hash.insert(2, want2);
        st.ordered_set.insert(want1);
        st.ordered_set.insert(want2);
        st.ordered.push_back(want1);
        st.ordered.push_back(want2);
        st.max_ordered_height = 2;
        // tip+1 claim-ready so densify walks to ht=2.
        hub.query
            .block_queue_offer(1, want1.to_byte_array(), 0, b"ok1")
            .unwrap();
        st.body.mark_pending(want1);
        // tip+2 zombie: pending without BQ wire.
        st.body.mark_pending(want2);
        assert!(!hub.query.block_queue_has_height(2));
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, 2, &want2),
            "zombie pending must not be claim-ready"
        );
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&want2),
            "densify must re-get zombie pending at ht=2; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        assert!(
            !st.body.is_pending(&want2),
            "need_hash_at must demote zombie pending before issue"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Densify band: wrong first-wins BQ at a height is dropped; work-path hash
    /// is requested (`need_hash_at` hash match, not height occupancy).
    #[test]
    fn densify_drops_wrong_bq_hash_and_regets_work_path() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 32;
        cfg.per_peer = 8;
        // tip+1 claim-ready (correct wire) so densify walks past tip hole.
        let want1 = h(0x11);
        let want2 = h(0x22);
        let wrong2 = h(0x99);
        st.record_height(want1, 1);
        st.record_height(want2, 2);
        st.height_to_hash.insert(1, want1);
        st.height_to_hash.insert(2, want2);
        st.ordered_set.insert(want1);
        st.ordered_set.insert(want2);
        st.ordered.push_back(want1);
        st.ordered.push_back(want2);
        st.max_ordered_height = 2;
        hub.query
            .block_queue_offer(1, want1.to_byte_array(), 0, b"ok1")
            .unwrap();
        st.body.mark_pending(want1);
        // Wrong first-wins at tip+2.
        hub.query
            .block_queue_offer(2, wrong2.to_byte_array(), 0, b"wrong2")
            .unwrap();
        assert!(
            !super::super::progress::claim_ready(&hub, &mut st.body, 2, &want2),
            "wrong BQ at ht=2 must not be claim-ready for want2"
        );
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&want2),
            "densify must re-get correct work-path hash at ht=2; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        assert!(
            !hub.query.block_queue_has_height(2)
                || hub
                    .query
                    .block_queue_hash_at_height(2)
                    .is_some_and(|x| x == want2.to_byte_array()),
            "wrong BQ body at densify height must be dequeued"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Reorg mid densify (1b) must issue getdata for need hash even when the
    /// same height's BQ slot holds a different first-wins body (height occupancy
    /// is not readiness — only `block_queue_has_hash` of the need).
    #[test]
    fn assign_reorg_need_despite_wrong_height_bq_occupant() {
        let _env = lock_default_assign_stop();
        use bitcoin::hashes::Hash as _;
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 16;
        cfg.per_peer = 4;
        let need = h(0xab);
        let wrong_occupant = h(0xde);
        // Mid recorded at height 1; BQ height 1 holds a different hash.
        st.record_height(need, 1);
        hub.query
            .block_queue_offer(1, wrong_occupant.to_byte_array(), 0, b"loser")
            .unwrap();
        assert!(hub.query.block_queue_has_height(1));
        assert!(!hub.query.block_queue_has_hash(&need.to_byte_array()));
        st.reorg.register_explore([need], None);
        st.body.mark_missing(need);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&need),
            "reorg need must getdata by hash despite wrong BQ height occupant; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn densify_requests_beyond_legacy_2k_when_soft_allows() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 16;

        // Past legacy 2048 ceiling with headroom; keep map/BQ setup small for suite speed.
        const HI: u32 = 2200;
        // Claim-ready prefix via tiny BQ so tip-hole race stops (pending without BQ
        // is a fetch hole). Fill through just under the legacy 2048 densify ceiling
        // so the first missing heights densify issues are already past that line.
        const FILL: u32 = 2040;
        let tiny = [0u8; 8];
        for ht in 1u32..=HI {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            if ht <= FILL {
                hub.query
                    .block_queue_enqueue(ht, hash.to_byte_array(), ht as u64, &tiny)
                    .unwrap();
                st.body.mark_pending(hash);
            } else {
                st.body.mark_missing(hash);
            }
        }

        // Under free floor — full densify ahead.
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);

        let far: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .filter(|&ht| ht > FILL)
            .collect();
        assert!(
            !far.is_empty(),
            "expected densify past claim-ready prefix; inflight heights={:?}",
            st.inflight
                .keys()
                .filter_map(|hash| st.hash_height.get(hash).copied())
                .collect::<Vec<_>>()
        );
        // Runtime pin: densify must issue heights past the legacy 2048 ceiling
        // (CONTIG_DENSIFY_AHEAD is 64k — not a constant-only check).
        assert!(
            far.iter().any(|&ht| ht > 2048),
            "legacy CONTIG_DENSIFY_AHEAD=2048 must not be the ceiling; far={far:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Over free-byte floor: densify only the confirm-time window (rate * 60s).
    #[test]
    fn densify_over_free_bytes_limited_to_confirm_window() {
        use rbitcoin_query::{soft_confirm_window_n, BQ_SOFT_FREE_BYTES};

        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        assert_eq!(hub.tip_height(), Some(0), "tip-accept genesis");
        // Genesis tip=0 → path_lo=1.
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;

        // Heights 1..=200 missing; fill BQ over free floor with fat payloads.
        for ht in 1u32..=200 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // ~110 MiB in queue (two ~55 MiB chunks) → restricted.
        let chunk = vec![0u8; 55 * 1024 * 1024];
        hub.query
            .block_queue_enqueue(1, h(1).to_byte_array(), 1, &chunk)
            .unwrap();
        hub.query
            .block_queue_enqueue(2, h(2).to_byte_array(), 2, &chunk)
            .unwrap();
        st.body.mark_pending(h(1));
        st.body.mark_pending(h(2));
        assert!(hub.query.block_queue_stats().1 > BQ_SOFT_FREE_BYTES);

        // 0.1 blk/s × 60s → window of 6 heights (path_lo=1 → band_hi=6).
        let rate = Some(0.1);
        let win = soft_confirm_window_n(rate);
        assert_eq!(win, 6);
        let path_lo = 1u32;
        let band_hi = path_lo + win - 1;

        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, rate);

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            !issued_hts.is_empty(),
            "expected densify inside confirm window; issued={issued_hts:?}"
        );
        assert!(
            issued_hts.iter().all(|&ht| ht <= band_hi),
            "no densify past confirm window {band_hi}; issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Under free-byte floor: full densify ahead even with many queued blocks.
    #[test]
    fn densify_under_free_bytes_uses_full_ahead() {
        use rbitcoin_query::BQ_SOFT_FREE_BYTES;

        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        // Genesis tip=0 → path_lo=1.
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 16;

        for ht in 1u32..=100 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // Tiny payloads well under free floor.
        for ht in 1u32..=10 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        assert!(hub.query.block_queue_stats().1 < BQ_SOFT_FREE_BYTES);

        // Rate would only allow 6 if restricted — must still densify past that.
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(0.1));

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            issued_hts.iter().any(|&ht| ht > 16),
            "under free bytes: densify past 1-min window; issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Filled BQ prefix must advance densify_scan_lo so the next tick skips it.
    #[test]
    fn densify_watermark_skips_bq_ready_prefix() {
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 64;

        for ht in 1u32..=80 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        for ht in 1u32..=40 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.densify_scan_lo >= 41,
            "BQ-ready 1..=40 must bump scan_lo; scan_lo={}",
            st.densify_scan_lo
        );
        let issued_low = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .filter(|&ht| ht <= 40)
            .count();
        assert_eq!(issued_low, 0, "must not getdata heights already on BQ");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Serialize env mutators — parallel suite races `bq_assign_stop_bytes`.
    static BQ_ASSIGN_STOP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(in crate::ibd) struct AssignStopEnvRestore(
        Option<std::ffi::OsString>,
        Option<std::ffi::OsString>,
    );
    impl Drop for AssignStopEnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", v),
                None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES"),
            }
            match self.1.take() {
                Some(v) => std::env::set_var("RBITCOIN_BLOCK_QUEUE_GB", v),
                None => std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB"),
            }
        }
    }

    pub(in crate::ibd) fn lock_default_assign_stop(
    ) -> (std::sync::MutexGuard<'static, ()>, AssignStopEnvRestore) {
        let g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let restore = AssignStopEnvRestore(
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES"),
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB"),
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        (g, restore)
    }

    /// Over assign-stop: densify within confirm window ∩ fetched; not past window.
    #[test]
    fn densify_over_assign_stop_clamps_window_and_fetched() {
        let _g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = AssignStopEnvRestore(
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES"),
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB"),
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "2048");

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 128;
        cfg.per_peer = 64;

        for ht in 1u32..=500 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        // Tip batch already fetched so densify is not starved by tip-hole slots.
        for ht in 1u32..=TIP_HOLE_MAX as u32 {
            hub.query
                .block_queue_enqueue(ht, h(ht).to_byte_array(), ht as u64, b"x")
                .unwrap();
            st.body.mark_pending(h(ht));
        }
        // Far fetched_hi=500 trips assign-stop; rate 5 → confirm window 300.
        let chunk = vec![0u8; 4096];
        hub.query
            .block_queue_enqueue(500, h(500).to_byte_array(), 500, &chunk)
            .unwrap();
        st.body.mark_pending(h(500));
        assert!(hub.query.block_queue_stats().1 >= 2048);
        assert_eq!(hub.query.block_queue_max_height(), Some(500));

        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));

        let issued_hts: Vec<u32> = st
            .inflight
            .keys()
            .filter_map(|hash| st.hash_height.get(hash).copied())
            .collect();
        assert!(
            issued_hts.is_empty(),
            "queue already at the assign-stop: no new getdata; issued={issued_hts:?}"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Most-work reorg densify: assign issues getdata for need_getdata hashes.
    #[test]
    fn assign_issues_reorg_need_getdata() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 16;
        cfg.per_peer = 4;
        let need = h(0xab);
        st.reorg.register_explore([need], None);
        st.body.mark_missing(need);
        assert_eq!(st.reorg.need_getdata(), vec![need]);
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.contains_key(&need),
            "reorg need_getdata must be issued as getdata"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn assign_depth_densify_cache_and_early_exits() {
        let _env = lock_default_assign_stop();
        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let mut st = IbdWorkState::new(vec![dummy_slot(0), dummy_slot(1)], None, Some(0));
        let stats = LoopStats::default();
        let mut cfg = IbdConfig::for_test();
        cfg.window = 64;
        cfg.per_peer = 8;

        for ht in 1u32..=12 {
            let hash = h(ht);
            st.record_height(hash, ht);
            st.height_to_hash.insert(ht, hash);
            st.ordered_set.insert(hash);
            st.ordered.push_back(hash);
            st.max_ordered_height = ht;
            st.body.mark_missing(hash);
        }
        plant_quarter_window(&hub, 1);

        assign_work_ordered(
            &mut st,
            &hub,
            &cfg,
            &stats,
            AssignDepth::Critical,
            Some(5.0),
        );
        let after_crit = st.inflight.len();
        assert!(after_crit > 0, "critical should still issue tip/race");

        let n_before = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, Some(5.0));
        assert!(st.inflight.len() <= n_before + 8);

        let hashes: Vec<_> = st.inflight.keys().copied().collect();
        for hash in hashes {
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            st.body.mark_missing(hash);
        }
        st.body.mark_pending(h(5));
        let _ = st
            .body
            .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
        st.body.mark_pending(h(5));
        st.body.mark_pending(h(1));
        let expired = st
            .body
            .expire_stale_pending_if(std::time::Duration::ZERO, |_| true);
        for hash in expired {
            clear_hash_inflight(&mut st.slots, &mut st.inflight, hash);
            st.body.mark_missing(hash);
        }

        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(!st.inflight.is_empty());
        assert!(stats.assign_issued.load(Ordering::Relaxed) > 0);

        for ht in 20u32..20 + cfg.window as u32 {
            let hash = h(ht + 100);
            inflight_add_peer(&mut st.inflight, hash, 0);
            st.slots[0].in_flight.insert(hash);
        }
        let n_full = st.inflight.len();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(st.inflight.len() <= n_full + 2);

        st.inflight.clear();
        st.slots[0].in_flight.clear();
        st.slots[1].in_flight.clear();
        for ht in 1u32..=4 {
            let hash = h(ht);
            st.body.mark_missing(hash);
        }
        for i in 0..cfg.per_peer {
            let hash = h(200 + i as u32);
            st.slots[0].in_flight.insert(hash);
            inflight_add_peer(&mut st.inflight, hash, 0);
        }
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(!st.slots[1].in_flight.is_empty() || st.inflight.len() > cfg.per_peer);

        // Claim-ready: pending **with** body-queue wire (not Class A alone).
        // Zombie pending without BQ is a tip fetch hole (cover_tip_holes re-gets).
        let tiny = [0u8; 8];
        for ht in 1u32..=12 {
            let hash = h(ht);
            hub.query
                .block_queue_enqueue(ht, hash.to_byte_array(), ht as u64, &tiny)
                .unwrap();
            st.body.mark_pending(hash);
        }
        st.inflight.clear();
        st.slots.iter_mut().for_each(|s| s.in_flight.clear());
        st.max_ready_height = 12;
        st.max_ordered_height = 12;
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            st.inflight.is_empty(),
            "claim-ready tip band must not re-get; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn hostile_peer_session() {
        let _g = BQ_ASSIGN_STOP_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = AssignStopEnvRestore(
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_BYTES"),
            std::env::var_os("RBITCOIN_BLOCK_QUEUE_GB"),
        );
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_GB");
        std::env::remove_var("RBITCOIN_BLOCK_QUEUE_BYTES");

        let (dir, hub) = tmp_hub();
        hub.ensure_genesis().unwrap();
        let four_mib = GETDATA_RESERVE_BYTES;
        let mut st = IbdWorkState::new(vec![dummy_slot(0)], hub.tip_hash(), hub.tip_height());
        st.intake_queued = 0;
        st.intake_stop = four_mib - 1;
        let mut room = 10usize;
        let mut issued = 0u64;
        assert!(
            !issue_one(&mut st, 0, h(32), &mut room, &mut issued),
            "one byte under 4 MiB cannot reserve a new hash"
        );
        assert!(st.inflight.is_empty());

        st.intake_stop = four_mib;
        assert!(
            issue_one(&mut st, 0, h(31), &mut room, &mut issued),
            "one new hash fits in exactly 4 MiB"
        );
        assert!(st.inflight.contains_key(&h(31)));
        let before = st.inflight.len();
        assert!(
            !issue_one(&mut st, 0, h(33), &mut room, &mut issued),
            "a second hash would pass the 4 MiB stop"
        );
        assert_eq!(st.inflight.len(), before);
        assert!(!st.inflight.contains_key(&h(33)));

        std::env::set_var("RBITCOIN_BLOCK_QUEUE_BYTES", "1000");
        plant_work_path(&mut st, 1, 2);
        let queued = vec![0u8; 1000];
        hub.query
            .block_queue_enqueue(50, h(50).to_byte_array(), 50, &queued)
            .unwrap();
        assert!(hub.query.block_queue_stats().1 >= 1000);
        let stats = LoopStats::default();
        let cfg = IbdConfig::for_test();
        assign_work_ordered(&mut st, &hub, &cfg, &stats, AssignDepth::Full, None);
        assert!(
            !st.inflight.contains_key(&h(1)) && !st.inflight.contains_key(&h(2)),
            "queue already at the stop: no new getdata; inflight={:?}",
            st.inflight.keys().collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
