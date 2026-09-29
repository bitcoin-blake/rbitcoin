//! Header chain ahead of the body window.
//!
//! One `getheaders` window is in flight. A second outbound peer must return the
//! same prefix before those headers are stored or can open the milestone gate.
//! A peer with that request outstanding is not given block `getdata`. The
//! ordered body window stays at [`ORDERED_HEADERS_SOFT_CAP`].

use super::dial::request_headers_from;
use super::events::enqueue_scanned_header;
use super::path::work_path_tips;
use super::progress::ibd_pct;
use super::state::IbdWorkState;
use super::ORDERED_HEADERS_SOFT_CAP;
use crate::chain::ChainHub;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

const AWAIT: Duration = Duration::from_secs(30);
const COOLDOWN: Duration = Duration::from_secs(600);
const CURSOR_NAME: &str = "header.adopt";
const CURSOR_MAGIC: &[u8; 8] = b"rbtchdr1";

#[derive(Clone, Debug)]
enum Phase {
    Idle,
    Primary {
        peer: usize,
        since: Instant,
    },
    Witness {
        primary: usize,
        witness: Option<usize>,
        since: Instant,
        headers: Vec<Header>,
        failed: Vec<(usize, Vec<Header>)>,
    },
}

/// Adopted header tip plus the in-flight two-peer window.
#[derive(Debug)]
pub(crate) struct HeaderScan {
    pub done: bool,
    /// Set once IBD starts the scan. Until then, header batches stay on the
    /// pre-scan path so existing intake tests are unchanged.
    engaged: bool,
    phase: Phase,
    origin_set: bool,
    adopted_height: u32,
    adopted_hash: Option<BlockHash>,
    served: HashMap<usize, u32>,
    cooldown: HashMap<usize, Instant>,
    empty_from: HashSet<usize>,
    milestone_logged: bool,
    done_logged: bool,
}

impl Default for HeaderScan {
    fn default() -> Self {
        Self {
            done: false,
            engaged: false,
            phase: Phase::Idle,
            origin_set: false,
            adopted_height: 0,
            adopted_hash: None,
            served: HashMap::new(),
            cooldown: HashMap::new(),
            empty_from: HashSet::new(),
            milestone_logged: false,
            done_logged: false,
        }
    }
}

impl HeaderScan {
    fn outstanding(&self) -> Option<usize> {
        match &self.phase {
            Phase::Primary { peer, .. } => Some(*peer),
            Phase::Witness {
                witness: Some(peer),
                ..
            } => Some(*peer),
            _ => None,
        }
    }

    fn ensure_origin(&mut self, hub: &ChainHub) {
        if self.origin_set {
            return;
        }
        self.adopted_height = hub.tip_height().unwrap_or(0);
        self.adopted_hash = hub.tip_hash();
        self.origin_set = true;
    }
}

/// True while `pid` has been sent `getheaders` and has not answered.
pub(crate) fn peer_awaits_headers(st: &IbdWorkState, pid: usize) -> bool {
    st.header_scan.outstanding() == Some(pid)
}

/// The scan owns `getheaders` while a witnessed window is in flight or two
/// peers can serve one. One live peer keeps the body-window fetch.
pub(crate) fn blocks_body_fetch(st: &IbdWorkState) -> bool {
    if st.header_scan.done {
        return false;
    }
    if !matches!(st.header_scan.phase, Phase::Idle) {
        return true;
    }
    eligible_header_peers(st, Instant::now()) >= 2
}

/// One peer's body-window headers must not open the milestone gate.
pub(crate) fn owns_milestone(st: &IbdWorkState) -> bool {
    st.header_scan.engaged && !st.header_scan.done
}

/// The outstanding header peer died. A held primary batch stays until a witness answers.
pub(crate) fn on_peer_dead(st: &mut IbdWorkState, peer: usize) {
    if st.header_scan.done {
        return;
    }
    let drop_primary = matches!(
        st.header_scan.phase,
        Phase::Primary { peer: p, .. } if p == peer
    );
    if drop_primary {
        st.header_scan.phase = Phase::Idle;
        return;
    }
    if let Phase::Witness { witness, .. } = &mut st.header_scan.phase {
        if *witness == Some(peer) {
            *witness = None;
        }
    }
}

pub(crate) fn format_headers_progress(height: u32, horizon: u32, work_ok: bool) -> String {
    let pct = ibd_pct(height, horizon);
    format!(
        "ibd: headers height={height} ({pct}%) horizon={horizon} work={}",
        work_word(work_ok)
    )
}

pub(crate) fn format_headers_milestone(height: u32, hash: &str) -> String {
    format!("ibd: headers milestone height={height} hash={hash} work=ok (script/sig skip at/below)")
}

pub(crate) fn format_headers_done(height: u32, horizon: u32, work_ok: bool) -> String {
    let pct = ibd_pct(height, horizon.max(height));
    format!(
        "ibd: headers done height={height} ({pct}%) work={}",
        work_word(work_ok)
    )
}

pub(crate) fn format_headers_resume(height: u32, horizon: u32, work_ok: bool) -> String {
    let pct = ibd_pct(height, horizon);
    format!(
        "ibd: headers resume height={height} ({pct}%) work={}",
        work_word(work_ok)
    )
}

fn work_word(work_ok: bool) -> &'static str {
    if work_ok {
        "ok"
    } else {
        "below"
    }
}

/// `None` when this peer's batch belonged to the scan.
pub(crate) fn take_headers(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    headers: Vec<Header>,
    now: Instant,
) -> Option<Vec<Header>> {
    if !st.header_scan.engaged || st.header_scan.done {
        return Some(headers);
    }
    // A batch that is not the in-flight witnessed window does not move the
    // adopted tip. The body window still accepts it when the scan is not the
    // one asking (a lone peer, or every other peer is cooling).
    if !expects(st, peer) {
        if blocks_body_fetch(st) {
            return None;
        }
        return Some(headers);
    }
    let phase = std::mem::replace(&mut st.header_scan.phase, Phase::Idle);
    match phase {
        Phase::Primary { peer: want, .. } if want == peer => {
            if release_to_body(st, hub, peer, &headers, now) {
                note_served(st, peer);
                return Some(headers);
            }
            on_primary(st, hub, peer, headers, now);
            None
        }
        Phase::Witness {
            primary,
            witness: Some(want),
            headers: primary_headers,
            failed,
            since: _,
        } if want == peer => {
            on_witness(
                st,
                hub,
                WitnessIn {
                    primary,
                    headers: primary_headers,
                    failed,
                },
                peer,
                headers,
                now,
            );
            None
        }
        other => {
            st.header_scan.phase = other;
            Some(headers)
        }
    }
}

fn expects(st: &IbdWorkState, peer: usize) -> bool {
    st.header_scan.outstanding() == Some(peer)
}

fn on_primary(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    headers: Vec<Header>,
    now: Instant,
) {
    note_served(st, peer);
    if headers.is_empty() {
        note_empty(st, hub, peer, now);
        return;
    }
    if !extends_adopted(st, hub, &headers) {
        warn_diverge(st, peer);
        cool(st, peer, now);
        ask_primary(st, hub, now);
        return;
    }
    st.header_scan.phase = Phase::Witness {
        primary: peer,
        witness: None,
        since: now,
        headers,
        failed: Vec::new(),
    };
    ask_witness(st, hub, now);
}

struct WitnessIn {
    primary: usize,
    headers: Vec<Header>,
    failed: Vec<(usize, Vec<Header>)>,
}

fn on_witness(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    prior: WitnessIn,
    witness: usize,
    headers: Vec<Header>,
    now: Instant,
) {
    let WitnessIn {
        primary,
        headers: primary_headers,
        mut failed,
    } = prior;
    note_served(st, witness);
    if headers.is_empty() {
        failed.push((witness, Vec::new()));
        hold_or_drop(st, hub, primary, primary_headers, failed, now);
        return;
    }
    if let Some(n) = agreed_prefix(&primary_headers, &headers) {
        if let Some((id, _)) = failed.iter().find(|(_, h)| !h.is_empty()) {
            warn_diverge(st, *id);
        }
        for (id, _) in &failed {
            cool(st, *id, now);
        }
        commit(st, hub, &primary_headers[..n], now);
        return;
    }
    if let Some((n, src)) = failed.iter().find_map(|(id, prev)| {
        agreed_prefix(prev, &headers)
            .filter(|_| *id != primary)
            .map(|n| (n, prev.clone()))
    }) {
        warn_diverge(st, primary);
        cool(st, primary, now);
        for (id, prev) in &failed {
            if agreed_prefix(prev, &headers).is_none() {
                cool(st, *id, now);
            }
        }
        commit(st, hub, &src[..n], now);
        return;
    }
    failed.push((witness, headers));
    hold_or_drop(st, hub, primary, primary_headers, failed, now);
}

fn hold_or_drop(
    st: &mut IbdWorkState,
    hub: &ChainHub,
    primary: usize,
    primary_headers: Vec<Header>,
    failed: Vec<(usize, Vec<Header>)>,
    now: Instant,
) {
    let empties = failed.iter().filter(|(_, h)| h.is_empty()).count();
    let disagree = failed.iter().filter(|(_, h)| !h.is_empty()).count();
    if disagree >= 2 || (empties >= 2 && disagree == 0) {
        if disagree > 0 {
            if let Some((id, _)) = failed.iter().find(|(_, h)| !h.is_empty()) {
                warn_diverge(st, *id);
            }
        }
        for (id, batch) in &failed {
            if !batch.is_empty() || disagree >= 2 {
                cool(st, *id, now);
            }
        }
        cool(st, primary, now);
        ask_primary(st, hub, now);
        return;
    }
    st.header_scan.phase = Phase::Witness {
        primary,
        witness: None,
        since: now,
        headers: primary_headers,
        failed,
    };
    ask_witness(st, hub, now);
}

/// Send the next primary `getheaders`, or a witness for the batch already held.
pub(crate) fn poll(st: &mut IbdWorkState, hub: &ChainHub, now: Instant) {
    st.header_scan.engaged = true;
    st.header_scan.ensure_origin(hub);
    admit(st, hub);
    if st.header_scan.done {
        return;
    }
    if timed_out(st, now) {
        if let Some(pid) = st.header_scan.outstanding() {
            cool(st, pid, now);
        }
        st.header_scan.phase = Phase::Idle;
    }
    // A lone peer cannot witness the milestone path. Leave getheaders to the
    // body window so IBD still connects.
    if matches!(st.header_scan.phase, Phase::Idle) && eligible_header_peers(st, now) < 2 {
        return;
    }
    match &st.header_scan.phase {
        Phase::Idle => ask_primary(st, hub, now),
        Phase::Witness { witness: None, .. } => ask_witness(st, hub, now),
        _ => {}
    }
}

pub(crate) fn log_progress(st: &IbdWorkState, hub: &ChainHub) {
    if st.header_scan.done {
        return;
    }
    info!(
        "{}",
        format_headers_progress(
            st.header_scan.adopted_height,
            st.max_peer_height,
            work_ok(hub)
        )
    );
}

/// Reload an adopted tip from `header.adopt`. A missing or mismatched file
/// does not open a height-only skip.
pub(crate) fn restore(st: &mut IbdWorkState, hub: &ChainHub) {
    st.header_scan.ensure_origin(hub);
    let Some(dir) = store_dir(hub) else {
        return;
    };
    let Some(cursor) = Cursor::load(&dir) else {
        return;
    };
    if !replay_cursor(hub, &cursor) {
        return;
    }
    st.header_scan.adopted_height = cursor.height;
    st.header_scan.adopted_hash = Some(BlockHash::from_byte_array(cursor.hash));
    st.header_scan.origin_set = true;
    info!(
        "{}",
        format_headers_resume(cursor.height, st.max_peer_height, work_ok(hub))
    );
    maybe_log_milestone(st, hub);
    if st.max_peer_height > 0 && cursor.height >= st.max_peer_height {
        finish(st, hub);
    }
}

fn timed_out(st: &IbdWorkState, now: Instant) -> bool {
    let since = match &st.header_scan.phase {
        Phase::Primary { since, .. } => Some(*since),
        Phase::Witness {
            witness: Some(_),
            since,
            ..
        } => Some(*since),
        _ => None,
    };
    since.is_some_and(|t| now.duration_since(t) > AWAIT)
}

fn ask_primary(st: &mut IbdWorkState, hub: &ChainHub, now: Instant) {
    if st.header_scan.done || !matches!(st.header_scan.phase, Phase::Idle) {
        return;
    }
    let Some(peer) = pick_peer(st, now, &[]) else {
        return;
    };
    if !send_locator(st, hub, peer) {
        return;
    }
    st.header_scan.phase = Phase::Primary { peer, since: now };
}

fn ask_witness(st: &mut IbdWorkState, hub: &ChainHub, now: Instant) {
    let Phase::Witness {
        primary,
        witness,
        failed,
        ..
    } = &st.header_scan.phase
    else {
        return;
    };
    if witness.is_some() {
        return;
    }
    let mut skip = vec![*primary];
    skip.extend(failed.iter().map(|(id, _)| *id));
    let Some(peer) = pick_peer(st, now, &skip) else {
        return;
    };
    if !send_locator(st, hub, peer) {
        return;
    }
    if let Phase::Witness { witness, since, .. } = &mut st.header_scan.phase {
        *witness = Some(peer);
        *since = now;
    }
}

fn peer_can_serve_headers(st: &IbdWorkState, id: usize, now: Instant) -> bool {
    let Some(s) = st.slots.iter().find(|s| s.id == id) else {
        return false;
    };
    s.alive
        && s.in_flight.is_empty()
        && st.header_scan.outstanding() != Some(id)
        && st
            .header_scan
            .cooldown
            .get(&id)
            .is_none_or(|until| *until <= now)
}

fn eligible_header_peers(st: &IbdWorkState, now: Instant) -> usize {
    st.slots
        .iter()
        .filter(|s| peer_can_serve_headers(st, s.id, now))
        .count()
}

/// No second peer can confirm this batch. The body window may still take it.
fn release_to_body(
    st: &IbdWorkState,
    hub: &ChainHub,
    peer: usize,
    headers: &[Header],
    now: Instant,
) -> bool {
    // A peer busy with blocks can still witness once those blocks drain.
    // Only a missing or cooling peer releases this batch to the body window.
    let other = st.slots.iter().any(|s| {
        s.id != peer
            && s.alive
            && st
                .header_scan
                .cooldown
                .get(&s.id)
                .is_none_or(|until| *until <= now)
    });
    if other {
        return false;
    }
    if headers.is_empty() {
        return st.header_scan.adopted_height <= hub.tip_height().unwrap_or(0);
    }
    extends_adopted(st, hub, headers)
}

fn pick_peer(st: &IbdWorkState, now: Instant, skip: &[usize]) -> Option<usize> {
    let mut best: Option<(u32, usize)> = None;
    for s in &st.slots {
        if skip.contains(&s.id) || !peer_can_serve_headers(st, s.id, now) {
            continue;
        }
        let n = st.header_scan.served.get(&s.id).copied().unwrap_or(0);
        let cand = (n, s.id);
        if best.is_none_or(|b| cand < b) {
            best = Some(cand);
        }
    }
    best.map(|(_, id)| id)
}

fn send_locator(st: &mut IbdWorkState, hub: &ChainHub, peer: usize) -> bool {
    let tips = locator_tips(st);
    request_headers_from(&st.slots, peer, hub, &mut st.header_req_seq, &tips).unwrap_or(false)
}

fn locator_tips(st: &IbdWorkState) -> Vec<BlockHash> {
    if let Some(h) = st.header_scan.adopted_hash {
        vec![h]
    } else {
        work_path_tips(st)
    }
}

fn extends_adopted(st: &IbdWorkState, hub: &ChainHub, headers: &[Header]) -> bool {
    let Some(first) = headers.first() else {
        return false;
    };
    match st.header_scan.adopted_hash {
        Some(h) => first.prev_blockhash == h,
        None => hub.tip_hash() == Some(first.prev_blockhash) || hub.tip_hash().is_none(),
    }
}

fn agreed_prefix(primary: &[Header], witness: &[Header]) -> Option<usize> {
    if primary.is_empty() || witness.is_empty() {
        return None;
    }
    let n = primary
        .iter()
        .zip(witness.iter())
        .take_while(|(a, b)| a.block_hash() == b.block_hash())
        .count();
    if n == 0 || witness.len() != n {
        return None;
    }
    let mid = n / 2;
    if primary[mid].block_hash() != witness[mid].block_hash() {
        return None;
    }
    Some(n)
}

fn commit(st: &mut IbdWorkState, hub: &ChainHub, headers: &[Header], now: Instant) {
    st.header_scan.phase = Phase::Idle;
    st.header_scan.empty_from.clear();
    let mut prev = st
        .header_scan
        .adopted_hash
        .or_else(|| hub.tip_hash())
        .unwrap_or_else(|| headers[0].prev_blockhash);
    let mut height = st.header_scan.adopted_height;
    let mut batch = Vec::with_capacity(headers.len());
    for hdr in headers {
        if hdr.prev_blockhash != prev {
            break;
        }
        batch.push(*hdr);
        prev = hdr.block_hash();
    }
    if batch.is_empty() {
        ask_primary(st, hub, now);
        return;
    }
    let Ok(fks) = hub.ensure_headers_batch(&batch) else {
        ask_primary(st, hub, now);
        return;
    };
    let mut prev_hash = batch[0].prev_blockhash;
    for (hdr, fk) in batch.iter().zip(fks) {
        height = height.saturating_add(1);
        let hash = hdr.block_hash();
        let base = if hub.tip_hash() == Some(hdr.prev_blockhash) {
            hub.chain_work().ok()
        } else {
            None
        };
        hub.query.note_milestone_header(
            height,
            hash.to_byte_array(),
            prev_hash.to_byte_array(),
            hdr.work(),
            base,
        );
        st.header_fks.insert(hash, fk);
        let _ = enqueue_scanned_header(st, hub, hash, prev_hash, height);
        prev_hash = hash;
        st.header_scan.adopted_hash = Some(hash);
        st.header_scan.adopted_height = height;
    }
    if let Some(hash) = st.header_scan.adopted_hash {
        let _ = Cursor {
            height: st.header_scan.adopted_height,
            hash: hash.to_byte_array(),
            work: hub.query.milestone_best_work_be().unwrap_or([0u8; 32]),
        }
        .store(store_dir(hub).as_deref());
    }
    maybe_log_milestone(st, hub);
    admit(st, hub);
    ask_primary(st, hub, now);
}

/// Pull the next adopted headers into `ordered` while it is under the soft cap.
pub(crate) fn admit(st: &mut IbdWorkState, hub: &ChainHub) {
    let tip = hub.tip_height().unwrap_or(0);
    while st.ordered.len() < ORDERED_HEADERS_SOFT_CAP {
        let ht = if st.ordered_set.is_empty() {
            tip.saturating_add(1)
        } else {
            st.max_ordered_height.saturating_add(1)
        };
        if ht == 0 || ht > st.header_scan.adopted_height {
            break;
        }
        let Some(hash_b) = hub.query.milestone_header_at(ht) else {
            break;
        };
        let hash = BlockHash::from_byte_array(hash_b);
        if hub.has_block(&hash) || st.ordered_set.contains(&hash) {
            st.max_ordered_height = st.max_ordered_height.max(ht);
            continue;
        }
        let prev = if ht == tip.saturating_add(1) {
            match hub.tip_hash() {
                Some(t) => t,
                None => break,
            }
        } else {
            match hub.query.milestone_header_at(ht.saturating_sub(1)) {
                Some(p) => BlockHash::from_byte_array(p),
                None => break,
            }
        };
        if !enqueue_scanned_header(st, hub, hash, prev, ht) {
            break;
        }
    }
}

fn note_empty(st: &mut IbdWorkState, hub: &ChainHub, peer: usize, now: Instant) {
    st.header_scan.empty_from.insert(peer);
    let height = st.header_scan.adopted_height;
    let caught = st.max_peer_height > 0 && height >= st.max_peer_height;
    let busy = st.slots.iter().any(|s| s.alive && !s.in_flight.is_empty());
    let idle_left = st.slots.iter().any(|s| {
        s.alive
            && s.in_flight.is_empty()
            && !st.header_scan.empty_from.contains(&s.id)
            && st
                .header_scan
                .cooldown
                .get(&s.id)
                .is_none_or(|until| *until <= now)
    });
    if caught || (!busy && !idle_left && !st.header_scan.empty_from.is_empty()) {
        finish(st, hub);
    } else {
        ask_primary(st, hub, now);
    }
}

fn finish(st: &mut IbdWorkState, hub: &ChainHub) {
    st.header_scan.done = true;
    st.header_scan.phase = Phase::Idle;
    st.headers_done = true;
    if st.header_scan.done_logged {
        return;
    }
    st.header_scan.done_logged = true;
    info!(
        "{}",
        format_headers_done(
            st.header_scan.adopted_height,
            st.max_peer_height,
            work_ok(hub)
        )
    );
}

fn maybe_log_milestone(st: &mut IbdWorkState, hub: &ChainHub) {
    if st.header_scan.milestone_logged || !anchored_gate_open(hub) {
        return;
    }
    let Some(anchor) = hub.milestone.anchor else {
        return;
    };
    info!(
        "{}",
        format_headers_milestone(hub.milestone.height, &anchor.hash.to_string())
    );
    st.header_scan.milestone_logged = true;
}

fn anchored_gate_open(hub: &ChainHub) -> bool {
    let Some(anchor) = hub.milestone.anchor else {
        return false;
    };
    if hub.milestone.height == 0 {
        return false;
    }
    let at = hub.query.milestone_header_at(hub.milestone.height);
    let work = hub.query.milestone_best_work_be();
    at.as_ref() == Some(anchor.hash.as_byte_array())
        && work.is_some_and(|w| w >= anchor.min_work_be)
}

fn work_ok(hub: &ChainHub) -> bool {
    match hub.milestone.anchor {
        None => true,
        Some(anchor) => hub
            .query
            .milestone_best_work_be()
            .is_some_and(|w| w >= anchor.min_work_be),
    }
}

fn note_served(st: &mut IbdWorkState, peer: usize) {
    *st.header_scan.served.entry(peer).or_insert(0) += 1;
}

fn cool(st: &mut IbdWorkState, peer: usize, now: Instant) {
    st.header_scan.cooldown.insert(peer, now + COOLDOWN);
}

fn warn_diverge(st: &IbdWorkState, peer: usize) {
    let addr = st
        .slots
        .iter()
        .find(|s| s.id == peer)
        .map(|s| s.addr.to_string())
        .unwrap_or_else(|| format!("peer{peer}"));
    warn!(
        "ibd: headers diverge height={} peer={addr} (not adopted)",
        st.header_scan.adopted_height.saturating_add(1)
    );
}

fn store_dir(hub: &ChainHub) -> Option<std::path::PathBuf> {
    Some(hub.query.store().path().to_path_buf())
}

struct Cursor {
    height: u32,
    hash: [u8; 32],
    work: [u8; 32],
}

impl Cursor {
    fn load(dir: &Path) -> Option<Self> {
        let buf = std::fs::read(dir.join(CURSOR_NAME)).ok()?;
        if buf.len() != 8 + 4 + 32 + 32 || buf.get(..8) != Some(CURSOR_MAGIC.as_slice()) {
            return None;
        }
        let height = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let mut hash = [0u8; 32];
        let mut work = [0u8; 32];
        hash.copy_from_slice(&buf[12..44]);
        work.copy_from_slice(&buf[44..76]);
        Some(Self { height, hash, work })
    }

    fn store(&self, dir: Option<&Path>) -> bool {
        let Some(dir) = dir else {
            return false;
        };
        let mut buf = Vec::with_capacity(76);
        buf.extend_from_slice(CURSOR_MAGIC);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.hash);
        buf.extend_from_slice(&self.work);
        let tmp = dir.join(format!("{CURSOR_NAME}.tmp"));
        let dest = dir.join(CURSOR_NAME);
        let mut f = match std::fs::File::create(&tmp) {
            Ok(f) => f,
            Err(_) => return false,
        };
        if f.write_all(&buf).is_err() || f.sync_all().is_err() {
            return false;
        }
        drop(f);
        std::fs::rename(&tmp, &dest).is_ok()
    }
}

fn stored_header(hub: &ChainHub, hash: &[u8; 32]) -> Option<rbitcoin_store::HeaderRecord> {
    match hub.query.get_header_by_hash(hash) {
        Ok(Some((_, rec))) if rec.hash == *hash => Some(rec),
        _ => None,
    }
}

fn parent_hash(hub: &ChainHub, rec: &rbitcoin_store::HeaderRecord) -> Option<[u8; 32]> {
    if rec.prev_fk.is_null() {
        return Some([0u8; 32]);
    }
    hub.query
        .store()
        .get_header(rec.prev_fk)
        .ok()
        .map(|p| p.hash)
}

/// The cursor names the confirmed tip. Restore its work and do not walk.
fn replay_at_tip(hub: &ChainHub, cursor: &Cursor, tip_h: u32) -> bool {
    let Some(tip) = hub.tip_hash() else {
        return false;
    };
    if tip.to_byte_array() != cursor.hash {
        return false;
    }
    hub.query.note_milestone_header(
        tip_h,
        cursor.hash,
        [0u8; 32],
        bitcoin::Work::from_be_bytes([0u8; 32]),
        Some(bitcoin::Work::from_be_bytes(cursor.work)),
    );
    hub.query.milestone_best_work_be() == Some(cursor.work)
}

struct WalkedHeader {
    height: u32,
    hash: [u8; 32],
    prev: [u8; 32],
    work: bitcoin::Work,
}

/// Headers strictly above the confirmed tip, low height first.
fn walk_above_tip(hub: &ChainHub, cursor: &Cursor, tip_h: u32) -> Option<Vec<WalkedHeader>> {
    let mut chain = Vec::new();
    let mut hash = cursor.hash;
    let mut height = cursor.height;
    while height > tip_h {
        let rec = stored_header(hub, &hash)?;
        let prev = parent_hash(hub, &rec)?;
        let hdr = header_from_record(&rec, prev);
        chain.push(WalkedHeader {
            height,
            hash: rec.hash,
            prev,
            work: hdr.work(),
        });
        if height == 0 {
            break;
        }
        hash = prev;
        height -= 1;
    }
    if height != tip_h {
        return None;
    }
    if hub
        .tip_hash()
        .is_some_and(|tip| hash != tip.to_byte_array())
    {
        return None;
    }
    chain.reverse();
    Some(chain)
}

fn note_walked(hub: &ChainHub, chain: Vec<WalkedHeader>, tip_h: u32, want: [u8; 32]) -> bool {
    let mut first = true;
    for row in chain {
        let base = if first {
            first = false;
            hub.chain_work().ok()
        } else {
            None
        };
        hub.query
            .note_milestone_header(row.height, row.hash, row.prev, row.work, base);
    }
    let got = hub.query.milestone_best_work_be().unwrap_or([0u8; 32]);
    if got != want {
        hub.query.clear_milestone_path_above(tip_h);
        return false;
    }
    true
}

/// Walk `header.body` from the cursor back to the confirmed tip and refill the
/// milestone map. False when the file does not match the store.
fn replay_cursor(hub: &ChainHub, cursor: &Cursor) -> bool {
    let tip_h = hub.tip_height().unwrap_or(0);
    if cursor.height < tip_h || stored_header(hub, &cursor.hash).is_none() {
        return false;
    }
    if cursor.height == tip_h {
        return replay_at_tip(hub, cursor, tip_h);
    }
    let Some(chain) = walk_above_tip(hub, cursor, tip_h) else {
        return false;
    };
    note_walked(hub, chain, tip_h, cursor.work)
}

fn header_from_record(rec: &rbitcoin_store::HeaderRecord, prev_hash: [u8; 32]) -> Header {
    Header {
        version: bitcoin::block::Version::from_consensus(rec.version),
        prev_blockhash: BlockHash::from_byte_array(prev_hash),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(rec.merkle_root),
        time: rec.timestamp,
        bits: bitcoin::CompactTarget::from_consensus(rec.bits),
        nonce: rec.nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainHub;
    use crate::ibd::assign::issue_batch;
    use crate::ibd::peer_io::{PeerCmd, PeerSlot};
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode};
    use rbitcoin_consensus::Milestone;
    use rbitcoin_log::{capture_logs, take_logs};
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn addr(o: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, o)), 8333)
    }

    fn slot(id: usize) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
        let (cmd_tx, rx) = mpsc::unbounded_channel();
        let task = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .spawn(async {});
        let a = addr(id as u8);
        (
            PeerSlot {
                id,
                addr: a,
                net: crate::NetAddr::from_socket(a),
                cmd_tx,
                in_flight: HashSet::new(),
                peer_height: 1,
                connected_ms: 1,
                first_data_ms: 0,
                bytes_rx_total: Arc::new(AtomicU64::new(0)),
                rate: Default::default(),
                alive: true,
                task,
            },
            rx,
        )
    }

    fn mine(prev: BlockHash, time: u32) -> Header {
        let mut h = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([time as u8; 32]),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    }

    fn count_line(logs: &[(rbitcoin_log::Level, String)], needle: &str) -> usize {
        logs.iter().filter(|(_, m)| m.contains(needle)).count()
    }

    fn hub() -> (rbitcoin_query::testutil::TempDir, ChainHub) {
        let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("header-scan");
        hub.ensure_genesis().unwrap();
        (dir, hub)
    }

    fn saw_getheaders(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> bool {
        matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. }))
    }

    #[test]
    fn one_live_peer_keeps_the_body_window_and_does_not_adopt() {
        let (_dir, hub) = hub();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1_600_000_000);
        let (s0, mut rx0) = slot(0);
        let mut st = IbdWorkState::new(vec![s0], Some(gen), Some(0));
        let now = Instant::now();
        assert!(!blocks_body_fetch(&st));
        poll(&mut st, &hub, now);
        assert!(
            !saw_getheaders(&mut rx0),
            "one live peer is not asked by the two-peer scan"
        );
        assert!(!blocks_body_fetch(&st));
        let body = take_headers(&mut st, &hub, 0, vec![good], now);
        assert!(
            body.is_some(),
            "a lone peer's reply still fills the body window"
        );
        assert!(hub.query.milestone_header_at(1).is_none());
        st.header_scan.phase = Phase::Primary {
            peer: 0,
            since: now,
        };
        let released = take_headers(&mut st, &hub, 0, vec![good], now);
        assert!(released.is_some(), "the batch returns to the body window");
        assert!(
            hub.query.milestone_header_at(1).is_none(),
            "one peer does not move the milestone path"
        );
        assert!(owns_milestone(&st));
    }

    #[test]
    fn header_log_lines_match_the_operator_form() {
        assert_eq!(
            format_headers_progress(240_000, 969_050, false),
            "ibd: headers height=240000 (24%) horizon=969050 work=below"
        );
        assert_eq!(
            format_headers_milestone(
                840_000,
                "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
            ),
            "ibd: headers milestone height=840000 hash=0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5 work=ok (script/sig skip at/below)"
        );
        assert_eq!(
            format_headers_done(969_050, 969_050, true),
            "ibd: headers done height=969050 (100%) work=ok"
        );
        assert_eq!(
            format_headers_resume(100, 200, true),
            "ibd: headers resume height=100 (50%) work=ok"
        );
    }

    fn arm_anchor(hub: &mut ChainHub, good: &Header) {
        hub.milestone = Milestone {
            height: 1,
            anchor: Some(rbitcoin_consensus::MilestoneAnchor {
                hash: good.block_hash(),
                min_work_be: [0u8; 32],
            }),
        };
    }

    fn three_slots(
        gen: BlockHash,
    ) -> (
        IbdWorkState,
        mpsc::UnboundedReceiver<PeerCmd>,
        mpsc::UnboundedReceiver<PeerCmd>,
        mpsc::UnboundedReceiver<PeerCmd>,
    ) {
        let (s0, rx0) = slot(0);
        let (s1, rx1) = slot(1);
        let (s2, rx2) = slot(2);
        let mut st = IbdWorkState::new(vec![s0, s1, s2], Some(gen), Some(0));
        st.slots[0]
            .in_flight
            .insert(BlockHash::from_byte_array([9u8; 32]));
        st.max_peer_height = 1;
        (st, rx0, rx1, rx2)
    }

    fn assert_primary_is_idle(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        now: Instant,
        rx0: &mut mpsc::UnboundedReceiver<PeerCmd>,
        rx1: &mut mpsc::UnboundedReceiver<PeerCmd>,
        rx2: &mut mpsc::UnboundedReceiver<PeerCmd>,
    ) {
        poll(st, hub, now);
        assert!(
            !saw_getheaders(rx0),
            "a peer with block inflight is not the header primary"
        );
        assert!(saw_getheaders(rx1), "lowest idle peer is primary");
        assert!(!saw_getheaders(rx2));
        assert!(peer_awaits_headers(st, 1));
        let mut room = 4usize;
        let mut issued = 0u64;
        assert!(
            !issue_batch(
                st,
                1,
                vec![BlockHash::from_byte_array([3u8; 32])],
                &mut room,
                &mut issued
            ),
            "getdata is not stacked on the header peer"
        );
        assert_eq!(issued, 0);
    }

    fn assert_fork_is_not_stored(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        now: Instant,
        good: Header,
        bad: Header,
        rx2: &mut mpsc::UnboundedReceiver<PeerCmd>,
    ) {
        assert!(take_headers(st, hub, 1, vec![good], now).is_none());
        assert!(saw_getheaders(rx2), "witness is a different idle peer");
        assert!(hub
            .query
            .get_header_by_hash(&good.block_hash().to_byte_array())
            .unwrap()
            .is_none());
        assert!(take_headers(st, hub, 2, vec![bad], now).is_none());
        assert!(
            hub.query
                .get_header_by_hash(&bad.block_hash().to_byte_array())
                .unwrap()
                .is_none(),
            "a divergent witness is not stored"
        );
        assert!(st.header_scan.cooldown.contains_key(&2) || st.header_scan.phase_waiting());
    }

    fn assert_third_peer_adopts(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        now: Instant,
        good: Header,
        rx0: &mut mpsc::UnboundedReceiver<PeerCmd>,
    ) {
        st.slots[0].in_flight.clear();
        poll(st, hub, now);
        assert!(saw_getheaders(rx0));
        assert!(take_headers(st, hub, 0, vec![good], now).is_none());
        assert!(
            hub.query
                .get_header_by_hash(&good.block_hash().to_byte_array())
                .unwrap()
                .is_some(),
            "agreement stores the header"
        );
        assert!(
            st.ordered_set.contains(&good.block_hash()),
            "the body window takes the agreed header"
        );
        assert!(
            st.header_scan.milestone_logged,
            "milestone line once the anchor is on the path and work meets the floor"
        );
        assert!(st.header_scan.cooldown.contains_key(&2));
    }

    fn assert_gate_skips_only_the_adopted_hash(hub: &ChainHub, good_hash: [u8; 32]) {
        let at = |h| hub.query.milestone_header_at(h);
        let work = hub.query.milestone_best_work_be();
        assert!(
            hub.milestone.skips_scripts(1, &good_hash, at, work),
            "script checks stay off once the agreed path meets the gate"
        );
        let mut other = good_hash;
        other[0] ^= 0xff;
        let at = |h| hub.query.milestone_header_at(h);
        assert!(!hub
            .milestone
            .skips_scripts(1, &other, at, hub.query.milestone_best_work_be()));
    }

    fn finish_at_horizon(
        st: &mut IbdWorkState,
        hub: &ChainHub,
        now: Instant,
        rx1: &mut mpsc::UnboundedReceiver<PeerCmd>,
    ) {
        log_progress(st, hub);
        poll(st, hub, now);
        let finisher = if saw_getheaders(rx1) { 1 } else { 0 };
        assert!(take_headers(st, hub, finisher, Vec::new(), now).is_none());
        assert!(
            st.header_scan.done,
            "empty headers at the horizon ends the scan"
        );
        assert!(st.header_scan.done_logged);
    }

    fn assert_one_header_line(logs: &[(rbitcoin_log::Level, String)]) {
        assert_eq!(count_line(logs, "ibd: headers height="), 1, "{logs:?}");
        assert_eq!(count_line(logs, "ibd: headers milestone"), 1, "{logs:?}");
        assert_eq!(count_line(logs, "ibd: headers done"), 1, "{logs:?}");
        assert_eq!(count_line(logs, "ibd: headers diverge"), 1, "{logs:?}");
    }

    #[test]
    fn two_peers_agree_a_busy_peer_is_not_asked_and_a_fork_is_not_adopted() {
        let (_dir, mut hub) = hub();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1_600_000_000);
        let bad = mine(gen, 1_600_000_600);
        assert_ne!(good.block_hash(), bad.block_hash());
        arm_anchor(&mut hub, &good);
        let (mut st, mut rx0, mut rx1, mut rx2) = three_slots(gen);
        capture_logs(true);
        let now = Instant::now();
        assert_primary_is_idle(&mut st, &hub, now, &mut rx0, &mut rx1, &mut rx2);
        assert_fork_is_not_stored(&mut st, &hub, now, good, bad, &mut rx2);
        assert_third_peer_adopts(&mut st, &hub, now, good, &mut rx0);
        assert_gate_skips_only_the_adopted_hash(&hub, good.block_hash().to_byte_array());
        finish_at_horizon(&mut st, &hub, now, &mut rx1);
        assert_one_header_line(&take_logs());
        capture_logs(false);
    }

    impl HeaderScan {
        fn phase_waiting(&self) -> bool {
            matches!(self.phase, Phase::Witness { witness: None, .. })
        }
    }

    #[test]
    fn ordered_stops_at_the_soft_cap_while_the_milestone_path_keeps_the_header() {
        let (_dir, hub) = hub();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1_600_000_000);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        for i in 0..ORDERED_HEADERS_SOFT_CAP {
            let mut b = [0u8; 32];
            b[28..32].copy_from_slice(&(i as u32).to_le_bytes());
            let h = BlockHash::from_byte_array(b);
            st.ordered.push_back(h);
            st.ordered_set.insert(h);
        }
        let now = Instant::now();
        poll(&mut st, &hub, now);
        assert!(take_headers(&mut st, &hub, 0, vec![good], now).is_none());
        assert!(take_headers(&mut st, &hub, 1, vec![good], now).is_none());
        assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);
        assert!(
            hub.query.milestone_header_at(1).is_some(),
            "the header is on the milestone path without entering ordered"
        );
        assert!(!st.ordered_set.contains(&good.block_hash()));
        let dropped = st.ordered.pop_front().unwrap();
        st.ordered_set.remove(&dropped);
        admit(&mut st, &hub);
        assert!(
            st.ordered_set.contains(&good.block_hash()),
            "room in ordered admits the stored header without another getheaders"
        );
        assert_eq!(st.ordered.len(), ORDERED_HEADERS_SOFT_CAP);
    }

    #[test]
    fn resume_cursor_refills_the_milestone_path_without_a_height_skip() {
        let (dir, hub) = hub();
        let gen = hub.tip_hash().unwrap();
        let good = mine(gen, 1_600_000_000);
        let (s0, _rx0) = slot(0);
        let (s1, _rx1) = slot(1);
        let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
        let now = Instant::now();
        poll(&mut st, &hub, now);
        assert!(take_headers(&mut st, &hub, 0, vec![good], now).is_none());
        assert!(take_headers(&mut st, &hub, 1, vec![good], now).is_none());
        assert!(hub.query.milestone_header_at(1).is_some());

        hub.query.clear_milestone_path_above(0);
        assert!(hub.query.milestone_header_at(1).is_none());
        assert!(
            hub.query.milestone_best_work_be().is_none(),
            "clearing the path does not leave a height-only skip"
        );

        let mut again = IbdWorkState::new(Vec::new(), Some(gen), Some(0));
        again.max_peer_height = 1;
        restore(&mut again, &hub);
        assert_eq!(again.header_scan.adopted_height, 1);
        assert!(hub.query.milestone_header_at(1).is_some());
        assert!(
            again.header_scan.done,
            "cursor at the peer horizon finishes the scan"
        );

        hub.query.clear_milestone_path_above(0);
        let bogus = hub.query.store().path().join("header.adopt");
        let mut buf = b"rbtchdr1".to_vec();
        buf.extend_from_slice(&50u32.to_le_bytes());
        buf.extend_from_slice(&[0xab; 32]);
        buf.extend_from_slice(&[0x11; 32]);
        std::fs::write(&bogus, &buf).unwrap();
        let mut miss = IbdWorkState::new(Vec::new(), Some(gen), Some(0));
        miss.max_peer_height = 50;
        restore(&mut miss, &hub);
        assert!(hub.query.milestone_header_at(1).is_none());
        assert!(hub.query.milestone_best_work_be().is_none());
        assert!(!miss.header_scan.done);
        assert_eq!(miss.header_scan.adopted_height, 0);
        let _ = dir;
    }
}
