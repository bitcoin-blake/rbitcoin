//! Single-tx accept: Libre policy + cluster limits + durable slot write.

use crate::error::MempoolError;
use crate::graph::{
    sigops_adjusted_weight, SelectBudget, Selected, TxEntry, TxGraph, MAX_BLOCK_SIGOPS_COST,
};
use crate::orphanage::Orphanage;
use crate::packed::VinAux;
use crate::store::Mempool;
use bitcoin::{OutPoint, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_consensus::policy::{self, PolicyResult};
use rbitcoin_primitives::Fk;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

const EXTRA_COMPACT_CAP: usize = 100;
const RECENT_INVALID_CAP: usize = 4_096;

/// Stage wall times (µs) for one accept attempt (or sum across package/orphan promote).
///
/// Used by tip:perf / microbench harness — not a consensus surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcceptStageUs {
    /// Prevout resolve (mempool graph peek + chain `UtxoProvider`).
    pub utxo_us: u64,
    /// Consensus script verify.
    pub script_us: u64,
    /// Durable slot/body append (coalesced persist when it runs).
    pub durable_us: u64,
}

/// Confirmed-chain unspent coin for mempool accept (content + maturity metadata).
///
/// Presence implies **unspent on the confirmed chain**. Missing/`None` means
/// unknown create or confirmed-strong spent (finding 010).
#[derive(Debug, Clone)]
pub struct Coin {
    pub txout: TxOut,
    /// Class C create height; `0` if unknown (BIP68 fail-closed when needed).
    pub create_height: u32,
    /// MTP of the block *before* the create block (BIP68 time locks). `0` if unknown.
    pub create_mtp: u32,
    pub is_coinbase: bool,
    /// Class A create fk when the UTXO provider resolved a confirmed coin.
    pub create_fk: Option<Fk>,
}

/// Tip snapshot for structural checks (finality / maturity / BIP68).
///
/// `height` is the **confirmed tip** height; absolute finality uses `height + 1`
/// as the next block height (Core mempool convention).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainTipCtx {
    pub height: u32,
    /// BIP113 median time past of the tip (locktime cutoff for time-form nLockTime).
    pub mtp: u32,
}

/// Resolve prevouts for mempool acceptance (chain UTXO + in-mempool outputs).
pub trait UtxoProvider {
    /// Unspent confirmed coin, or `None` if missing/spent on the confirmed chain.
    /// Spent vs never-seen is [`Self::chain_prevout`].
    fn get_coin(&self, op: &OutPoint) -> Option<Coin>;

    fn get_txout(&self, op: &OutPoint) -> Option<TxOut> {
        self.get_coin(op).map(|c| c.txout)
    }

    /// Spent/missing vout on a *confirmed* create vs a parent we have never seen.
    fn chain_prevout(&self, op: &OutPoint) -> ChainPrevout {
        match self.get_coin(op) {
            Some(coin) => ChainPrevout::Unspent(coin),
            None => ChainPrevout::Unknown,
        }
    }

    /// Spender about to resolve coins (BIP68 time-lock MTP only when needed).
    fn note_spender(&self, _tx: &Transaction) {}
}

/// Confirmed-chain lookup for one prevout.
#[derive(Debug, Clone)]
pub enum ChainPrevout {
    Unspent(Coin),
    /// Create is confirmed; output spent, missing vout, or otherwise unusable.
    KnownUnavailable,
    Unknown,
}

/// Map-backed provider for tests and simple callers.
pub struct MapUtxoProvider {
    pub map: std::collections::HashMap<OutPoint, Coin>,
}

impl UtxoProvider for MapUtxoProvider {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        self.map.get(op).cloned()
    }
}

/// Max txs in one ancestor package.
pub const MAX_PACKAGE_COUNT: usize = 25;
/// Max total weight (WU) of one package.
pub const MAX_PACKAGE_WEIGHT: u64 = 404_000;
/// Default mempool weight budget (WU) — ~75 MvB class; eviction by worst chunk.
pub const DEFAULT_MAX_MEMPOOL_WEIGHT: u64 = 300_000_000;
/// Incremental relay feerate for RBF (same as Libre min).
pub const INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB: u64 =
    rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB;
/// Pure replace-by-fee-rate ratio (Libre Relay v27.1+): **1.25×** = 5/4.
pub const RBFR_RATIO_NUM: u64 = 5;
pub const RBFR_RATIO_DEN: u64 = 4;
/// Half-life of the eviction feerate bump once the mempool is no longer full.
pub const ROLLING_FEE_HALFLIFE_MS: u64 = 12 * 60 * 60 * 1000;

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Eviction bump decays by half toward `min_relay` once per halflife.
pub(crate) fn decayed_relay_floor(rolling: u64, min_relay: u64, elapsed_ms: u64) -> u64 {
    let rolling = rolling.max(min_relay);
    if elapsed_ms < ROLLING_FEE_HALFLIFE_MS {
        return rolling;
    }
    let steps = elapsed_ms / ROLLING_FEE_HALFLIFE_MS;
    let excess = rolling.saturating_sub(min_relay);
    let excess = if steps >= 63 { 0 } else { excess >> steps };
    min_relay.saturating_add(excess)
}

/// Min fee while full keeps the static bump and any evicted-rate floor.
/// Below the cap the evicted-rate floor decays.
pub(crate) fn relay_floor(
    min_relay: u64,
    rolling: u64,
    updated_ms: u64,
    now_ms: u64,
    near_full: bool,
) -> u64 {
    let bumped = if near_full {
        min_relay.saturating_add(INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB)
    } else {
        min_relay
    };
    let rolling_now = if near_full {
        rolling.max(min_relay)
    } else {
        decayed_relay_floor(rolling, min_relay, now_ms.saturating_sub(updated_ms))
    };
    bumped.max(rolling_now)
}

/// Outcome of a successful accept.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    pub txid: Txid,
    pub fee_sat: u64,
    /// Sigop-adjusted weight; `vsize = ceil(weight / 4)` is Core's `m_vsize`.
    pub weight: u64,
    pub slot: u32,
    /// Mempool txids removed by full-RBF / RBFR when admitting this tx (empty if no conflict).
    pub replaced: Vec<Txid>,
    /// Electrum scripthashes (SHA256 of output scriptPubKeys) of **replaced** bodies,
    /// collected **before** RBF removal so wallet address tracks can drop zombie unconfs
    /// even when the old body is gone from the hub.
    pub replaced_scripthashes: Vec<[u8; 32]>,
    /// Replaced bodies, for package rollback to restore victims.
    pub replaced_txs: Vec<Transaction>,
}

/// Why accept failed (policy / graph / durable / consensus script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    Policy(&'static str),
    MissingPrevout(OutPoint),
    /// Tx parked in the orphanage waiting on missing parent(s). Not a hard reject.
    /// `fresh` is true on first insert; re-delivery of the same parked tx is false.
    Orphaned {
        txid: Txid,
        missing: BTreeSet<Txid>,
        fresh: bool,
    },
    Duplicate(Txid),
    ClusterTooLarge {
        count: usize,
        weight: u64,
    },
    PackageTooLarge {
        count: usize,
        weight: u64,
    },
    PackageEmpty,
    PackageNotTopo,
    /// Conflicting mempool txs exist and replacement does not pay enough.
    RbfInsufficient,
    Coinbase,
    /// Duplicate previous_output within the same transaction (011).
    InputsDuplicate,
    /// Coinbase maturity not met at tip+1 (011).
    ImmatureCoinbase,
    /// Absolute nLockTime / sequence finality not met for next block (011).
    NotFinal,
    /// BIP68 relative lock not satisfied at tip (011).
    NonBip68Final,
    NotFound(Txid),
    Durable(String),
    /// Consensus script verification failed for one or more inputs.
    Script(String),
    /// Sigop cost cannot fit the configured block-template budget, including
    /// its reserved coinbase allowance.
    TooManySigops {
        cost: u64,
    },
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::Policy(s) => write!(f, "policy: {s}"),
            AcceptError::MissingPrevout(op) => write!(f, "missing prevout {op}"),
            AcceptError::Orphaned { txid, .. } => write!(f, "orphaned {txid}"),
            AcceptError::Duplicate(t) => write!(f, "duplicate {t}"),
            AcceptError::ClusterTooLarge { .. } => f.write_str("too-large-cluster"),
            AcceptError::PackageTooLarge { count, weight } => {
                write!(f, "package too large count={count} weight={weight}")
            }
            AcceptError::PackageEmpty => f.write_str("package empty"),
            AcceptError::PackageNotTopo => f.write_str("package not topologically ordered"),
            AcceptError::RbfInsufficient => f.write_str("rbf insufficient fee"),
            AcceptError::Coinbase => f.write_str("coinbase"),
            AcceptError::InputsDuplicate => f.write_str("inputs-duplicate"),
            AcceptError::ImmatureCoinbase => f.write_str("coinbase immature"),
            AcceptError::NotFinal => f.write_str("not final"),
            AcceptError::NonBip68Final => f.write_str("non-BIP68-final"),
            AcceptError::NotFound(t) => write!(f, "not found {t}"),
            AcceptError::Durable(s) => write!(f, "durable: {s}"),
            AcceptError::Script(s) => write!(f, "script: {s}"),
            AcceptError::TooManySigops { .. } => f.write_str("bad-txns-too-many-sigops"),
        }
    }
}

impl AcceptError {
    /// Core debug.log / `was not accepted:` needle (`Policy` is the bare reason).
    pub fn mempool_reject_reason(&self) -> String {
        match self {
            AcceptError::Policy(s) => (*s).to_string(),
            other => other.to_string(),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Side effects of a recordable accept failure (recent-invalid / extra-compact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFailureRecord {
    Invalid(Txid),
    Extra,
}

impl From<MempoolError> for AcceptError {
    fn from(e: MempoolError) -> Self {
        match e {
            MempoolError::Full => AcceptError::Policy("mempool full"),
            other => AcceptError::Durable(other.to_string()),
        }
    }
}

/// Maturity, absolute finality (`is_final_tx`), and BIP68 at the next block.
pub fn check_mempool_structural(
    tx: &Transaction,
    chain_coins: &[Option<Coin>],
    tip: ChainTipCtx,
) -> Result<(), AcceptError> {
    let next_height = tip.height.saturating_add(1);
    for c in chain_coins.iter().flatten() {
        if c.is_coinbase && next_height < c.create_height.saturating_add(100) {
            return Err(AcceptError::ImmatureCoinbase);
        }
    }
    if !rbitcoin_consensus::is_final_tx(tx, next_height, tip.mtp) {
        return Err(AcceptError::NotFinal);
    }
    if rbitcoin_consensus::bip68_active_for_tx(tx) {
        let mut prev_heights = Vec::with_capacity(tx.input.len());
        let mut prev_mtps = Vec::with_capacity(tx.input.len());
        for (i, inp) in tx.input.iter().enumerate() {
            let seq = inp.sequence.to_consensus_u32();
            let lock_enabled = seq & (1u32 << 31) == 0;
            match chain_coins.get(i).and_then(|c| c.as_ref()) {
                Some(c) => {
                    // Unknown create height with an active relative lock → fail closed.
                    if lock_enabled && c.create_height == 0 && !c.is_coinbase {
                        return Err(AcceptError::NonBip68Final);
                    }
                    prev_heights.push(c.create_height);
                    prev_mtps.push(c.create_mtp);
                }
                None => {
                    // Mempool parent: treat as created at next_height (unconfirmed).
                    prev_heights.push(next_height);
                    prev_mtps.push(tip.mtp);
                }
            }
        }
        if !rbitcoin_consensus::sequence_locks_satisfied(
            tx,
            &prev_heights,
            &prev_mtps,
            next_height,
            tip.mtp,
        ) {
            return Err(AcceptError::NonBip68Final);
        }
    }
    Ok(())
}

/// Run consensus script verification for every input (mempool / tip height assumed
/// post-all-softforks: BIP16/65/66/112 active).
///
/// Always uses the shared `rbtc-scripts` detached path (same family as IBD
/// confirm) so the caller stack — peer session or tokio — never runs the
/// interpreter.
fn tx_has_witness(tx: &Transaction) -> bool {
    tx.input.iter().any(|i| !i.witness.is_empty())
}

/// Full BIP16 + BIP141 sigop cost (Core ATMP `GetTransactionSigOpCost`; P2SH
/// and witness flags match `STANDARD_SCRIPT_VERIFY_FLAGS`). Rejects a cost
/// that does not fit the configured template reserve.
fn block_fit_sigop_cost(
    tx: &Transaction,
    prevouts: &[TxOut],
    reserved_sigops: u64,
) -> Result<u64, AcceptError> {
    let spks: Vec<&[u8]> = prevouts
        .iter()
        .map(|o| o.script_pubkey.as_bytes())
        .collect();
    let cost = rbitcoin_consensus::tx_sigop_cost(tx, &spks, true, true);
    if reserved_sigops.saturating_add(cost) > MAX_BLOCK_SIGOPS_COST {
        return Err(AcceptError::TooManySigops { cost });
    }
    Ok(cost)
}

fn checked_fee_sat(tx: &Transaction, input_value: u64) -> Result<u64, AcceptError> {
    let mut output_value = 0u64;
    for output in &tx.output {
        output_value = output_value
            .checked_add(output.value.to_sat())
            .ok_or(AcceptError::Policy("bad-txns-txouttotal-toolarge"))?;
    }
    input_value
        .checked_sub(output_value)
        .ok_or(AcceptError::Policy("negative fee"))
}

/// Fee and sigop-adjusted weight of `tx` over resolved `prevouts`; `None`
/// if outputs exceed inputs.
fn fee_and_adjusted_weight(
    tx: &Transaction,
    prevouts: &[TxOut],
    bytes_per_sigop: u64,
) -> Option<(u64, u64)> {
    let inn = prevouts
        .iter()
        .fold(0u64, |a, o| a.saturating_add(o.value.to_sat()));
    let out = tx
        .output
        .iter()
        .fold(0u64, |a, o| a.saturating_add(o.value.to_sat()));
    let fee = inn.checked_sub(out)?;
    let spks: Vec<&[u8]> = prevouts
        .iter()
        .map(|o| o.script_pubkey.as_bytes())
        .collect();
    let sigops = rbitcoin_consensus::tx_sigop_cost(tx, &spks, true, true);
    Some((
        fee,
        sigops_adjusted_weight(tx.weight().to_wu(), sigops, bytes_per_sigop),
    ))
}

fn first_missing_outpoint(
    tx: &Transaction,
    missing: &BTreeSet<Txid>,
    extra: impl Fn(&OutPoint) -> bool,
) -> Option<OutPoint> {
    tx.input
        .iter()
        .map(|inp| inp.previous_output)
        .find(|op| missing.contains(&op.txid) && extra(op))
}

/// Script policy that follows the chain the mempool serves. Knots sets the
/// unified-sighash flag wherever the BLAKE2b fork is scheduled (a lagging node
/// would otherwise refuse what its peers relay) and carries the RDTS flags as
/// standardness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForkScriptPolicy {
    /// Opted-in signatures are checked against the unified message.
    pub unified_sighash: bool,
    /// RDTS rules as standardness, on every input.
    pub reduced_data: bool,
}

impl ForkScriptPolicy {
    /// The script flags admission verifies with: every buried fork, plus this policy.
    pub fn script_flags(self) -> rbitcoin_consensus::ScriptVerifyFlags {
        let mut flags = rbitcoin_consensus::ScriptVerifyFlags::buried(true, true, true, true, true);
        flags.unified_sighash = self.unified_sighash;
        flags.reduced_data = self.reduced_data;
        flags
    }
}

fn verify_tx_scripts(
    tx: &Transaction,
    prevouts: Vec<TxOut>,
    policy: ForkScriptPolicy,
) -> Result<(), AcceptError> {
    if prevouts.len() != tx.input.len() {
        return Err(AcceptError::Script("prevout count mismatch".into()));
    }
    rbitcoin_consensus::verify_tx_scripts_detached_with(prevouts, tx.clone(), policy.script_flags())
        .map_err(|e| AcceptError::Script(e.to_string()))
}

/// Result of accept prepare (resolve + policy + structural), before script verify.
///
/// Script runs outside the mempool exclusive lock; [`ActiveMempool::commit_after_script`]
/// re-checks and durable-commits.
#[derive(Debug, Clone)]
pub struct PreparedAdmit {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub fee_sat: u64,
    /// `prioritisetransaction` delta applied at prepare (min-relay / RBF).
    pub fee_delta: i64,
    pub weight: u64,
    /// Full BIP16 + BIP141 sigop cost (Core ATMP `GetTransactionSigOpCost`).
    pub sigop_cost: u64,
    pub prevouts: Vec<TxOut>,
    pub chain_coins: Vec<Option<Coin>>,
    pub utxo_us: u64,
}

/// Graph spend edges for one tx (conflicts + mempool parents).
struct ConflictScan {
    direct_conflicts: BTreeSet<Txid>,
    parent_txids: BTreeSet<Txid>,
}

enum EvictUntil {
    FreeSlot,
    WeightBudget,
}

struct IngestedLive {
    graph: TxGraph,
    bodies: std::collections::HashMap<Txid, Arc<Transaction>>,
    vin_aux: std::collections::HashMap<Txid, Vec<VinAux>>,
}

/// Mempool with RAM TxGraph layered on durable store.
pub struct ActiveMempool {
    pub store: Mempool,
    pub graph: TxGraph,
    /// Cached tx bodies for graph rebuild / remove (live set only).
    bodies: std::collections::HashMap<Txid, Arc<Transaction>>,
    /// Per-vin aux from the packed sidecar (SH / purge). Missing only if a
    /// leftover record omitted it.
    vin_aux: std::collections::HashMap<Txid, Vec<VinAux>>,
    /// Evict worst chunks when live weight exceeds this.
    pub max_weight: u64,
    /// Side pool of txs waiting on missing parents (weight budget).
    pub orphanage: Orphanage,
    /// Stage µs for the most recent top-level [`Self::accept_tx`] / package member
    /// (includes nested orphan promote for that accept). Sampled by MempoolHub.
    pub last_accept_stages: AcceptStageUs,
    /// Overlay from `-limitclustercount` / `-limitclustersize` (re-applied after compact).
    cluster_count_overlay: Option<u32>,
    cluster_size_kvb_overlay: Option<u32>,
    /// Core `-minrelaytxfee` in sat/kvB (default Libre 100).
    min_relay_sat_kvb: u64,
    /// Highest evicted chunk feerate (sat/kvB). Decays toward min relay when not full.
    rolling_min_sat_kvb: u64,
    /// Unix ms when `rolling_min_sat_kvb` was last raised or decayed.
    rolling_updated_ms: u64,
    /// Txids recently rejected as invalid (not policy-reconsiderable).
    recent_invalid: HashSet<Txid>,
    /// Script policy of the chain served (fork opt-ins).
    fork_policy: ForkScriptPolicy,
    /// Recent rejects / RBF replacements for compact fill and 1p1c.
    extra_compact: VecDeque<(Txid, Transaction)>,
}

impl ActiveMempool {
    pub fn open_or_create(dir: impl Into<std::path::PathBuf>) -> Result<Self, MempoolError> {
        Self::open_or_create_with_limit(dir, DEFAULT_MAX_MEMPOOL_WEIGHT)
    }

    pub fn open_or_create_with_limit(
        dir: impl Into<std::path::PathBuf>,
        max_weight: u64,
    ) -> Result<Self, MempoolError> {
        Self::open_with_limit_persist(dir, max_weight, true)
    }

    /// Overlay Core `-limitclustercount` / `-limitclustersize`.
    pub fn set_cluster_limits(&mut self, count: Option<u32>, size_kvb: Option<u32>) {
        if count.is_some() {
            self.cluster_count_overlay = count;
        }
        if size_kvb.is_some() {
            self.cluster_size_kvb_overlay = size_kvb;
        }
        self.graph.set_cluster_limits(count, size_kvb);
    }

    /// Overlay Core `-bytespersigop` (`0` disables sigop-adjusted size).
    pub fn set_bytes_per_sigop(&mut self, bytes_per_sigop: u64) {
        self.graph.set_bytes_per_sigop(bytes_per_sigop);
    }

    /// Set the sigop reserve shared by admission and [`Self::template_budget`].
    pub fn set_block_reserved_sigops(&mut self, reserved_sigops: u64) {
        self.graph.set_block_reserved_sigops(reserved_sigops);
    }

    /// Overlay Core `-minrelaytxfee` (sat/kvB). `0` admits any non-negative fee.
    pub fn set_min_relay_sat_kvb(&mut self, sat_kvb: u64) {
        self.min_relay_sat_kvb = sat_kvb;
    }

    pub fn min_relay_sat_kvb(&self) -> u64 {
        self.min_relay_sat_kvb
    }

    /// `persist=false` abandons any on-disk live set (Core `-persistmempool=0`).
    pub fn open_with_limit_persist(
        dir: impl Into<std::path::PathBuf>,
        max_weight: u64,
        persist: bool,
    ) -> Result<Self, MempoolError> {
        let mut store = Mempool::open_or_create(dir)?;
        if !persist {
            store.abandon_live()?;
        }
        let loaded = store.load_live_txs()?;
        let ingested = Self::ingest_loaded(loaded);
        store.set_live_count(ingested.graph.len() as u32);
        Ok(Self {
            store,
            graph: ingested.graph,
            bodies: ingested.bodies,
            vin_aux: ingested.vin_aux,
            max_weight,
            orphanage: Orphanage::new(),
            last_accept_stages: AcceptStageUs::default(),
            cluster_count_overlay: None,
            cluster_size_kvb_overlay: None,
            min_relay_sat_kvb: rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            rolling_min_sat_kvb: rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
            rolling_updated_ms: unix_ms(),
            recent_invalid: HashSet::new(),
            fork_policy: ForkScriptPolicy::default(),
            extra_compact: VecDeque::new(),
        })
    }

    /// Script policy for the chain this mempool serves.
    pub fn set_fork_policy(&mut self, policy: ForkScriptPolicy) {
        self.fork_policy = policy;
    }

    pub fn fork_policy(&self) -> ForkScriptPolicy {
        self.fork_policy
    }

    pub fn live_count(&self) -> usize {
        self.graph.len()
    }

    pub fn mempool_min_fee_sat_kvb(&self) -> u64 {
        let near_full = self
            .graph
            .total_weight()
            .saturating_add(policy::MAX_STANDARD_TX_WEIGHT)
            > self.max_weight;
        relay_floor(
            self.min_relay_sat_kvb,
            self.rolling_min_sat_kvb,
            self.rolling_updated_ms,
            unix_ms(),
            near_full,
        )
    }

    fn note_evicted_feerate(&mut self, rate_sat_kvb: u64) {
        let now = unix_ms();
        let decayed = decayed_relay_floor(
            self.rolling_min_sat_kvb,
            self.min_relay_sat_kvb,
            now.saturating_sub(self.rolling_updated_ms),
        );
        // One sat/kvB above the evicted chunk so that same-rate tx cannot re-enter.
        let raised = rate_sat_kvb.saturating_add(1);
        self.rolling_min_sat_kvb = decayed.max(raised);
        self.rolling_updated_ms = now;
    }

    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    pub fn flush(&mut self) -> Result<(), MempoolError> {
        self.store.flush()
    }

    /// Best-effort sidecar persist of dirty accepts (no generation bump).
    pub fn persist_if_dirty(&mut self) -> Result<(), MempoolError> {
        self.store.persist_due()
    }

    /// Time-based sidecar persist (5 s, no fsync). Body tail then new LIVE slots.
    pub fn persist_due(&mut self) -> Result<(), MempoolError> {
        self.store.persist_due()
    }

    /// Compact durable storage (drop DEAD holes) and rebuild RAM graph.
    pub fn compact(&mut self) -> Result<(u32, usize), MempoolError> {
        let (live, body_len) = self.store.compact()?;
        let loaded = self.store.load_live_txs()?;
        let mut ingested = Self::ingest_loaded(loaded);
        ingested
            .graph
            .set_cluster_limits(self.cluster_count_overlay, self.cluster_size_kvb_overlay);
        ingested
            .graph
            .set_bytes_per_sigop(self.graph.bytes_per_sigop());
        ingested
            .graph
            .set_block_reserved_sigops(self.graph.block_reserved_sigops());
        self.graph = ingested.graph;
        self.bodies = ingested.bodies;
        self.vin_aux = ingested.vin_aux;
        self.store.set_live_count(live);
        Ok((live, body_len))
    }

    fn ingest_loaded(loaded: Vec<crate::store::LiveTx>) -> IngestedLive {
        let mut graph = TxGraph::new();
        let mut bodies = std::collections::HashMap::new();
        let mut vin_aux = std::collections::HashMap::new();
        let mut items = Vec::with_capacity(loaded.len());
        for live in loaded {
            let p = live.packed;
            let tx = Arc::new(p.tx);
            let entry = TxEntry {
                txid: p.txid,
                wtxid: p.wtxid,
                fee_sat: p.fee_sat,
                weight: p.weight,
                // Migrated from schema ≤ 2: unknown until
                // [`ActiveMempool::recompute_missing_sigops`]. MAX never fits a block.
                sigop_cost: p.sigop_cost.unwrap_or(u64::MAX),
                slot: live.slot,
                parents: BTreeSet::new(),
                children: BTreeSet::new(),
            };
            vin_aux.insert(p.txid, p.vins);
            bodies.insert(p.txid, Arc::clone(&tx));
            items.push((entry, tx));
        }
        graph.rebuild_from(items);
        IngestedLive {
            graph,
            bodies,
            vin_aux,
        }
    }

    /// Compact when DEAD slots are a large fraction of capacity (file growth bound).
    pub fn maybe_compact(&mut self) -> Result<Option<(u32, usize)>, MempoolError> {
        let (_free, live, dead) = self.store.slot_stats();
        if dead == 0 {
            return Ok(None);
        }
        let cap = self.store.meta().slot_cap;
        if dead * 4 >= cap || (live > 0 && dead >= live) || (live == 0 && dead > 0) {
            return Ok(Some(self.compact()?));
        }
        Ok(None)
    }

    /// Accept a single transaction under Libre policy + cluster limits.
    ///
    /// RAM graph is source of truth. Packed body is appended in RAM; sidecar
    /// write waits for [`Self::persist_due`] (5 s) or [`Self::flush`].
    /// Crash may lose ≤5 s of admits.
    /// When prevouts are missing from both mempool and chain UTXO, the tx is
    /// parked in the [`Orphanage`] (weight budget) and
    /// [`AcceptError::Orphaned`] is returned — not a hard peer reject.
    ///
    /// `tip` is the confirmed tip for maturity / `is_final_tx` / BIP68 (next block
    /// height = `tip.height + 1`, BIP113 cutoff = `tip.mtp`).
    pub fn accept_tx(
        &mut self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<AcceptResult, AcceptError> {
        self.last_accept_stages = AcceptStageUs::default();
        match self.accept_tx_with(tx, utxos, tip, 0, true, None) {
            Ok(r) => {
                self.promote_orphans_of(r.txid, utxos, tip);
                Ok(r)
            }
            Err(AcceptError::Orphaned { missing, .. }) => Err(self.park_orphan(tx, missing)),
            Err(e) => {
                self.note_accept_failure(tx, &e);
                Err(e)
            }
        }
    }

    fn accept_tx_with(
        &mut self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        fee_delta: i64,
        report_orphans: bool,
        min_relay: Option<u64>,
    ) -> Result<AcceptResult, AcceptError> {
        let prep = self.prepare_admit(tx, utxos, tip, fee_delta, report_orphans, min_relay)?;
        self.last_accept_stages.utxo_us = prep.utxo_us;
        let t_script = Instant::now();
        let script_res = verify_tx_scripts(tx, prep.prevouts.clone(), self.fork_policy);
        self.last_accept_stages.script_us = self
            .last_accept_stages
            .script_us
            .saturating_add(t_script.elapsed().as_micros() as u64);
        if let Err(e) = script_res {
            self.note_accept_failure(tx, &e);
            return Err(e);
        }
        self.commit_after_script(tx, prep)
    }

    fn note_conflict_and_parent(
        &self,
        txid: Txid,
        op: OutPoint,
        mut scan: Option<&mut ConflictScan>,
    ) -> Result<Option<Txid>, AcceptError> {
        if let Some(c) = self.graph.conflict_txid(&op) {
            if c != txid {
                if let Some(s) = scan.as_mut() {
                    s.direct_conflicts.insert(c);
                }
            }
        }
        if let Some(creator) = self.graph.creator(&op) {
            if !self.graph.mempool_utxo(&op) {
                if let Some(c) = self.graph.conflict_txid(&op) {
                    if let Some(s) = scan.as_mut() {
                        s.direct_conflicts.insert(c);
                    }
                } else {
                    let parent_tx = self
                        .bodies
                        .get(&creator)
                        .ok_or(AcceptError::Durable("parent body missing".into()))?;
                    if (op.vout as usize) >= parent_tx.output.len() {
                        return Err(AcceptError::MissingPrevout(op));
                    }
                    return Err(AcceptError::Policy("mempool double-spend"));
                }
            }
            if let Some(s) = scan.as_mut() {
                s.parent_txids.insert(creator);
            }
            return Ok(Some(creator));
        }
        Ok(None)
    }

    fn scan_conflicts_and_parents(
        &self,
        txid: Txid,
        tx: &Transaction,
        chain_coins: &[Option<Coin>],
    ) -> Result<ConflictScan, AcceptError> {
        let mut scan = ConflictScan {
            direct_conflicts: BTreeSet::new(),
            parent_txids: BTreeSet::new(),
        };
        for (i, inp) in tx.input.iter().enumerate() {
            let op = inp.previous_output;
            if let Some(creator) = self.note_conflict_and_parent(txid, op, Some(&mut scan))? {
                if !self.bodies.contains_key(&creator) {
                    return Err(AcceptError::Durable("parent body missing".into()));
                }
            } else if chain_coins.get(i).and_then(|c| c.as_ref()).is_none() {
                return Err(AcceptError::MissingPrevout(op));
            }
        }
        Ok(scan)
    }

    /// Graph peek + UTXO resolve (`&self`: callers may hold a read lock).
    ///
    /// `report_orphans`: missing parents become [`AcceptError::Orphaned`] (caller
    /// may [`Self::park_orphan`]); otherwise [`AcceptError::MissingPrevout`].
    pub fn prepare_admit(
        &self,
        tx: &Transaction,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
        fee_delta: i64,
        report_orphans: bool,
        min_relay: Option<u64>,
    ) -> Result<PreparedAdmit, AcceptError> {
        if tx.is_coinbase() {
            return Err(AcceptError::Coinbase);
        }
        let txid = tx.compute_txid();
        let wtxid = tx.compute_wtxid();
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == wtxid {
                return Err(AcceptError::Duplicate(txid));
            }
            // Same txid, different witness (Core testmempoolaccept /
            // mempool_accept_wtxid.py).
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        // Already parked: soft re-announce of the same orphan.
        if report_orphans {
            if let Some(missing) = self.orphanage.missing_of(&txid).cloned() {
                return Err(AcceptError::Orphaned {
                    txid,
                    missing,
                    fresh: false,
                });
            }
        }

        // Finding 011: duplicate inputs before any value sum (phantom fee).
        {
            let mut seen = BTreeSet::new();
            for inp in &tx.input {
                if !seen.insert(inp.previous_output) {
                    return Err(AcceptError::InputsDuplicate);
                }
            }
        }

        let t_utxo = Instant::now();
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(tx.input.len());
        let mut chain_coins: Vec<Option<Coin>> = Vec::with_capacity(tx.input.len());
        let mut missing_parents: BTreeSet<Txid> = BTreeSet::new();
        let mut input_value = 0u64;
        for inp in &tx.input {
            let op = inp.previous_output;
            let mempool_parent = self.note_conflict_and_parent(txid, op, None)?;
            let (txout, chain_coin) = if let Some(creator) = mempool_parent {
                let parent_tx = self
                    .bodies
                    .get(&creator)
                    .ok_or(AcceptError::Durable("parent body missing".into()))?;
                match parent_tx.output.get(op.vout as usize).cloned() {
                    Some(o) => (o, None),
                    None => return Err(AcceptError::MissingPrevout(op)),
                }
            } else {
                match utxos.chain_prevout(&op) {
                    ChainPrevout::Unspent(coin) => (coin.txout.clone(), Some(coin)),
                    ChainPrevout::KnownUnavailable => {
                        return Err(AcceptError::MissingPrevout(op));
                    }
                    ChainPrevout::Unknown => {
                        missing_parents.insert(op.txid);
                        continue;
                    }
                }
            };
            input_value = input_value.saturating_add(txout.value.to_sat());
            prevouts.push(txout);
            chain_coins.push(chain_coin);
        }
        let utxo_us = t_utxo.elapsed().as_micros() as u64;

        if !missing_parents.is_empty() {
            if let Some(op) = first_missing_outpoint(tx, &missing_parents, |op| {
                self.recent_invalid.contains(&op.txid)
            }) {
                return Err(AcceptError::MissingPrevout(op));
            }
            if report_orphans {
                match policy::check_libre_shape(tx, tx.weight().to_wu()) {
                    policy::PolicyResult::Standard => {}
                    policy::PolicyResult::NonStandard(s) => return Err(AcceptError::Policy(s)),
                }
                return Err(AcceptError::Orphaned {
                    txid,
                    missing: missing_parents,
                    fresh: true,
                });
            }
            return Err(AcceptError::MissingPrevout(
                first_missing_outpoint(tx, &missing_parents, |_| true)
                    .expect("missing_parents is built from tx.input"),
            ));
        }

        check_mempool_structural(tx, &chain_coins, tip)?;

        let sigop_cost = block_fit_sigop_cost(tx, &prevouts, self.graph.block_reserved_sigops())?;

        let fee_sat = checked_fee_sat(tx, input_value)?;
        let weight = tx.weight().to_wu();
        let admit_fee = (i128::from(fee_sat).saturating_add(i128::from(fee_delta))).max(0) as u64;

        let floor = self.mempool_min_fee_sat_kvb();
        let min_relay = min_relay.unwrap_or(floor);
        // Standardness on raw weight; the fee floor on sigop-adjusted vsize.
        if let PolicyResult::NonStandard(s) =
            policy::check_libre_admission_at(tx, admit_fee, weight, 0)
        {
            return Err(AcceptError::Policy(s));
        }
        let adj = sigops_adjusted_weight(weight, sigop_cost, self.graph.bytes_per_sigop());
        if !policy::meets_min_relay_fee_at(admit_fee, adj, min_relay) {
            return Err(AcceptError::Policy(if floor > self.min_relay_sat_kvb {
                "mempool min fee"
            } else {
                "min relay fee"
            }));
        }

        Ok(PreparedAdmit {
            txid,
            wtxid,
            fee_sat,
            fee_delta,
            weight,
            sigop_cost,
            prevouts,
            chain_coins,
            utxo_us,
        })
    }

    /// Park `tx` waiting on `missing` parent txids (from [`prepare_admit`]).
    pub fn park_orphan(&mut self, tx: &Transaction, missing: BTreeSet<Txid>) -> AcceptError {
        self.park_orphan_from(tx, missing, None)
    }

    /// Park with a P2P announcer peer id.
    pub fn park_orphan_from(
        &mut self,
        tx: &Transaction,
        missing: BTreeSet<Txid>,
        from: Option<u64>,
    ) -> AcceptError {
        let txid = tx.compute_txid();
        if self.graph.get(&txid).is_some() {
            return AcceptError::Duplicate(txid);
        }
        if let Some(parked) = self.orphanage.missing_of(&txid).cloned() {
            if self.orphanage.contains_wtxid(&tx.compute_wtxid()) {
                if let Some(peer) = from {
                    self.orphanage.add_announcer(&txid, peer);
                }
                return AcceptError::Orphaned {
                    txid,
                    missing: parked,
                    fresh: false,
                };
            }
        }
        if missing.is_empty() {
            return AcceptError::MissingPrevout(tx.input[0].previous_output);
        }
        if self
            .orphanage
            .insert_from(tx.clone(), missing.clone(), from)
        {
            AcceptError::Orphaned {
                txid,
                missing,
                fresh: true,
            }
        } else {
            AcceptError::MissingPrevout(tx.input[0].previous_output)
        }
    }

    /// Take orphans waiting on `parent` (hub promote outside the write lock).
    pub fn take_orphan_children(&mut self, parent: Txid) -> Vec<Transaction> {
        self.orphanage.take_children_of(&parent)
    }

    /// Drop orphans that are themselves in `block_txids`.
    pub fn erase_orphans_for_block(&mut self, block_txids: &[Txid]) {
        self.orphanage.erase_for_block(block_txids);
    }

    /// Re-check + RBF + durable insert after scripts verified off-lock.
    ///
    /// Fail closed on race (duplicate, conflict set changed, parent gone).
    /// Chain coins come from `prep` (resolved under read); no UTXO provider.
    pub fn commit_after_script(
        &mut self,
        tx: &Transaction,
        prep: PreparedAdmit,
    ) -> Result<AcceptResult, AcceptError> {
        let (conflict_set, fee_sat, adj_weight) = self.plan_after_script(tx, &prep)?;
        let txid = prep.txid;
        let weight = prep.weight;

        let mut replaced_scripthashes: Vec<[u8; 32]> = Vec::new();
        let mut replaced_txs: Vec<Transaction> = Vec::new();
        for c in &conflict_set {
            if let Some(old) = self.bodies.get(c) {
                let old_tx = (**old).clone();
                self.note_extra(&old_tx);
                for o in &old_tx.output {
                    replaced_scripthashes
                        .push(Self::electrum_scripthash(o.script_pubkey.as_bytes()));
                }
                replaced_txs.push(old_tx);
            }
        }
        replaced_scripthashes.sort_unstable();
        replaced_scripthashes.dedup();

        for c in conflict_set.iter().rev() {
            let _ = self.remove_txid(c);
        }

        self.ensure_free_slot(Some(txid))?;

        let aux = Self::vin_aux_from_prep(tx, &prep);
        let t_dur = Instant::now();
        let slot = self.store.append_live_tx(
            tx,
            &txid,
            &prep.wtxid,
            fee_sat,
            weight,
            prep.sigop_cost,
            &aux,
        )?;
        self.last_accept_stages.durable_us = self
            .last_accept_stages
            .durable_us
            .saturating_add(t_dur.elapsed().as_micros() as u64);

        let entry = TxEntry {
            txid,
            wtxid: prep.wtxid,
            fee_sat,
            weight,
            sigop_cost: prep.sigop_cost,
            slot,
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        };
        let body = Arc::new(tx.clone());
        self.graph.insert(entry, tx);
        self.bodies.insert(txid, Arc::clone(&body));
        self.vin_aux.insert(txid, aux);

        self.evict_to_budget(Some(txid))?;

        Ok(AcceptResult {
            txid,
            fee_sat,
            weight: adj_weight,
            slot,
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes,
            replaced_txs,
        })
    }

    /// Prepare + RBF/cluster checks with no graph or store mutation.
    /// `weight` in the result is sigop-adjusted.
    pub fn evaluate_after_script(
        &self,
        tx: &Transaction,
        prep: PreparedAdmit,
    ) -> Result<AcceptResult, AcceptError> {
        let (conflict_set, fee_sat, weight) = self.plan_after_script(tx, &prep)?;
        Ok(AcceptResult {
            txid: prep.txid,
            fee_sat,
            weight,
            slot: 0,
            replaced: conflict_set.into_iter().collect(),
            replaced_scripthashes: Vec::new(),
            replaced_txs: Vec::new(),
        })
    }

    /// Returns (conflict set, fee, sigop-adjusted weight).
    fn plan_after_script(
        &self,
        tx: &Transaction,
        prep: &PreparedAdmit,
    ) -> Result<(BTreeSet<Txid>, u64, u64), AcceptError> {
        let txid = prep.txid;
        if let Some(live) = self.graph.get(&txid) {
            if live.wtxid == prep.wtxid {
                return Err(AcceptError::Duplicate(txid));
            }
            return Err(AcceptError::Policy("txn-same-nonwitness-data-in-mempool"));
        }
        if self.orphanage.contains(&txid) {
            let missing = self
                .orphanage
                .missing_of(&txid)
                .cloned()
                .unwrap_or_default();
            return Err(AcceptError::Orphaned {
                txid,
                missing,
                fresh: false,
            });
        }

        let scan = self.scan_conflicts_and_parents(txid, tx, &prep.chain_coins)?;

        let fee_sat = prep.fee_sat;
        let weight =
            sigops_adjusted_weight(prep.weight, prep.sigop_cost, self.graph.bytes_per_sigop());
        let admit_fee =
            (i128::from(fee_sat).saturating_add(i128::from(prep.fee_delta))).max(0) as u64;

        let conflict_set = if !scan.direct_conflicts.is_empty() {
            let direct: Vec<Txid> = scan.direct_conflicts.into_iter().collect();
            let set = self.graph.conflict_set(&direct);
            let (old_fee, old_weight) = self.graph.set_fee_weight(&set);
            let (direct_fee, direct_weight) = self
                .graph
                .set_fee_weight(&direct.iter().copied().collect::<BTreeSet<_>>());
            if !rbf_allows_replacement(
                admit_fee,
                weight,
                old_fee,
                old_weight,
                direct_fee,
                direct_weight,
            ) {
                return Err(AcceptError::RbfInsufficient);
            }
            set
        } else {
            BTreeSet::new()
        };
        let parent_txids: BTreeSet<Txid> = scan
            .parent_txids
            .into_iter()
            .filter(|p| !conflict_set.contains(p))
            .collect();
        // Cluster limits count raw weight (Libre): at 20 B/sigop an adjusted
        // cap would reject any tx above ~20,200 sigop cost.
        let (n_members, base_w) = self
            .graph
            .connected_weight_except(&parent_txids, &conflict_set);
        let combined_w = base_w.saturating_add(prep.weight);
        if n_members + 1 > self.graph.cluster_count_limit()
            || combined_w.saturating_add(3) / 4 > self.graph.cluster_vsize_limit()
        {
            return Err(AcceptError::ClusterTooLarge {
                count: n_members + 1,
                weight: combined_w,
            });
        }

        Ok((conflict_set, fee_sat, weight))
    }

    /// Electrum scripthash = SHA256(scriptPubKey) (same as store `script_hash`).
    fn electrum_scripthash(script: &[u8]) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash};
        *sha256::Hash::hash(script).as_byte_array()
    }

    /// Re-try orphans that listed `parent` as missing (recursive via accept_tx_with).
    ///
    /// Uses `accept_tx_with` (not top-level accept_tx) so stage timers accumulate
    /// on the parent admit that unlocked the orphan chain. Public for hub staged commit.
    pub fn promote_orphans_of(
        &mut self,
        parent: Txid,
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) {
        let children = self.orphanage.take_children_of(&parent);
        for child in children {
            if let Ok(r) = self.accept_tx_with(&child, utxos, tip, 0, true, None) {
                self.promote_orphans_of(r.txid, utxos, tip);
            }
        }
    }

    /// Ensure the durable slot table has a FREE/DEAD entry for the next append.
    ///
    /// Order: if full of LIVE, **grow** the slot table first (weight may still have
    /// headroom — mainnet 4k-slot stall); if at max cap, **evict** worst chunks.
    /// Never surface as store corruption.
    fn ensure_free_slot(&mut self, protect: Option<Txid>) -> Result<(), AcceptError> {
        if self.store.has_free_slot() {
            return Ok(());
        }
        match self.store.grow_slots() {
            Ok(()) => {
                if self.store.has_free_slot() {
                    return Ok(());
                }
            }
            Err(MempoolError::Full) => {}
            Err(e) => return Err(e.into()),
        }
        self.evict_worst_chunks(protect, EvictUntil::FreeSlot)?;
        if self.store.has_free_slot() {
            return Ok(());
        }
        Err(AcceptError::Policy("mempool full"))
    }

    /// Remove lowest-feerate chunks until `total_weight <= max_weight`.
    ///
    /// Prefer not to evict `protect` (the just-accepted tx). Returns how many removed.
    pub fn evict_to_budget(&mut self, protect: Option<Txid>) -> Result<usize, AcceptError> {
        self.evict_worst_chunks(protect, EvictUntil::WeightBudget)
    }

    fn evict_worst_chunks(
        &mut self,
        protect: Option<Txid>,
        until: EvictUntil,
    ) -> Result<usize, AcceptError> {
        let mut removed = 0usize;
        let mut guard = 0u32;
        loop {
            match until {
                EvictUntil::FreeSlot => {
                    if self.store.has_free_slot() || guard >= 10_000 {
                        break;
                    }
                    guard += 1;
                }
                EvictUntil::WeightBudget => {
                    if self.graph.total_weight() <= self.max_weight {
                        break;
                    }
                }
            }
            let n = self.evict_worst_chunk_once(protect)?;
            if n == 0 {
                break;
            }
            removed = removed.saturating_add(n);
        }
        Ok(removed)
    }

    /// One worst-chunk pass. Returns how many txs this pass removed (0 = stop).
    fn evict_worst_chunk_once(&mut self, protect: Option<Txid>) -> Result<usize, AcceptError> {
        let Some((_rep, chunk)) = self.graph.worst_chunk() else {
            return Ok(0);
        };
        if chunk.txids.len() == 1 && protect == chunk.txids.first().copied() {
            return Ok(0);
        }
        let evicted_rate = chunk.fee_rate_sat_per_kvb();
        self.note_evicted_feerate(evicted_rate);
        let mut removed = 0usize;
        for t in &chunk.txids {
            if protect == Some(*t) {
                continue;
            }
            if self.graph.contains(t) {
                let gone = self.remove_txid_tree(t);
                removed = removed.saturating_add(gone.len());
            }
        }
        Ok(removed)
    }

    /// Count / weight / topo checks for an ancestor package (no graph lock).
    pub fn check_package_shape(txs: &[Transaction]) -> Result<(), AcceptError> {
        if txs.is_empty() {
            return Err(AcceptError::PackageEmpty);
        }
        let total_weight: u64 = txs.iter().map(|t| t.weight().to_wu()).sum();
        if txs.len() > MAX_PACKAGE_COUNT || total_weight > MAX_PACKAGE_WEIGHT {
            return Err(AcceptError::PackageTooLarge {
                count: txs.len(),
                weight: total_weight,
            });
        }
        let mut seen = BTreeSet::new();
        let mut pkg_ids = BTreeSet::new();
        for tx in txs {
            if tx.is_coinbase() {
                return Err(AcceptError::Coinbase);
            }
            let id = tx.compute_txid();
            if !seen.insert(id) {
                return Err(AcceptError::Duplicate(id));
            }
            pkg_ids.insert(id);
        }
        for (i, tx) in txs.iter().enumerate() {
            for inp in &tx.input {
                let parent = inp.previous_output.txid;
                if pkg_ids.contains(&parent) {
                    let parent_pos = txs.iter().position(|t| t.compute_txid() == parent);
                    match parent_pos {
                        Some(p) if p < i => {}
                        _ => return Err(AcceptError::PackageNotTopo),
                    }
                }
            }
        }
        Ok(())
    }

    /// Core `IsChildWithParents`: last tx spends every other package member.
    pub fn package_is_child_with_direct_parents(txs: &[Transaction]) -> bool {
        if txs.len() < 2 {
            return false;
        }
        let spent: BTreeSet<Txid> = txs[txs.len() - 1]
            .input
            .iter()
            .map(|i| i.previous_output.txid)
            .collect();
        txs[..txs.len() - 1]
            .iter()
            .all(|tx| spent.contains(&tx.compute_txid()))
    }

    /// Last tx is a child; every other member is an in-package ancestor of it.
    fn package_is_child_with_parents(txs: &[Transaction]) -> bool {
        if txs.len() < 2 {
            return false;
        }
        let ids: BTreeMap<Txid, usize> = txs
            .iter()
            .enumerate()
            .map(|(i, tx)| (tx.compute_txid(), i))
            .collect();
        let child = txs.len() - 1;
        let mut ancestors = BTreeSet::new();
        let mut stack = vec![child];
        while let Some(i) = stack.pop() {
            for inp in &txs[i].input {
                let Some(&pi) = ids.get(&inp.previous_output.txid) else {
                    continue;
                };
                if ancestors.insert(txs[pi].compute_txid()) {
                    stack.push(pi);
                }
            }
        }
        !ancestors.is_empty() && ancestors.len() + 1 == txs.len()
    }

    /// Combined ancestor/CPFP package fee vs total sigop-adjusted weight
    /// against `sat_kvb`.
    pub fn package_meets_min_relay(
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        sat_kvb: u64,
        bytes_per_sigop: u64,
    ) -> bool {
        if !Self::package_is_child_with_parents(txs) {
            return false;
        }
        let mut created: BTreeMap<Txid, &[TxOut]> = BTreeMap::new();
        let mut fee = 0u64;
        let mut weight = 0u64;
        for tx in txs {
            let mut prevouts = Vec::with_capacity(tx.input.len());
            for inp in &tx.input {
                let op = inp.previous_output;
                let prev = if let Some(outs) = created.get(&op.txid) {
                    outs.get(op.vout as usize).cloned()
                } else {
                    utxos.get_coin(&op).map(|c| c.txout)
                };
                let Some(prev) = prev else {
                    return false;
                };
                prevouts.push(prev);
            }
            let Some((f, w)) = fee_and_adjusted_weight(tx, &prevouts, bytes_per_sigop) else {
                return false;
            };
            fee = fee.saturating_add(f);
            weight = weight.saturating_add(w);
            created.insert(tx.compute_txid(), &tx.output);
        }
        policy::meets_min_relay_fee_at(fee, weight, sat_kvb)
    }

    /// Accept an ancestor package (CPFP): txs must be parent-before-child.
    ///
    /// On any failure, already-accepted members of this package are rolled back.
    pub fn accept_package(
        &mut self,
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<Vec<AcceptResult>, AcceptError> {
        Self::check_package_shape(txs)?;

        self.last_accept_stages = AcceptStageUs::default();
        let member_min = if Self::package_meets_min_relay(
            txs,
            utxos,
            self.min_relay_sat_kvb,
            self.graph.bytes_per_sigop(),
        ) {
            Some(0)
        } else {
            None
        };
        let mut accepted: Vec<AcceptResult> = Vec::with_capacity(txs.len());
        for tx in txs {
            // accept_tx_with + promote (not top-level accept_tx) so stages are not reset per member.
            match self.accept_tx_with(tx, utxos, tip, 0, true, member_min) {
                Ok(r) => {
                    self.promote_orphans_of(r.txid, utxos, tip);
                    accepted.push(r);
                }
                Err(e) => {
                    self.rollback_accepted_package(&accepted, utxos, tip);
                    return Err(e);
                }
            }
        }
        Ok(accepted)
    }

    fn rollback_accepted_package(
        &mut self,
        accepted: &[AcceptResult],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) {
        let victims: Vec<Transaction> = accepted
            .iter()
            .flat_map(|r| r.replaced_txs.iter().cloned())
            .collect();
        for r in accepted.iter().rev() {
            let _ = self.remove_txid_tree(&r.txid);
        }
        for tx in victims {
            let _ = self.accept_tx(&tx, utxos, tip);
        }
    }

    /// Durable remove one live tx (confirm / RBF / eviction).
    pub fn remove_txid(&mut self, txid: &Txid) -> Result<(), AcceptError> {
        let entry = self
            .graph
            .get(txid)
            .ok_or(AcceptError::NotFound(*txid))?
            .clone();
        let tx = self
            .bodies
            .get(txid)
            .cloned()
            .ok_or(AcceptError::Durable("body missing".into()))?;
        self.remember_extra_compact(&tx);
        self.store.mark_slot_dead(entry.slot)?;
        self.graph.remove(txid, &tx);
        self.bodies.remove(txid);
        self.vin_aux.remove(txid);
        Ok(())
    }

    /// Remove `txid` and live mempool txs that spend it (1p1c child-fail rollback).
    ///
    /// Returns every txid dropped (spenders first, then `txid` if it was live).
    pub fn remove_txid_tree(&mut self, txid: &Txid) -> Vec<Txid> {
        let n_out = self
            .get_tx(txid)
            .map(|tx| tx.output.len() as u32)
            .unwrap_or(0);
        let spent: Vec<OutPoint> = (0..n_out)
            .map(|vout| OutPoint { txid: *txid, vout })
            .collect();
        let mut gone = self.evict_conflicts_with(&spent);
        if self.remove_txid(txid).is_ok() {
            gone.push(*txid);
        }
        gone
    }

    /// Remove all txs that appear in a confirmed block (coinbase ignored if present).
    ///
    /// Missing mempool entries are skipped (already not in pool). Returns how many removed.
    /// May trigger compaction when DEAD slots dominate.
    ///
    /// Also drops orphanage entries that are confirmed or conflict with the block,
    /// and best-effort re-accepts orphans whose parent just confirmed (caller must
    /// pass a UTXO view that includes the new tip — use [`remove_for_block_with_utxo`]).
    pub fn remove_for_block(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        self.remove_for_block_with_utxo(
            block_txids,
            &MapUtxoProvider {
                map: std::collections::HashMap::new(),
            },
            ChainTipCtx::default(),
        )
    }

    /// Remove live graph entries listed in `block_txids` (no orphan promote).
    pub fn remove_live_txids(&mut self, block_txids: &[Txid]) -> Result<usize, AcceptError> {
        let mut n = 0usize;
        for txid in block_txids {
            if self.graph.contains(txid) {
                self.remove_txid(txid)?;
                n += 1;
            }
        }
        if n > 0 {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        Ok(n)
    }

    /// Like [`remove_for_block`], then promote orphans of confirmed parents via `utxos`.
    pub fn remove_for_block_with_utxo(
        &mut self,
        block_txids: &[Txid],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Result<usize, AcceptError> {
        let n = self.remove_live_txids(block_txids)?;
        for txid in block_txids {
            self.promote_orphans_of(*txid, utxos, tip);
        }
        self.orphanage.erase_for_block(block_txids);
        Ok(n)
    }

    /// Drop live txs (and their descendants) that spend `spent` outpoints.
    ///
    /// A confirmed block that double-spends mempool txs does not list those
    /// txs in `txdata`; `remove_for_block` alone would leave them hanging.
    pub fn evict_conflicts_with(&mut self, spent: &[OutPoint]) -> Vec<Txid> {
        let mut direct = Vec::new();
        for op in spent {
            if let Some(c) = self.graph.conflict_txid(op) {
                direct.push(c);
            }
        }
        if direct.is_empty() {
            return Vec::new();
        }
        let set = self.graph.conflict_set(&direct);
        let mut out = Vec::new();
        for id in set {
            if self.remove_txid(&id).is_ok() {
                out.push(id);
            }
        }
        if !out.is_empty() {
            let _ = self.maybe_compact();
            let _ = self.store.persist_if_dirty();
        }
        out
    }

    pub fn orphan_count(&self) -> usize {
        self.orphanage.len()
    }

    pub fn extra_compact_txs(&self) -> impl Iterator<Item = &Transaction> {
        self.extra_compact.iter().map(|(_, tx)| tx)
    }

    /// Recently seen body for BIP152 extra fill (compact prefill / blocktxn / strip).
    pub fn remember_extra_compact(&mut self, tx: &Transaction) {
        self.note_extra(tx);
    }

    pub fn accept_failure_record(tx: &Transaction, e: &AcceptError) -> Option<AcceptFailureRecord> {
        match e {
            AcceptError::InputsDuplicate | AcceptError::Coinbase => {
                Some(AcceptFailureRecord::Invalid(tx.compute_txid()))
            }
            AcceptError::Script(s)
                if !tx_has_witness(tx)
                    && !s.contains("WITNESS_UNEXPECTED")
                    && !s.contains("empty witness") =>
            {
                Some(AcceptFailureRecord::Invalid(tx.compute_txid()))
            }
            AcceptError::Policy("min relay fee") => Some(AcceptFailureRecord::Extra),
            _ => None,
        }
    }

    pub fn apply_accept_failure(&mut self, tx: &Transaction, rec: AcceptFailureRecord) {
        match rec {
            AcceptFailureRecord::Invalid(txid) => self.note_invalid(txid),
            AcceptFailureRecord::Extra => self.note_extra(tx),
        }
    }

    pub fn note_accept_failure(&mut self, tx: &Transaction, e: &AcceptError) {
        if let Some(rec) = Self::accept_failure_record(tx, e) {
            self.apply_accept_failure(tx, rec);
        }
    }

    fn note_invalid(&mut self, txid: Txid) {
        if self.recent_invalid.len() >= RECENT_INVALID_CAP {
            self.recent_invalid.clear();
        }
        self.recent_invalid.insert(txid);
    }

    fn note_extra(&mut self, tx: &Transaction) {
        if tx.is_coinbase() {
            return;
        }
        let txid = tx.compute_txid();
        self.extra_compact.retain(|(id, _)| *id != txid);
        if self.extra_compact.len() >= EXTRA_COMPACT_CAP {
            self.extra_compact.pop_front();
        }
        self.extra_compact.push_back((txid, tx.clone()));
    }

    fn extra_by_txid(&self, txid: Txid) -> Option<&Transaction> {
        self.extra_compact
            .iter()
            .find(|(id, _)| *id == txid)
            .map(|(_, tx)| tx)
    }

    /// 1p1c parent body from extra-compact. Parent inputs must be confirmed.
    pub fn try_one_parent_package(
        &self,
        child: &Transaction,
        missing: &BTreeSet<Txid>,
        utxos: &impl UtxoProvider,
    ) -> Option<Transaction> {
        if missing.len() != 1 {
            return None;
        }
        let pid = *missing.iter().next()?;
        if self.recent_invalid.contains(&pid) {
            return None;
        }
        let parent = self.extra_by_txid(pid)?.clone();
        if !self.package_pays_min_relay(&parent, child, utxos) {
            return None;
        }
        Some(parent)
    }

    /// Combined parent+child fee must meet min-relay. Parent inputs must be
    /// confirmed (no unconfirmed grandparent — same limit as Core 1p1c).
    fn package_pays_min_relay(
        &self,
        parent: &Transaction,
        child: &Transaction,
        utxos: &impl UtxoProvider,
    ) -> bool {
        let bps = self.graph.bytes_per_sigop();
        let pid = parent.compute_txid();
        let p_prev: Option<Vec<TxOut>> = parent
            .input
            .iter()
            .map(|i| utxos.get_coin(&i.previous_output).map(|c| c.txout))
            .collect();
        let c_prev: Option<Vec<TxOut>> = child
            .input
            .iter()
            .map(|i| {
                let op = i.previous_output;
                if op.txid == pid {
                    parent.output.get(op.vout as usize).cloned()
                } else {
                    utxos.get_coin(&op).map(|c| c.txout)
                }
            })
            .collect();
        let (Some(p_prev), Some(c_prev)) = (p_prev, c_prev) else {
            return false;
        };
        let (Some((pf, pw)), Some((cf, cw))) = (
            fee_and_adjusted_weight(parent, &p_prev, bps),
            fee_and_adjusted_weight(child, &c_prev, bps),
        ) else {
            return false;
        };
        policy::meets_min_relay_fee_at(
            pf.saturating_add(cf),
            pw.saturating_add(cw),
            self.min_relay_sat_kvb,
        )
    }

    /// Re-accept non-coinbase txs after a reorg disconnect (best-effort).
    ///
    /// Failures on individual txs are collected; successful accepts remain.
    pub fn reorg_disconnect_reaccept(
        &mut self,
        txs: &[Transaction],
        utxos: &impl UtxoProvider,
        tip: ChainTipCtx,
    ) -> Vec<Result<AcceptResult, AcceptError>> {
        let out: Vec<Result<AcceptResult, AcceptError>> = txs
            .iter()
            .filter(|t| !t.is_coinbase())
            .map(|t| self.accept_tx(t, utxos, tip))
            .collect();
        self.evict_nonfinal(utxos, tip);
        out
    }

    /// Drop live txs whose BIP68 / finality no longer holds (reorg: parent
    /// went from confirmed to mempool).
    pub fn evict_nonfinal(&mut self, utxos: &impl UtxoProvider, tip: ChainTipCtx) {
        loop {
            let ids: Vec<Txid> = self.graph.iter().map(|(t, _)| *t).collect();
            let mut removed = false;
            for id in ids {
                let Some(tx) = self.get_tx(&id).cloned() else {
                    continue;
                };
                let mut chain_coins = Vec::with_capacity(tx.input.len());
                let mut missing_chain = false;
                for inp in &tx.input {
                    if self.graph.creator(&inp.previous_output).is_some() {
                        chain_coins.push(None);
                    } else if let Some(c) = utxos.get_coin(&inp.previous_output) {
                        chain_coins.push(Some(c));
                    } else {
                        // Parent is neither live nor a confirmed coin — reorg
                        // made the input disappear (or we just evicted it).
                        missing_chain = true;
                        break;
                    }
                }
                if missing_chain || check_mempool_structural(&tx, &chain_coins, tip).is_err() {
                    let _ = self.remove_txid(&id);
                    removed = true;
                }
            }
            if !removed {
                break;
            }
        }
    }

    /// Fill sigop cost for entries migrated from schema ≤ 2 (open-time pass).
    ///
    /// Prevouts resolve from live parents or `utxos`. Entries whose prevouts
    /// no longer resolve, or whose cost cannot fit a block, are evicted
    /// (with spenders). Filled costs are written back to the durable record.
    pub fn recompute_missing_sigops(&mut self, utxos: &impl UtxoProvider) {
        let ids: Vec<Txid> = self
            .graph
            .iter()
            .filter(|(_, e)| e.sigop_cost == u64::MAX)
            .map(|(t, _)| *t)
            .collect();
        for id in ids {
            let Some(tx) = self.get_tx(&id).cloned() else {
                continue;
            };
            let prevouts: Option<Vec<TxOut>> = tx
                .input
                .iter()
                .map(|inp| {
                    let op = inp.previous_output;
                    match self.graph.creator(&op) {
                        Some(p) => self
                            .get_tx(&p)
                            .and_then(|t| t.output.get(op.vout as usize))
                            .cloned(),
                        None => utxos.get_coin(&op).map(|c| c.txout),
                    }
                })
                .collect();
            let slot = self.graph.get(&id).map(|e| e.slot);
            match (
                prevouts.map(|p| block_fit_sigop_cost(&tx, &p, self.graph.block_reserved_sigops())),
                slot,
            ) {
                (Some(Ok(cost)), Some(slot)) => {
                    self.graph.set_sigop_cost(&id, cost);
                    if let Err(e) = self.store.set_sigop_cost(slot, cost) {
                        rbitcoin_log::warn!("mempool: sigops write-back {id}: {e}");
                    }
                }
                _ => {
                    let gone = self.remove_txid_tree(&id);
                    rbitcoin_log::info!(
                        "mempool: sigops recompute evicted {id} ({} with spenders): inputs gone or cost over block budget",
                        gone.len()
                    );
                }
            }
        }
    }

    /// Lookup a live body (for tests / Electrum unconf).
    pub fn get_tx(&self, txid: &Txid) -> Option<&Transaction> {
        self.bodies.get(txid).map(|a| a.as_ref())
    }

    /// Packed vin aux for a live tx (SH reindex / purge). Empty if unknown.
    pub fn vin_aux(&self, txid: &Txid) -> &[VinAux] {
        self.vin_aux.get(txid).map_or(&[], Vec::as_slice)
    }

    fn vin_aux_from_prep(tx: &Transaction, prep: &PreparedAdmit) -> Vec<VinAux> {
        tx.input
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let script_hash = prep
                    .prevouts
                    .get(i)
                    .map(|o| Self::electrum_scripthash(o.script_pubkey.as_bytes()));
                let create_fk = prep
                    .chain_coins
                    .get(i)
                    .and_then(|c| c.as_ref())
                    .and_then(|c| c.create_fk);
                VinAux {
                    prev_txid: inp.previous_output.txid,
                    vout: inp.previous_output.vout,
                    script_hash,
                    create_fk,
                }
            })
            .collect()
    }

    /// This node's own block budget (GBT / `generate`): template weight and
    /// the admission sigop reserve, with a `-blockmintxfee` floor.
    pub fn template_budget(&self, min_sat_kvb: u64) -> SelectBudget {
        SelectBudget {
            max_weight_wu: TxGraph::template_tx_weight(),
            reserved_sigops: self.graph.block_reserved_sigops(),
            min_sat_kvb,
        }
    }

    /// Mining-order live txs that fit `budget` (best chunks first) with
    /// `prioritisetransaction` deltas, each with its [`Selected`] meta.
    pub fn select_block_template(
        &self,
        budget: SelectBudget,
        delta: impl Fn(Txid) -> i64,
    ) -> Vec<(Transaction, Selected)> {
        self.graph
            .select_block_template(budget, delta)
            .into_iter()
            .filter_map(|s| self.get_tx(&s.txid).map(|tx| (tx.clone(), s)))
            .collect()
    }
}

/// BIP125-style full-RBF fee check (no signaling required — Libre full RBF).
///
/// Requires strictly higher absolute fee over the **conflict set** (incl.
/// descendants), higher feerate, and incremental relay fee on replacement vsize.
pub fn rbf_pays_for_replacement(
    new_fee: u64,
    new_weight: u64,
    old_fee: u64,
    old_weight: u64,
) -> bool {
    if new_fee <= old_fee {
        return false;
    }
    let new_rate = policy::fee_rate_sat_per_kvb(new_fee, new_weight);
    let old_rate = policy::fee_rate_sat_per_kvb(old_fee, old_weight);
    if new_rate <= old_rate {
        return false;
    }
    let vsize = policy::get_virtual_size(new_weight);
    let inc = vsize
        .saturating_mul(INCREMENTAL_RELAY_FEE_RATE_SAT_PER_KVB)
        .saturating_add(999)
        / 1000;
    new_fee.saturating_sub(old_fee) >= inc
}

/// Pure replace-by-fee-rate (Libre Relay): `new_rate ≥ 1.25 × direct_conflict_rate`.
///
/// Uses only **direct** conflict fee/weight (not the full descendant set), so a
/// high-feerate replacement can unpin low-feerate descendant packages.
///
/// Integer form: `new_fee * DEN * direct_vsize ≥ direct_fee * NUM * new_vsize`
/// with `NUM/DEN = 5/4`.
pub fn pure_rbfr_pays(new_fee: u64, new_weight: u64, direct_fee: u64, direct_weight: u64) -> bool {
    if new_weight == 0 || direct_weight == 0 {
        return false;
    }
    let new_v = policy::get_virtual_size(new_weight);
    let old_v = policy::get_virtual_size(direct_weight);
    if new_v == 0 || old_v == 0 {
        return false;
    }
    new_fee.saturating_mul(RBFR_RATIO_DEN).saturating_mul(old_v)
        >= direct_fee
            .saturating_mul(RBFR_RATIO_NUM)
            .saturating_mul(new_v)
}

/// Admit replacement if BIP125-style rules **or** pure RBFR (Libre).
pub fn rbf_allows_replacement(
    new_fee: u64,
    new_weight: u64,
    conflict_fee: u64,
    conflict_weight: u64,
    direct_fee: u64,
    direct_weight: u64,
) -> bool {
    rbf_pays_for_replacement(new_fee, new_weight, conflict_fee, conflict_weight)
        || pure_rbfr_pays(new_fee, new_weight, direct_fee, direct_weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{MAX_CLUSTER_COUNT, MAX_CLUSTER_VSIZE, MAX_CLUSTER_WEIGHT};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Witness};
    use std::collections::{BTreeSet, HashMap};

    fn tmp_dir() -> rbitcoin_store::testutil::TempDir {
        rbitcoin_store::testutil::TempDir::labeled("mempool-accept").unwrap()
    }

    /// Tip high enough that maturity/finality/BIP68 do not block normal test txs.
    const TIP_OK: ChainTipCtx = ChainTipCtx {
        height: 1_000_000,
        mtp: u32::MAX,
    };

    fn coin(txout: TxOut) -> Coin {
        Coin {
            txout,
            create_height: 0,
            create_mtp: 0,
            is_coinbase: false,
            create_fk: None,
        }
    }

    fn chain_utxo(value: u64) -> (OutPoint, TxOut, MapUtxoProvider) {
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout.clone()));
        (op, txout, MapUtxoProvider { map })
    }

    /// Finding 011: duplicate inputs rejected before fee accounting.
    #[test]
    fn reject_duplicate_inputs() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: op, // same outpoint twice
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::InputsDuplicate), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 011: absolute nLockTime height form not final at tip+1.
    #[test]
    fn reject_non_final_locktime_height() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 99_000);
        // Height lock: need block_height > 500; tip.height+1 = 101 → not final.
        tx.lock_time = LockTime::from_height(500).unwrap();
        // Non-final sequence so locktime is enforced.
        tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
        let tip = ChainTipCtx {
            height: 100,
            mtp: u32::MAX,
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
        assert!(matches!(err, AcceptError::NotFinal), "got {err}");
        // At tip 500, next height 501 > 500 → final.
        let tip2 = ChainTipCtx {
            height: 500,
            mtp: u32::MAX,
        };
        mp.accept_tx(&tx, &utxos, tip2).expect("final at tip 500");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 011: immature coinbase spend rejected.
    #[test]
    fn reject_immature_coinbase() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            Coin {
                txout: TxOut {
                    value: Amount::from_sat(50_0000_0000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                create_height: 50,
                create_mtp: 0,
                is_coinbase: true,
                create_fk: None,
            },
        );
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 49_0000_0000);
        // tip 100 → next 101; need create+100 = 150.
        let tip = ChainTipCtx {
            height: 100,
            mtp: u32::MAX,
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, tip).unwrap_err();
        assert!(matches!(err, AcceptError::ImmatureCoinbase), "got {err}");
        let tip2 = ChainTipCtx {
            height: 149,
            mtp: u32::MAX,
        };
        mp.accept_tx(&tx, &utxos, tip2)
            .expect("mature at tip 149 (next=150)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bip68_time_lock_uses_coin_create_mtp() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0x22; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            Coin {
                txout: TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                create_height: 10,
                create_mtp: 1_000_000,
                is_coinbase: false,
                create_fk: None,
            },
        );
        let utxos = MapUtxoProvider { map };
        let mut tx = spend_tx(op, 49_000);
        tx.version = Version::TWO;
        // Time-type relative lock of 2 units (2 << 9 = 1024 seconds).
        tx.input[0].sequence = Sequence::from_consensus((1 << 22) | 2);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        // prev MTP 1_000_000 + 1024 - 1 = 1_001_023; tip MTP 1_001_000 → not final.
        let err = mp
            .accept_tx(
                &tx,
                &utxos,
                ChainTipCtx {
                    height: 20,
                    mtp: 1_001_000,
                },
            )
            .unwrap_err();
        assert!(matches!(err, AcceptError::NonBip68Final), "got {err}");
        mp.accept_tx(
            &tx,
            &utxos,
            ChainTipCtx {
                height: 20,
                mtp: 1_002_000,
            },
        )
        .expect("time lock satisfied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Stage timers are recorded on a successful chain-spend accept.
    #[test]
    fn accept_records_stage_us_on_success() {
        let dir = tmp_dir();
        let (op, _txout, utxos) = chain_utxo(50_000);
        let tx = spend_tx(op, 49_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).expect("accept");
        let s = mp.last_accept_stages;
        // Detached script hop + durable append should register µs on typical hosts.
        assert!(
            s.script_us > 0 || s.durable_us > 0 || s.utxo_us > 0,
            "expected non-zero stage sample, got {s:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 010: provider returns no coin for a spent/missing outpoint → reject.
    #[test]
    fn reject_when_provider_has_no_unspent_coin() {
        let dir = tmp_dir();
        let op = OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        };
        let tx = spend_tx(op, 1_000);
        let utxos = MapUtxoProvider {
            map: HashMap::new(), // spent or unknown → no coin
        };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp
            .accept_tx(&tx, &utxos, TIP_OK)
            .expect_err("must not admit");
        // Orphanage parks missing parents; empty map → orphaned or missing.
        assert!(
            matches!(
                err,
                AcceptError::Orphaned { .. } | AcceptError::MissingPrevout(_)
            ),
            "got {err}"
        );
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn mempool_under_pressure() {
        assert_eq!(decayed_relay_floor(5_000, 100, 0), 5_000);
        assert_eq!(
            decayed_relay_floor(5_000, 100, ROLLING_FEE_HALFLIFE_MS),
            100 + ((5_000 - 100) >> 1)
        );
        assert_eq!(
            relay_floor(100, 5_000, 0, ROLLING_FEE_HALFLIFE_MS, true),
            5_000
        );
        assert_eq!(
            relay_floor(100, 5_000, 0, ROLLING_FEE_HALFLIFE_MS, false),
            100 + ((5_000 - 100) >> 1)
        );
        assert_eq!(
            decayed_relay_floor(5_000, 100, 2 * ROLLING_FEE_HALFLIFE_MS),
            100 + ((5_000 - 100) >> 2)
        );
        assert_eq!(
            decayed_relay_floor(u64::MAX, 100, 63 * ROLLING_FEE_HALFLIFE_MS),
            100
        );
        assert_eq!(ROLLING_FEE_HALFLIFE_MS, 43_200_000);
        assert!(unix_ms() > 1_700_000_000_000);

        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(10_000_000);
        let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 800).unwrap();
        let before = mp.mempool_min_fee_sat_kvb();
        assert!(before > policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB);
        for i in 0u8..8 {
            let spend = OutPoint {
                txid: Txid::from_byte_array([i.wrapping_add(1); 32]),
                vout: 0,
            };
            let mut map = HashMap::new();
            map.insert(
                spend,
                coin(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }),
            );
            let out = 99_000u64 - u64::from(i) * 100;
            mp.accept_tx(&spend_tx(spend, out), &MapUtxoProvider { map }, TIP_OK)
                .unwrap_or_else(|e| panic!("i={i}: {e}"));
        }
        let after = mp.mempool_min_fee_sat_kvb();
        assert!(
            after > before,
            "eviction must raise the floor above the static bump ({before} -> {after})"
        );
        let probe_op = OutPoint {
            txid: Txid::from_byte_array([0xee; 32]),
            vout: 0,
        };
        let probe = spend_tx(probe_op, 99_000);
        let vsize = policy::get_virtual_size(probe.weight().to_wu());
        let fee = vsize.saturating_mul(before).div_ceil(1_000);
        let tx = spend_tx(probe_op, 100_000 - fee);
        let mut map = HashMap::new();
        map.insert(
            probe_op,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
        let err = mp
            .accept_tx(&tx, &MapUtxoProvider { map }, TIP_OK)
            .expect_err("same static-bump rate must not re-enter");
        assert!(
            matches!(
                err,
                AcceptError::Policy("mempool min fee") | AcceptError::Policy("min relay fee")
            ),
            "{err}"
        );

        mp.max_weight = mp
            .graph
            .total_weight()
            .saturating_add(policy::MAX_STANDARD_TX_WEIGHT);
        mp.rolling_min_sat_kvb = 5_000;
        mp.rolling_updated_ms = 0;
        mp.min_relay_sat_kvb = 100;
        assert_eq!(
            mp.mempool_min_fee_sat_kvb(),
            100,
            "one more standard tx exactly filling must let the floor decay"
        );

        mp.max_weight = policy::MAX_STANDARD_TX_WEIGHT.saturating_mul(64);
        // 4001 legacy CHECKSIG × witness scale 4 = 16004, over Core's 16000
        // standard cap. The tx fits the mempool's block-template sigop budget.
        let sigops = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac; 4_001]),
            }],
        };
        mp.accept_tx(&sigops, &utxos, TIP_OK)
            .expect("16004 sigop cost fits a block");
        assert_eq!(
            mp.graph
                .get(&sigops.compute_txid())
                .map(|entry| entry.sigop_cost),
            Some(16_004)
        );

        mp.set_cluster_limits(Some(50), Some(1));
        let mut wide = spend_tx(op, 9_000_000);
        wide.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 4_000]);
        let err = mp.accept_tx(&wide, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::ClusterTooLarge { .. }), "{err}");

        mp.set_cluster_limits(Some(2), None);
        let tx1 = spend_tx(op, 9_000_000);
        mp.accept_tx(&tx1, &utxos, TIP_OK).unwrap();
        let tx2 = spend_tx(
            OutPoint {
                txid: tx1.compute_txid(),
                vout: 0,
            },
            8_000_000,
        );
        mp.accept_tx(&tx2, &utxos, TIP_OK).unwrap();
        let tx3 = spend_tx(
            OutPoint {
                txid: tx2.compute_txid(),
                vout: 0,
            },
            7_000_000,
        );
        let err = mp.accept_tx(&tx3, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::ClusterTooLarge { count: 3, .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn spend_tx(op: OutPoint, out_value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    #[test]
    fn prepare_admit_output_sum_overflow_is_policy_not_panic() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let half = (u64::MAX / 2) + 2;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(half),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(half),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            ],
        };
        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp
            .prepare_admit(&tx, &utxos, TIP_OK, 0, false, None)
            .expect_err("overflowing output sum");
        assert!(
            matches!(err, AcceptError::Policy("bad-txns-txouttotal-toolarge")),
            "got {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_admit_rejects_negative_fee() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 100_001);
        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp
            .prepare_admit(&tx, &utxos, TIP_OK, 0, false, None)
            .expect_err("outputs exceed inputs");
        assert!(matches!(err, AcceptError::Policy("negative fee")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Consensus script check must reject spends of real templates with empty witness.
    /// (Regression: accept used to skip verify and only apply Libre policy.)
    #[test]
    fn reject_invalid_p2wpkh_script() {
        use bitcoin::WPubkeyHash;

        let dir = tmp_dir();
        // Standard P2WPKH spk — not anyone-can-spend; empty witness fails.
        let wpkh = WPubkeyHash::from_byte_array([0x11; 20]);
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let op = OutPoint {
            txid: Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };
        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout));
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 99_000); // empty scriptSig + empty witness
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::Script(_)),
            "expected Script reject, got {err}"
        );
        assert_eq!(mp.live_count(), 0);
        // Sanity: ACS still accepted (Libre + consensus anyone-can-spend).
        let (op2, _, utxos2) = chain_utxo(50_000);
        let ok = spend_tx(op2, 49_000);
        mp.accept_tx(&ok, &utxos2, TIP_OK).expect("ACS still ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `btc:testnet4-blake2b` 150,336: a taproot spend signed
    /// `SIGHASH_ALL | SIGHASH_UNIFIED`. Legacy policy refuses it; the fork's
    /// policy takes it, so it can relay and reach a template.
    #[test]
    fn opted_in_signature_relays_only_under_the_fork_policy() {
        let dir = tmp_dir();
        let raw = rbitcoin_primitives::hex_decode("0200000000010139382bdedc269f5619b355c3a1a35fd0eaf5e2cdbb519d2a464315847c30743e0100000000feffffff02fbed00000000000022512042cbbc48095e40a27a7435c5f00de131097d8136ad297e7a09daa51da0805cef60770200000000002251209ef54bd84baced5d1fc48174699893f7576bcdd68872ae75abe906111e3ae1d50141c33ca18f7e478ca7270cd32c2456174bbde31d30f1b13e5376d7f27b1907a0188e4e990ab190dec6f763651ee1f297b2708860ba409b778d477f0addbb7eea74213f4b0200").unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
        let op = tx.input[0].previous_output;
        let txout = TxOut {
            value: Amount::from_sat(227_565),
            script_pubkey: ScriptBuf::from_bytes(
                rbitcoin_primitives::hex_decode(
                    "5120c54bc3c5a67e1cf0096dc52fbe54bbc24b1858bb83da43e0c539953d6d355675",
                )
                .unwrap(),
            ),
        };
        let mut map = HashMap::new();
        map.insert(op, coin(txout));
        let utxos = MapUtxoProvider { map };
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(&err, AcceptError::Script(m) if m.contains("sighash type")),
            "legacy policy reads 0x21 as an unknown taproot hash type: {err}"
        );
        assert_eq!(mp.live_count(), 0);
        mp.set_fork_policy(ForkScriptPolicy {
            unified_sighash: true,
            reduced_data: true,
        });
        mp.accept_tx(&tx, &utxos, TIP_OK)
            .expect("accepted under the fork's policy");
        assert_eq!(mp.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accept_tx_nonstandard_version_is_ok() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 50_000);
        tx.version = Version::non_standard(0xffff_ffffu32 as i32);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK)
            .expect("Libre P2P admits nVersion outside 1/2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reject_low_feerate() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        // fee 1 sat — below 0.1 sat/vB for any real tx weight
        let tx = spend_tx(op, 99_999);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::Policy("min relay fee")));
        assert_eq!(mp.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dust_and_op_true_allowed() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        // 1-sat output is dust under Core; Libre allows it.
        let tx = spend_tx(op, 1);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).expect("dust ok");
        let _ = std::fs::remove_dir_all(&dir);

        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 0);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(
            matches!(err, AcceptError::Policy("dust")),
            "0-value spendable must be dust, got {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 0);
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK)
            .expect("0-value OP_RETURN ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `n` bare `OP_CHECKMULTISIG` outputs: legacy cost `n × 20 × 4`.
    fn multisig_outputs_tx(op: OutPoint, n: usize) -> Transaction {
        let mut tx = spend_tx(op, 1);
        tx.output = vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
            };
            n
        ];
        tx
    }

    /// Chain coins at P2SH and P2WSH of `0 <pk> <pk> 2 CHECKMULTISIG` (2 accurate
    /// sigops, zero-sig so it verifies) plus a spend of each. Legacy ×4 is 0 for
    /// both; full cost is 8 (P2SH ×4) and 2 (witness ×1).
    fn p2sh_p2wsh_multisig_spends() -> (MapUtxoProvider, Transaction, Transaction) {
        use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2};
        use bitcoin::opcodes::OP_0;
        let pk = [0x02u8; 33];
        let redeem = bitcoin::script::Builder::new()
            .push_opcode(OP_0)
            .push_slice(pk)
            .push_slice(pk)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let p2sh_op = OutPoint {
            txid: Txid::from_byte_array([0xa1; 32]),
            vout: 0,
        };
        let p2wsh_op = OutPoint {
            txid: Txid::from_byte_array([0xa2; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        for (op, spk) in [
            (p2sh_op, ScriptBuf::new_p2sh(&redeem.script_hash())),
            (p2wsh_op, ScriptBuf::new_p2wsh(&redeem.wscript_hash())),
        ] {
            map.insert(
                op,
                coin(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: spk,
                }),
            );
        }
        let mut p2sh = spend_tx(p2sh_op, 90_000);
        p2sh.input[0].script_sig = bitcoin::script::Builder::new()
            .push_opcode(OP_0)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap())
            .into_script();
        let mut p2wsh = spend_tx(p2wsh_op, 90_000);
        p2wsh.input[0].witness = Witness::from_slice(&[&[][..], redeem.as_bytes()]);
        (MapUtxoProvider { map }, p2sh, p2wsh)
    }

    fn live_sigops(mp: &ActiveMempool, tx: &Transaction) -> u64 {
        mp.graph.get(&tx.compute_txid()).unwrap().sigop_cost
    }

    #[test]
    fn accept_tx_records_full_sigop_cost_for_p2sh_and_p2wsh() {
        let dir = tmp_dir();
        let (utxos, p2sh, p2wsh) = p2sh_p2wsh_multisig_spends();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&p2sh, &utxos, TIP_OK).expect("p2sh");
        mp.accept_tx(&p2wsh, &utxos, TIP_OK).expect("p2wsh");
        assert_eq!(live_sigops(&mp, &p2sh), 8);
        assert_eq!(live_sigops(&mp, &p2wsh), 2);
    }

    #[test]
    fn package_and_reorg_readmit_record_sigop_cost() {
        let dir = tmp_dir();
        let (utxos, parent, _) = p2sh_p2wsh_multisig_spends();
        let pid = parent.compute_txid();
        let mut child = spend_tx(OutPoint { txid: pid, vout: 0 }, 80_000);
        child.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
        });
        let pkg = [parent.clone(), child.clone()];
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_package(&pkg, &utxos, TIP_OK).expect("package");
        assert_eq!(live_sigops(&mp, &parent), 8);
        assert_eq!(live_sigops(&mp, &child), 80);

        mp.remove_for_block(&[pid, child.compute_txid()]).unwrap();
        assert_eq!(mp.live_count(), 0);
        let readmitted: Vec<Txid> = mp
            .reorg_disconnect_reaccept(&pkg, &utxos, TIP_OK)
            .into_iter()
            .map(|r| r.expect("reorg re-admit").txid)
            .collect();
        assert_eq!(readmitted, [pid, child.compute_txid()]);
        assert_eq!(live_sigops(&mp, &parent), 8);
        assert_eq!(live_sigops(&mp, &child), 80);
    }

    /// Schema-2 pool: costs unknown after migrate; the open-time pass recomputes
    /// from live parents + chain coins, evicts unresolvable / over-budget
    /// entries, and writes costs back so the next open needs no pass.
    #[test]
    fn schema2_pool_recomputes_sigops_after_open() {
        let dir = tmp_dir();
        let (mut utxos, p2sh, p2wsh) = p2sh_p2wsh_multisig_spends();
        let mut child = spend_tx(
            OutPoint {
                txid: p2sh.compute_txid(),
                vout: 0,
            },
            80_000,
        );
        child.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
        });
        let (gone_op, _, extra) = chain_utxo(100_000);
        utxos.map.extend(extra.map);
        let gone = spend_tx(gone_op, 90_000);
        let probe_op = OutPoint {
            txid: Txid::from_byte_array([0xa3; 32]),
            vout: 0,
        };
        utxos.map.insert(probe_op, utxos.map[&gone_op].clone());
        let probe = multisig_outputs_tx(probe_op, 1001);
        {
            let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
            for tx in [&p2sh, &p2wsh, &child, &gone] {
                mp.accept_tx(tx, &utxos, TIP_OK).unwrap();
            }
            // Admitted by a pre-sigop-check build.
            let (pid, pw) = (probe.compute_txid(), probe.compute_wtxid());
            mp.store
                .append_live_tx(&probe, &pid, &pw, 1_000, probe.weight().to_wu(), 0, &[])
                .unwrap();
            mp.flush().unwrap();
        }
        crate::store::tests::downgrade_to_schema2(dir.as_ref());
        utxos.map.remove(&gone_op);

        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.live_count(), 5);
        assert!(mp.graph.iter().all(|(_, e)| e.sigop_cost == u64::MAX));
        mp.recompute_missing_sigops(&utxos);
        assert_eq!(mp.live_count(), 3);
        assert!(!mp.graph.contains(&gone.compute_txid()), "prevout gone");
        assert!(!mp.graph.contains(&probe.compute_txid()), "over budget");
        assert_eq!(live_sigops(&mp, &p2sh), 8);
        assert_eq!(live_sigops(&mp, &p2wsh), 2);
        assert_eq!(live_sigops(&mp, &child), 80);
        drop(mp);

        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        assert_eq!(mp.live_count(), 3);
        assert_eq!(live_sigops(&mp, &p2sh), 8, "written back");
        assert_eq!(live_sigops(&mp, &child), 80);
    }

    #[test]
    fn annex_reject() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut tx = spend_tx(op, 90_000);
        tx.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let err = mp.accept_tx(&tx, &utxos, TIP_OK).unwrap_err();
        assert!(matches!(err, AcceptError::Policy("libre annex")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evaluate_after_script_rbf_leaves_conflict() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let low = spend_tx(op, 99_000);
        let high = spend_tx(op, 50_000);
        let low_id = low.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&low, &utxos, TIP_OK).unwrap();
        let prep = mp
            .prepare_admit(&high, &utxos, TIP_OK, 0, true, None)
            .unwrap();
        let r = mp.evaluate_after_script(&high, prep).expect("preview");
        assert!(r.replaced.contains(&low_id));
        assert!(mp.graph.contains(&low_id));
        assert!(!mp.graph.contains(&high.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// testmempoolaccept preview enforces cluster count and raw-weight vsize
    /// limits itself (only the accept path re-checks after insert): exactly at
    /// each limit previews Ok, one past is ClusterTooLarge with exact totals.
    #[test]
    fn evaluate_after_script_enforces_cluster_limits() {
        let (op, _, utxos) = chain_utxo(100_000);
        let parent = spend_tx(op, 99_000);
        let pw = parent.weight().to_wu();
        let pad_child = |total_w: u64| {
            let mut c = spend_tx(
                OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0,
                },
                98_000,
            );
            while pw + c.weight().to_wu() < total_w {
                c.output[0]
                    .script_pubkey
                    .push_opcode(bitcoin::opcodes::OP_TRUE);
            }
            assert_eq!(pw + c.weight().to_wu(), total_w);
            c
        };
        let preview = |count: u32, child: &Transaction| {
            let dir = tmp_dir();
            let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
            mp.set_cluster_limits(Some(count), Some(1)); // 1 kvB = 4_000 WU
            mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
            let prep = mp
                .prepare_admit(child, &utxos, TIP_OK, 0, true, None)
                .unwrap();
            mp.evaluate_after_script(child, prep).map(|r| r.txid)
        };
        let at = pad_child(4_000);
        assert_eq!(preview(2, &at).unwrap(), at.compute_txid());
        let over = pad_child(4_004);
        assert!(matches!(
            preview(2, &over),
            Err(AcceptError::ClusterTooLarge {
                count: 2,
                weight: 4_004
            })
        ));
        assert!(matches!(
            preview(1, &at),
            Err(AcceptError::ClusterTooLarge {
                count: 2,
                weight: 4_000
            })
        ));
    }

    #[test]
    fn commit_after_script_does_not_take_utxo_provider() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 99_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let prep = mp
            .prepare_admit(&tx, &utxos, TIP_OK, 0, true, None)
            .unwrap();
        mp.commit_after_script(&tx, prep)
            .expect("commit uses prep.chain_coins");
        assert!(mp.graph.contains(&tx.compute_txid()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_admit_stashes_txid() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 99_000);
        let mp = ActiveMempool::open_or_create(&dir).unwrap();
        let prep = mp
            .prepare_admit(&tx, &utxos, TIP_OK, 0, true, None)
            .unwrap();
        assert_eq!(prep.txid, tx.compute_txid());
        assert_eq!(prep.wtxid, tx.compute_wtxid());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_after_script_parent_body_missing_is_durable() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let parent = spend_tx(op, 90_000);
        let pid = parent.compute_txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 80_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&parent, &utxos, TIP_OK).unwrap();
        let prep = mp
            .prepare_admit(&child, &utxos, TIP_OK, 0, true, None)
            .unwrap();
        mp.bodies.remove(&pid);
        let err = mp.commit_after_script(&child, prep).unwrap_err();
        assert!(
            matches!(err, AcceptError::Durable(ref s) if s == "parent body missing"),
            "got {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rbf_pays_helper() {
        assert!(rbf_pays_for_replacement(10_000, 4000, 1000, 4000));
        assert!(!rbf_pays_for_replacement(1000, 4000, 10_000, 4000));
        assert!(!rbf_pays_for_replacement(1000, 4000, 1000, 4000));
    }

    #[test]
    fn pure_rbfr_1_25x_ratio() {
        // Same weight: new fee ≥ 1.25× old fee.
        // old fee 1000 @ 4000 WU → need new ≥ 1250 same weight.
        assert!(pure_rbfr_pays(1_250, 4000, 1_000, 4000));
        assert!(!pure_rbfr_pays(1_249, 4000, 1_000, 4000));
        // Higher rate, lower absolute fee vs a fat conflict set still passes pure RBFR
        // (BIP125 would fail): direct 1000@4000, conflict set pretends 50k@40k.
        assert!(!rbf_pays_for_replacement(2_000, 4000, 50_000, 40_000));
        assert!(pure_rbfr_pays(2_000, 4000, 1_000, 4000));
        assert!(rbf_allows_replacement(
            2_000, 4000, 50_000, 40_000, 1_000, 4000
        ));
    }

    #[test]
    fn compact_reclaims_dead_and_preserves_live() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        let body_before = mp.store.body_logical_len().unwrap();
        // Confirm-remove leaves a DEAD slot (body still holds the old payload).
        mp.remove_for_block(&[txid]).unwrap();
        // Re-accept so we have live + dead history in the body file.
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        let (_f, live, dead) = mp.store.slot_stats();
        assert_eq!(live, 1);
        // remove_for_block may already have auto-compacted; either way compact is safe.
        let _ = dead;
        let (live_after, body_after) = mp.compact().unwrap();
        assert_eq!(live_after, 1);
        assert!(body_after <= body_before + 256);
        assert_eq!(body_after, mp.store.body_logical_len().unwrap());
        assert_eq!(mp.live_count(), 1);
        mp.flush().unwrap();
        let mp2 = ActiveMempool::open_or_create(&dir).unwrap();
        assert_eq!(mp2.live_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `mempool_cluster.py` cleanup mines the mempool empty and `maybe_compact`
    /// rebuilds the graph. Overlay limits must survive that rebuild.
    #[test]
    fn compact_preserves_cluster_size_overlay() {
        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let tx = spend_tx(op, 90_000);
        let txid = tx.compute_txid();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        mp.set_cluster_limits(None, Some(10));
        assert_eq!(mp.graph.cluster_vsize_limit(), 10_000);
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        mp.remove_for_block(&[txid]).unwrap();
        let _ = mp.maybe_compact().unwrap();
        assert_eq!(
            mp.graph.cluster_vsize_limit(),
            10_000,
            "compact must keep -limitclustersize overlay"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::cognitive_complexity)] // one fixture, many reject arms
    #[test]
    fn accept_error_display_and_reject_paths() {
        use std::error::Error;
        let errs = [
            AcceptError::Policy("x"),
            AcceptError::MissingPrevout(OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            }),
            AcceptError::Orphaned {
                txid: Txid::from_byte_array([4; 32]),
                missing: BTreeSet::new(),
                fresh: true,
            },
            AcceptError::Duplicate(Txid::from_byte_array([2; 32])),
            AcceptError::ClusterTooLarge {
                count: 3,
                weight: 9,
            },
            AcceptError::PackageTooLarge {
                count: 2,
                weight: 8,
            },
            AcceptError::PackageEmpty,
            AcceptError::PackageNotTopo,
            AcceptError::RbfInsufficient,
            AcceptError::Coinbase,
            AcceptError::NotFound(Txid::from_byte_array([3; 32])),
            AcceptError::Durable("d".into()),
            AcceptError::Script("s".into()),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
            let _ = e as &dyn Error;
        }
        // From MempoolError.
        let from_io: AcceptError = MempoolError::BadMagic.into();
        assert!(from_io.to_string().contains("durable"));
        let from_full: AcceptError = MempoolError::Full.into();
        assert!(matches!(from_full, AcceptError::Policy("mempool full")));

        let dir = tmp_dir();
        let (op, _, utxos) = chain_utxo(100_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();

        // Coinbase reject.
        let cb = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(matches!(
            mp.accept_tx(&cb, &utxos, TIP_OK),
            Err(AcceptError::Coinbase)
        ));

        // Package empty / too large.
        assert!(matches!(
            mp.accept_package(&[], &utxos, TIP_OK),
            Err(AcceptError::PackageEmpty)
        ));
        // Count over MAX_PACKAGE_COUNT (25).
        let many: Vec<Transaction> = (0..MAX_PACKAGE_COUNT + 1)
            .map(|i| {
                spend_tx(
                    OutPoint {
                        txid: Txid::from_byte_array({
                            let mut b = [0u8; 32];
                            b[0] = i as u8;
                            b
                        }),
                        vout: 0,
                    },
                    1,
                )
            })
            .collect();
        assert!(matches!(
            mp.accept_package(&many, &utxos, TIP_OK),
            Err(AcceptError::PackageTooLarge { .. })
        ));

        let tx = spend_tx(op, 99_000);
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        // Duplicate.
        assert!(matches!(
            mp.accept_tx(&tx, &utxos, TIP_OK),
            Err(AcceptError::Duplicate(_))
        ));

        // Missing prevout → parked in orphanage (soft accept).
        let (_op2, _, empty) = chain_utxo(50_000);
        let missing = spend_tx(
            OutPoint {
                txid: Txid::from_byte_array([0xcd; 32]),
                vout: 0,
            },
            1,
        );
        let missing_id = missing.compute_txid();
        assert!(matches!(
            mp.accept_tx(&missing, &empty, TIP_OK),
            Err(AcceptError::Orphaned { .. })
        ));
        assert!(mp.orphanage.contains(&missing_id));
        assert_eq!(mp.orphan_count(), 1);

        // maybe_compact with only live → None.
        assert!(mp.maybe_compact().unwrap().is_none());

        // Package coinbase / not topo / oversized count.
        assert!(matches!(
            mp.accept_package(&[cb], &utxos, TIP_OK),
            Err(AcceptError::Coinbase)
        ));
        let a = spend_tx(op, 98_000);
        let b = spend_tx(
            OutPoint {
                txid: a.compute_txid(),
                vout: 0,
            },
            97_000,
        );
        // Child before parent → not topo.
        assert!(matches!(
            mp.accept_package(&[b.clone(), a.clone()], &utxos, TIP_OK),
            Err(AcceptError::PackageNotTopo)
        ));
        // Duplicate in package.
        assert!(matches!(
            mp.accept_package(&[a.clone(), a.clone()], &utxos, TIP_OK),
            Err(AcceptError::Duplicate(_))
        ));

        // remove unknown.
        assert!(matches!(
            mp.remove_txid(&Txid::from_byte_array([0xee; 32])),
            Err(AcceptError::NotFound(_))
        ));

        // Negative fee.
        let fat = spend_tx(op, 200_000);
        assert!(matches!(
            mp.accept_tx(&fat, &utxos, TIP_OK),
            Err(AcceptError::Policy(_))
        ));

        // rbf_pays_for_replacement pure unit.
        assert!(!rbf_pays_for_replacement(100, 400, 100, 400));
        assert!(!rbf_pays_for_replacement(100, 400, 200, 400));
        // Higher fee and rate with incremental cover.
        assert!(rbf_pays_for_replacement(50_000, 400, 1_000, 400));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn witness_unexpected_script_is_not_txid_invalid() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let stripped = AcceptError::Script(
            "script verification failed: p2tr empty witness txid=00 vin=0".into(),
        );
        assert!(
            ActiveMempool::accept_failure_record(&tx, &stripped).is_none(),
            "stripped-witness fail must not poison txid"
        );
        let bad_sig = AcceptError::Script("script verification failed: SIG_DER".into());
        assert!(
            matches!(
                ActiveMempool::accept_failure_record(&tx, &bad_sig),
                Some(AcceptFailureRecord::Invalid(_))
            ),
            "non-witness script fail still poisons txid"
        );
    }

    #[test]
    fn remove_txid_notes_extra_compact() {
        let dir = tmp_dir();
        let (op, txout, utxos) = chain_utxo(100_000);
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let tx = spend_tx(op, txout.value.to_sat() - 1_000);
        let txid = tx.compute_txid();
        mp.accept_tx(&tx, &utxos, TIP_OK).unwrap();
        mp.remove_txid(&txid).unwrap();
        assert!(
            mp.extra_compact_txs().any(|t| t.compute_txid() == txid),
            "confirm/evict strip must keep the body for compact fill"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remember_extra_compact_skips_coinbase() {
        let dir = tmp_dir();
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        let cb = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        assert!(cb.is_coinbase());
        mp.remember_extra_compact(&cb);
        assert_eq!(
            mp.extra_compact_txs().count(),
            0,
            "coinbase prefill must not consume extra_compact"
        );
        let spend = spend_tx(
            OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            1_000,
        );
        mp.remember_extra_compact(&spend);
        assert_eq!(mp.extra_compact_txs().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Slot table growth under accept: legacy tiny sidecar must not fail as Durable corrupt.
    #[test]
    fn accept_grows_legacy_tiny_slot_table() {
        use std::fs;
        let dir = tmp_dir();
        fs::create_dir_all(&dir).unwrap();
        // 4-slot meta/slots/body (same layout as store unit test).
        {
            let mut meta = [0u8; 64];
            meta[0..4].copy_from_slice(b"rBMP");
            meta[4..6].copy_from_slice(&2u16.to_le_bytes());
            meta[16..20].copy_from_slice(&4u32.to_le_bytes());
            fs::write(dir.join("meta"), meta).unwrap();
            let mut slots = vec![0u8; 16 + 4 * 48];
            slots[0..4].copy_from_slice(b"rBMP");
            slots[4..6].copy_from_slice(&2u16.to_le_bytes());
            slots[8..12].copy_from_slice(&4u32.to_le_bytes());
            fs::write(dir.join("slots"), &slots).unwrap();
            let mut body = vec![0u8; 16];
            body[0..4].copy_from_slice(b"rBMP");
            body[4..6].copy_from_slice(&2u16.to_le_bytes());
            body[8..16].copy_from_slice(&16u64.to_le_bytes());
            fs::write(dir.join("tx.body"), &body).unwrap();
        }
        // Large weight budget so eviction is not the free-slot path.
        let mut mp = ActiveMempool::open_or_create_with_limit(&dir, 300_000_000).unwrap();
        assert_eq!(mp.store.meta().slot_cap, 4);
        // Four independent chain utxos → four live slots.
        for i in 0..4u8 {
            let op = OutPoint {
                txid: Txid::from_byte_array({
                    let mut b = [0xab; 32];
                    b[0] = i;
                    b
                }),
                vout: 0,
            };
            let mut map = HashMap::new();
            map.insert(
                op,
                coin(TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }),
            );
            let utxos = MapUtxoProvider { map };
            let tx = spend_tx(op, 99_000);
            mp.accept_tx(&tx, &utxos, TIP_OK)
                .unwrap_or_else(|e| panic!("accept {i}: {e}"));
        }
        assert_eq!(mp.live_count(), 4);
        // Fifth must grow slots, not Durable(corrupt: slot table full).
        let op = OutPoint {
            txid: Txid::from_byte_array([0xcd; 32]),
            vout: 0,
        };
        let mut map = HashMap::new();
        map.insert(
            op,
            coin(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }),
        );
        let utxos = MapUtxoProvider { map };
        let tx = spend_tx(op, 99_000);
        let r = mp.accept_tx(&tx, &utxos, TIP_OK);
        assert!(
            r.is_ok(),
            "expected grow (weight budget has headroom), got {:?}",
            r.err().map(|e| e.to_string())
        );
        assert!(
            mp.store.meta().slot_cap > 4,
            "ensure_free_slot must grow before it evicts"
        );
        assert_eq!(mp.live_count(), 5);
        let _ = fs::remove_dir_all(&dir);
    }

    /// P2WSH spend whose witness script holds `n` unexecuted sigops, output an
    /// OP_RETURN push of `pad` bytes (Core `mempool_sigoplimit.py` fixture).
    fn witness_sigops_spend(n: usize, pad: usize) -> (MapUtxoProvider, Transaction) {
        use bitcoin::opcodes::all::{
            OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHNUM_1, OP_RETURN,
        };
        use bitcoin::opcodes::OP_FALSE;
        let mut b = bitcoin::script::Builder::new()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        for _ in 0..n / 20 {
            b = b.push_opcode(OP_CHECKMULTISIG);
        }
        for _ in 0..n % 20 {
            b = b.push_opcode(OP_CHECKSIG);
        }
        let ws = b
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_PUSHNUM_1)
            .into_script();
        let op = OutPoint {
            txid: Txid::from_byte_array([0xa3; 32]),
            vout: 0,
        };
        let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
        let map = HashMap::from([(
            op,
            coin(TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: spk,
            }),
        )]);
        let mut tx = spend_tx(op, 0);
        tx.input[0].witness = Witness::from_slice(&[ws.as_bytes()]);
        let data = bitcoin::script::PushBytesBuf::try_from(vec![b'X'; pad]).unwrap();
        tx.output[0].script_pubkey = bitcoin::script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(data)
            .into_script();
        (MapUtxoProvider { map }, tx)
    }

    fn vsize_of(tx: &Transaction) -> u64 {
        policy::get_virtual_size(tx.weight().to_wu())
    }

    /// Zero-fee parent + heavy-sigop child: 200 sat pays the raw package
    /// vsize, not the sigop-adjusted one.
    fn cpfp_heavy_child(op: OutPoint) -> (Transaction, Transaction) {
        let parent = spend_tx(op, 100_000);
        let mut child = multisig_outputs_tx(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            10,
        );
        child.output[0].value = Amount::from_sat(100_000 - 200 - 9);
        (parent, child)
    }

    include!("accept_life_journey.rs");
}
