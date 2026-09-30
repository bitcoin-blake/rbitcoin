//! Esplora HTTP listener (axum + tower limits).

use crate::handlers;
use crate::tx_json::{build_tx_json, build_tx_json_from_tx, tx_status_json_in};
use axum::extract::{FromRequestParts, Path, Query as AxumQuery, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use bitcoin::consensus::Encodable;
use bitcoin::Network;
use rbitcoin_electrum::ServeLimits;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Height;
use rbitcoin_query::{ChainView, ChainViewKind, Query, ShJoinSlot};
use rbitcoin_store::StoreError;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Tip-follow 5s DEBUG `tip: perf`: REST request count this window.
static METER_REQ: AtomicU64 = AtomicU64::new(0);
/// Sum of REST handler walls (µs).
static METER_US: AtomicU64 = AtomicU64::new(0);
/// Max single REST request wall (µs).
static METER_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Sample-and-reset Esplora REST request meters: `(count, sum_us, max_us)`.
pub fn sample_reset_perf() -> (u64, u64, u64) {
    (
        METER_REQ.swap(0, Ordering::Relaxed),
        METER_US.swap(0, Ordering::Relaxed),
        METER_MAX_US.swap(0, Ordering::Relaxed),
    )
}

async fn meter_rest(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let t0 = Instant::now();
    let resp = next.run(req).await;
    let elapsed = t0.elapsed();
    let us = elapsed.as_micros() as u64;
    METER_REQ.fetch_add(1, Ordering::Relaxed);
    METER_US.fetch_add(us, Ordering::Relaxed);
    let mut cur = METER_MAX_US.load(Ordering::Relaxed);
    while us > cur {
        match METER_MAX_US.compare_exchange_weak(cur, us, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(c) => cur = c,
        }
    }
    let status = resp.status();
    let err = if status.is_success() {
        None
    } else {
        Some(status.as_str().to_string())
    };
    rbitcoin_log::api_call(
        "esplora",
        "-",
        &format!("{method} {path}"),
        "",
        elapsed.as_millis() as u64,
        err.as_deref(),
    );
    resp
}

pub(crate) const HDR_CHAIN_TIP: &str = "x-bitcoin-chain-tip";
pub(crate) const HDR_CHAIN_TIP_HEIGHT: &str = "x-bitcoin-chain-tip-height";

fn stamp_chain_view_headers(resp: &mut Response, view: &ChainView) {
    let hash = block_hash_hex(&view.hash);
    let height = view.height.0.to_string();
    if let Ok(v) = HeaderValue::from_str(&hash) {
        resp.headers_mut().insert(HDR_CHAIN_TIP, v);
    }
    if let Ok(v) = HeaderValue::from_str(&height) {
        resp.headers_mut().insert(HDR_CHAIN_TIP_HEIGHT, v);
    }
    resp.headers_mut().insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("X-Bitcoin-Chain-Tip, X-Bitcoin-Chain-Tip-Height"),
    );
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct AsOfQuery {
    pub asof: Option<String>,
}

/// Parsed `?asof=` (None if omitted). Invalid hex is 404.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AsOf(pub Option<[u8; 32]>);

impl FromRequestParts<AppState> for AsOf {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AxumQuery(q) = AxumQuery::<AsOfQuery>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found())?;
        parse_asof_param(&q).map(AsOf).map_err(|_| not_found())
    }
}

pub(crate) fn parse_asof_param(q: &AsOfQuery) -> Result<Option<[u8; 32]>, ()> {
    match q.asof.as_deref() {
        None => Ok(None),
        Some(s) => parse_hash32(s).map(Some),
    }
}

pub(crate) fn attach_chain_view(mut resp: Response, view: ChainView) -> Response {
    resp.extensions_mut().insert(view);
    resp
}

pub(crate) fn maybe_attach_view(resp: Response, view: Option<ChainView>) -> Response {
    match view {
        Some(v) => attach_chain_view(resp, v),
        None => resp,
    }
}

#[allow(clippy::result_large_err)] // public error enum
pub(crate) fn pin_or_reject(
    query: &Query,
    kind: ChainViewKind,
    asof: Option<[u8; 32]>,
) -> Result<Option<ChainView>, Response> {
    match query.pin_view(kind, asof.as_ref()) {
        Ok(None) if asof.is_some() => Err(not_found()),
        Ok(v) => Ok(v),
        Err(e) => Err(store_err(e)),
    }
}

fn asof_hash_from_uri(uri: &axum::http::Uri) -> Result<Option<[u8; 32]>, ()> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("asof=") {
            if v.is_empty() {
                return Err(());
            }
            return parse_hash32(v).map(Some);
        }
    }
    Ok(None)
}

fn path_uses_sh_view(path: &str) -> bool {
    path.starts_with("/address/")
        || path.starts_with("/scripthash/")
        || path.starts_with("/addresses/")
        || path.starts_with("/scripthashes/")
}

/// COMPAT.md: `?asof=` only on tx status/outspend(s) and address/scripthash
/// `/`, `/utxo`, `/txs`, `/txs/chain` (not `/txs/mempool`).
fn path_accepts_asof(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["tx", _, "status"]
            | ["tx", _, "outspends"]
            | ["tx", _, "outspend", _]
            | ["address", _]
            | ["scripthash", _]
            | ["address", _, "utxo"]
            | ["scripthash", _, "utxo"]
            | ["address", _, "txs"]
            | ["scripthash", _, "txs"]
            | ["address", _, "txs", "chain"]
            | ["scripthash", _, "txs", "chain"]
            | ["address", _, "txs", "chain", _]
            | ["scripthash", _, "txs", "chain", _]
    )
}

fn path_never_pins(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["mempool"]
            | ["mempool", _]
            | ["fee-estimates"]
            | ["tx"]
            | ["txs", "package"]
            | ["address", _, "txs", "mempool"]
            | ["scripthash", _, "txs", "mempool"]
    )
}

fn powered_by_header() -> HeaderValue {
    static V: OnceLock<HeaderValue> = OnceLock::new();
    V.get_or_init(|| {
        let ver = env!("CARGO_PKG_VERSION");
        let mut hex = String::with_capacity(ver.len().saturating_mul(2));
        for b in ver.as_bytes() {
            hex.push_str(&format!("{b:02x}"));
        }
        HeaderValue::from_str(&format!("rbitcoin-esplora/{ver}-{hex}")).expect("ascii powered-by")
    })
    .clone()
}

async fn stamp_powered_by_mw(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("x-powered-by", powered_by_header());
    resp
}

async fn stamp_chain_view_mw(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let asof = match asof_hash_from_uri(req.uri()) {
        Ok(v) => v,
        Err(()) => return not_found(),
    };
    let path = req.uri().path().to_string();
    if path_uses_sh_view(&path) && !st.query.sh_history_available() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            rbitcoin_query::SCRIPTHASH_INDEX_DISABLED,
        )
            .into_response();
    }
    if asof.is_some() && !path_accepts_asof(&path) {
        return not_found();
    }
    let pre_view = if path_never_pins(&path) || asof.is_some() {
        None
    } else if path_uses_sh_view(&path) {
        match st.query.pin_sh_chain_view() {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    } else {
        match st.query.pin_chain_view() {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    };
    let mut resp = next.run(req).await;
    let view = resp.extensions().get::<ChainView>().copied().or(pre_view);
    let Some(view) = view else {
        return resp;
    };
    match view.still_live(&st.query) {
        Ok(true) => {
            stamp_chain_view_headers(&mut resp, &view);
            resp
        }
        Ok(false) if asof.is_some() => not_found(),
        Ok(false) => (StatusCode::SERVICE_UNAVAILABLE, "chain view moved").into_response(),
        Err(e) => store_err(e),
    }
}

/// Opt-in `GET /block-template` builder (node injects GBT; tests inject a stub).
#[derive(Clone)]
pub struct BlockTemplateFn(pub Arc<dyn Fn() -> Result<Value, String> + Send + Sync>);

impl std::fmt::Debug for BlockTemplateFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockTemplateFn")
    }
}

pub(crate) struct GbtCache {
    pub(crate) at: Instant,
    pub(crate) tip: [u8; 32],
    pub(crate) updates: u64,
    pub(crate) body: Value,
}

/// TCP `host:port` or a filesystem unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EsploraListen {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl EsploraListen {
    /// Empty value → `127.0.0.1:<default_port>`. A `host:port` is TCP. A path
    /// (`/…`, `./…`, or `*.sock`) is unix (not Windows).
    pub fn parse(val: &str, default_port: u16) -> Result<Self, String> {
        if val.is_empty() {
            return Ok(Self::Tcp(SocketAddr::from(([127, 0, 0, 1], default_port))));
        }
        if let Ok(addr) = val.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }
        let pathish = val.starts_with('/')
            || val.starts_with('.')
            || val.contains('/')
            || val.ends_with(".sock");
        if !pathish {
            return Err(format!(
                "esplora-listen: expected host:port or unix path, got {val}"
            ));
        }
        #[cfg(unix)]
        {
            Ok(Self::Unix(PathBuf::from(val)))
        }
        #[cfg(not(unix))]
        {
            Err(
                "esplora unix socket needs AF_UNIX; this Windows build has no tokio UnixListener"
                    .into(),
            )
        }
    }
}

/// Esplora HTTP server config (listen + shared DoS floor).
#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub listen: EsploraListen,
    /// Shared with Electrum ([`ServeLimits::for_public_proxy`] defaults).
    pub limits: ServeLimits,
    /// Address encoding network (mainnet/testnet/signet/regtest).
    pub network: Network,
    /// `None` → `GET /block-template` is 404 (default).
    pub block_template: Option<BlockTemplateFn>,
}

impl EsploraConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self::with_network(listen, Network::Bitcoin)
    }

    pub fn with_network(listen: SocketAddr, network: Network) -> Self {
        Self::with_listen(EsploraListen::Tcp(listen), network)
    }

    pub fn with_listen(listen: EsploraListen, network: Network) -> Self {
        Self {
            listen,
            limits: ServeLimits::for_public_proxy(),
            network,
            block_template: None,
        }
    }
}

pub struct EsploraHandle {
    /// Bound TCP address. Unix listen leaves this as `127.0.0.1:0`.
    pub local_addr: SocketAddr,
    pub socket_path: Option<PathBuf>,
    shutdown: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl EsploraHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = self.task.await;
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) query: Arc<Query>,
    pub(crate) network: Network,
    pub(crate) mempool: Option<Arc<MempoolHub>>,
    pub(crate) max_body: usize,
    /// Per-client last-1 GET + last-bulk POST joins (unix or `join_header_trusted`).
    pub(crate) sh_join: Arc<Mutex<JoinCache>>,
    /// Unix listen trusts `X-Rbitcoin-Client` without a TCP peer address.
    pub(crate) join_header_trusted: bool,
    pub(crate) block_template: Option<BlockTemplateFn>,
    pub(crate) gbt_cache: Arc<Mutex<Option<GbtCache>>>,
}

const JOIN_IDLE: Duration = Duration::from_secs(30);
const JOIN_MAX_CLIENTS: usize = 256;
const JOIN_BULK_CAP: usize = 16 * 1024 * 1024;

struct InflightJoin {
    /// `None` = still running. `Some(slot)` = finished (`slot` may be empty).
    done: Mutex<Option<Option<Arc<ShJoinSlot>>>>,
    cv: std::sync::Condvar,
}

impl InflightJoin {
    fn finish(&self, slot: Option<Arc<ShJoinSlot>>) {
        let mut d = self.done.lock().unwrap_or_else(|p| p.into_inner());
        if d.is_none() {
            *d = Some(slot);
            self.cv.notify_all();
        }
    }
}

/// Finishes the inflight slot (and drops the map entry) if the leader unwinds.
struct InflightGuard {
    cache: Arc<Mutex<JoinCache>>,
    id: String,
    sh: [u8; 32],
    inf: Arc<InflightJoin>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inf.finish(None);
        let mut g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = g.clients.get_mut(&self.id) {
            if c.inflight
                .get(&self.sh)
                .is_some_and(|a| Arc::ptr_eq(a, &self.inf))
            {
                c.inflight.remove(&self.sh);
            }
        }
    }
}

struct ClientJoins {
    last_sh: Option<([u8; 32], Arc<ShJoinSlot>)>,
    last_bulk: HashMap<[u8; 32], Arc<ShJoinSlot>>,
    last_req: Instant,
    inflight: HashMap<[u8; 32], Arc<InflightJoin>>,
}

impl Default for ClientJoins {
    fn default() -> Self {
        Self {
            last_sh: None,
            last_bulk: HashMap::new(),
            last_req: Instant::now(),
            inflight: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub(crate) struct JoinCache {
    clients: HashMap<String, ClientJoins>,
}

impl JoinCache {
    #[cfg(test)]
    fn last_sh_key(&self, id: &str) -> Option<[u8; 32]> {
        self.clients
            .get(id)
            .and_then(|c| c.last_sh.as_ref().map(|(k, _)| *k))
    }

    #[cfg(test)]
    fn bulk_len(&self, id: &str) -> usize {
        self.clients.get(id).map(|c| c.last_bulk.len()).unwrap_or(0)
    }
}

fn sweep_clients(map: &mut HashMap<String, ClientJoins>, now: Instant) {
    map.retain(|_, c| now.saturating_duration_since(c.last_req) < JOIN_IDLE);
    while map.len() > JOIN_MAX_CLIENTS {
        let oldest = map
            .iter()
            .min_by_key(|(_, c)| c.last_req)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                map.remove(&k);
            }
            None => break,
        }
    }
}

fn cap_bulk(c: &mut ClientJoins) {
    let last_sh_bytes = c
        .last_sh
        .as_ref()
        .map(|(_, s)| s.packed_bytes())
        .unwrap_or(0);
    let mut bytes: usize =
        last_sh_bytes.saturating_add(c.last_bulk.values().map(|s| s.packed_bytes()).sum());
    while bytes > JOIN_BULK_CAP && !c.last_bulk.is_empty() {
        let victim = c
            .last_bulk
            .iter()
            .max_by_key(|(_, s)| s.packed_bytes())
            .map(|(k, s)| (*k, s.packed_bytes()));
        let Some((k, sz)) = victim else {
            break;
        };
        c.last_bulk.remove(&k);
        bytes = bytes.saturating_sub(sz);
    }
}

fn retain_join_budget(c: &mut ClientJoins) {
    if c.last_sh
        .as_ref()
        .is_some_and(|(_, s)| s.packed_bytes() > JOIN_BULK_CAP)
    {
        c.last_sh = None;
    }
    cap_bulk(c);
}

fn trusted_client_id(unix_or_trusted: bool, header: Option<String>) -> Option<String> {
    if unix_or_trusted {
        header
    } else {
        None
    }
}

#[derive(Clone)]
pub(crate) struct JoinClient(pub Option<String>);

impl FromRequestParts<AppState> for JoinClient {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = if state.join_header_trusted {
            parts
                .headers
                .get("x-rbitcoin-client")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        Ok(JoinClient(trusted_client_id(
            state.join_header_trusted,
            header,
        )))
    }
}

impl AppState {
    pub(crate) fn with_sh_join<R>(
        &self,
        client: Option<&str>,
        sh: &[u8; 32],
        f: impl FnOnce(&mut Option<Arc<ShJoinSlot>>) -> R,
    ) -> R {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            let mut slot = None;
            return f(&mut slot);
        };
        let inflight = {
            let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            sweep_clients(&mut g.clients, Instant::now());
            let c = g.clients.entry(id.to_string()).or_default();
            c.last_req = Instant::now();
            if c.last_sh.as_ref().is_some_and(|(k, _)| k == sh) {
                let mut slot = c.last_sh.as_ref().map(|(_, s)| s.clone());
                drop(g);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        c.last_sh = Some((*sh, s));
                        c.last_req = Instant::now();
                        retain_join_budget(c);
                    }
                }
                return r;
            }
            if let Some(inf) = c.inflight.get(sh).cloned() {
                Err(inf)
            } else {
                let inf = Arc::new(InflightJoin {
                    done: Mutex::new(None),
                    cv: std::sync::Condvar::new(),
                });
                c.inflight.insert(*sh, Arc::clone(&inf));
                Ok(inf)
            }
        };
        let inf = match inflight {
            Err(inf) => {
                let mut d = inf.done.lock().unwrap_or_else(|p| p.into_inner());
                while d.is_none() {
                    d = inf.cv.wait(d).unwrap_or_else(|p| p.into_inner());
                }
                let mut slot = (*d).clone().flatten();
                drop(d);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        c.last_sh = Some((*sh, s));
                        c.last_req = Instant::now();
                        retain_join_budget(c);
                    }
                }
                return r;
            }
            Ok(inf) => inf,
        };
        let mut slot = {
            let g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            g.clients.get(id).and_then(|c| c.last_bulk.get(sh).cloned())
        };
        let _guard = InflightGuard {
            cache: Arc::clone(&self.sh_join),
            id: id.to_string(),
            sh: *sh,
            inf: Arc::clone(&inf),
        };
        let r = f(&mut slot);
        inf.finish(slot.clone());
        {
            let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = g.clients.get_mut(id) {
                c.last_req = Instant::now();
                c.inflight.remove(sh);
                if let Some(s) = slot {
                    c.last_sh = Some((*sh, s));
                }
                retain_join_budget(c);
            }
        }
        r
    }

    pub(crate) fn seed_bulk(
        &self,
        client: Option<&str>,
        bag: &mut HashMap<[u8; 32], Arc<ShJoinSlot>>,
    ) {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            return;
        };
        let g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = g.clients.get(id) {
            for (k, v) in &c.last_bulk {
                bag.entry(*k).or_insert_with(|| v.clone());
            }
        }
    }

    pub(crate) fn promote_bulk(
        &self,
        client: Option<&str>,
        bag: HashMap<[u8; 32], Arc<ShJoinSlot>>,
    ) {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            return;
        };
        let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
        sweep_clients(&mut g.clients, Instant::now());
        let c = g.clients.entry(id.to_string()).or_default();
        c.last_req = Instant::now();
        c.last_bulk = bag;
        cap_bulk(c);
    }
}

/// electrs `/internal/*` bulk REST. Merged only on unix listen.
#[cfg(unix)]
fn internal_routes() -> Router<AppState> {
    Router::new()
        .route("/internal/txs", post(crate::internal::post_internal_txs))
        .route(
            "/internal/mempool/txs/all",
            get(crate::internal::get_internal_mempool_txs_all),
        )
        .route(
            "/internal/mempool/txs",
            get(crate::internal::get_internal_mempool_txs)
                .post(crate::internal::post_internal_mempool_txs),
        )
        .route(
            "/internal/mempool/txs/{last}",
            get(crate::internal::get_internal_mempool_txs_cursor),
        )
        .route(
            "/internal/block/{hash}/txs",
            get(crate::internal::get_internal_block_txs),
        )
        .route(
            "/internal/txs/outspends/by-txid",
            post(crate::internal::post_outspends_by_txid),
        )
        .route(
            "/internal/txs/outspends/by-outpoint",
            post(crate::internal::post_outspends_by_outpoint),
        )
}

#[cfg(unix)]
fn bind_unix_mode(path: &std::path::Path, mode: u32) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Start Esplora **plain HTTP** on `config.listen`.
///
/// TLS is external (reverse proxy). App [`ServeLimits`] always apply
/// (concurrency, body size, request timeout).
///
/// Optional `mempool` enables fee estimates, mempool summary, and `POST /tx`.
pub async fn run_esplora(
    config: EsploraConfig,
    query: Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
) -> Result<EsploraHandle, std::io::Error> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_c = shutdown.clone();

    let max_conn = config.limits.max_connections.max(1);
    let max_body = config.limits.max_request_bytes.max(1);
    let idle = config.limits.idle_timeout;
    // Floor for request timeout: at least 1s so unit tests with short idle still work.
    let timeout = idle.max(Duration::from_secs(1));

    let state = AppState {
        query,
        network: config.network,
        mempool,
        max_body,
        sh_join: Arc::new(Mutex::new(JoinCache::default())),
        join_header_trusted: {
            #[cfg(unix)]
            {
                matches!(config.listen, EsploraListen::Unix(_))
            }
            #[cfg(not(unix))]
            {
                false
            }
        },
        block_template: config.block_template,
        gbt_cache: Arc::new(Mutex::new(None)),
    };

    // axum 0.8 path params use `{name}` (not `:name`).
    let rest = Router::new()
        .route("/block-template", get(handlers::block_template))
        .route("/blocks/tip/height", get(tip_height))
        .route("/blocks/tip/hash", get(tip_hash))
        .route("/blocks", get(handlers::blocks_tip))
        .route("/blocks/{start}", get(handlers::blocks_from_height))
        .route("/block-height/{height}", get(block_height))
        .route("/block/{hash}", get(handlers::block_json))
        .route("/block/{hash}/header", get(block_header))
        .route("/block/{hash}/status", get(handlers::block_status))
        .route("/block/{hash}/raw", get(handlers::block_raw))
        .route("/block/{hash}/txids", get(handlers::block_txids))
        .route("/block/{hash}/txid/{index}", get(handlers::block_txid_at))
        .route("/block/{hash}/txs", get(handlers::block_txs_0))
        .route("/block/{hash}/txs/{start}", get(handlers::block_txs_start))
        .route("/tx/{txid}", get(tx_full))
        .route("/tx/{txid}/hex", get(tx_hex))
        .route("/tx/{txid}/raw", get(handlers::tx_raw))
        .route("/tx/{txid}/status", get(tx_status))
        .route("/tx/{txid}/merkle-proof", get(handlers::tx_merkle_proof))
        .route(
            "/tx/{txid}/merkleblock-proof",
            get(handlers::tx_merkleblock_proof),
        )
        .route("/tx/{txid}/outspend/{vout}", get(handlers::tx_outspend))
        .route("/tx/{txid}/outspends", get(handlers::tx_outspends))
        .route("/tx", post(handlers::post_tx))
        .route("/broadcast", get(handlers::get_broadcast))
        .route("/txs/test", post(handlers::post_txs_test))
        .route("/txs/outspends", get(handlers::get_txs_outspends))
        .route("/txs/package", post(handlers::post_tx_package))
        .route("/addresses/txs", post(handlers::post_addresses_txs))
        .route(
            "/addresses/txs/summary",
            post(handlers::post_addresses_txs_summary),
        )
        .route("/scripthashes/txs", post(handlers::post_scripthashes_txs))
        .route(
            "/scripthashes/txs/summary",
            post(handlers::post_scripthashes_txs_summary),
        )
        .route("/address/{addr}", get(handlers::address_info))
        .route("/address/{addr}/utxo", get(handlers::address_utxo))
        .route("/address/{addr}/txs", get(handlers::address_txs))
        .route(
            "/address/{addr}/txs/summary",
            get(handlers::address_txs_summary),
        )
        .route(
            "/address/{addr}/txs/summary/{last}",
            get(handlers::address_txs_summary_cursor),
        )
        .route(
            "/address/{addr}/txs/mempool",
            get(handlers::address_txs_mempool),
        )
        .route(
            "/address/{addr}/txs/chain",
            get(handlers::address_txs_chain),
        )
        .route(
            "/address/{addr}/txs/chain/{last}",
            get(handlers::address_txs_chain_cursor),
        )
        .route("/scripthash/{hash}", get(handlers::scripthash_info))
        .route("/scripthash/{hash}/utxo", get(handlers::scripthash_utxo))
        .route("/scripthash/{hash}/txs", get(handlers::scripthash_txs))
        .route(
            "/scripthash/{hash}/txs/summary",
            get(handlers::scripthash_txs_summary),
        )
        .route(
            "/scripthash/{hash}/txs/summary/{last}",
            get(handlers::scripthash_txs_summary_cursor),
        )
        .route(
            "/scripthash/{hash}/txs/mempool",
            get(handlers::scripthash_txs_mempool),
        )
        .route(
            "/scripthash/{hash}/txs/chain",
            get(handlers::scripthash_txs_chain),
        )
        .route(
            "/scripthash/{hash}/txs/chain/{last}",
            get(handlers::scripthash_txs_chain_cursor),
        )
        .route("/mempool", get(handlers::mempool_info))
        .route(
            "/mempool/txids/page",
            get(crate::internal::get_mempool_txids_page),
        )
        .route(
            "/mempool/txids/page/{last}",
            get(crate::internal::get_mempool_txids_page_cursor),
        )
        .route("/mempool/txids", get(handlers::mempool_txids))
        .route("/mempool/recent", get(handlers::mempool_recent))
        .route("/fee-estimates", get(handlers::fee_estimates));
    #[cfg(unix)]
    let rest = if matches!(config.listen, EsploraListen::Unix(_)) {
        rest.merge(internal_routes())
    } else {
        rest
    };
    let rest = rest
        .fallback(fallback_404)
        // Outer → inner: concurrency → body → timeout → meter → chain-view stamp.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            stamp_chain_view_mw,
        ))
        .layer(middleware::from_fn(meter_rest))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(ConcurrencyLimitLayer::new(max_conn));

    let app = rest
        .layer(middleware::from_fn(stamp_powered_by_mw))
        .with_state(state);

    match config.listen {
        EsploraListen::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let make = app.into_make_service_with_connect_info::<SocketAddr>();
                let serve = axum::serve(listener, make).with_graceful_shutdown(async move {
                    while !shutdown_c.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
                if let Err(e) = serve.await {
                    rbitcoin_log::warn!("esplora: serve ended: {e}");
                }
            });
            Ok(EsploraHandle {
                local_addr,
                socket_path: None,
                shutdown,
                task,
            })
        }
        #[cfg(unix)]
        EsploraListen::Unix(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let _ = std::fs::remove_file(&path);
            let listener = bind_unix_mode(&path, 0o660)?;
            let task = tokio::spawn(async move {
                let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                    while !shutdown_c.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
                if let Err(e) = serve.await {
                    rbitcoin_log::warn!("esplora: serve ended: {e}");
                }
            });
            Ok(EsploraHandle {
                local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                socket_path: Some(path),
                shutdown,
                task,
            })
        }
    }
}

async fn tip_height(State(st): State<AppState>) -> Response {
    match st.query.tip_height() {
        Some(h) => (StatusCode::OK, format!("{}", h.0)).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "no chain tip").into_response(),
    }
}

async fn tip_hash(State(st): State<AppState>) -> Response {
    let Some(h) = st.query.tip_height() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no chain tip").into_response();
    };
    match st.query.header_at_height(h) {
        Ok(Some((_fk, rec))) => plain_ok(block_hash_hex(&rec.hash)),
        Ok(None) => (StatusCode::SERVICE_UNAVAILABLE, "no tip header").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /block-height/:height` → display-order block hash (plain text).
async fn block_height(State(st): State<AppState>, Path(height): Path<u32>) -> Response {
    match st.query.header_at_height(Height(height)) {
        Ok(Some((_fk, rec))) => plain_ok(block_hash_hex(&rec.hash)),
        Ok(None) => not_found(),
        Err(e) => store_err(e),
    }
}

/// `GET /block/:hash/header` → wire header hex (80 bytes, or 164 for a Knots v2 header).
async fn block_header(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    // Prefer best-chain height path (fills prev correctly for wire header).
    match st.query.height_of_hash(&hash) {
        Ok(Some(h)) => match st.query.wire_header_at_height(h) {
            Ok(hdr) => match encode_header_hex(&hdr) {
                Ok(hex) => plain_ok(hex),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
            },
            Err(e) => store_err(e),
        },
        Ok(None) => not_found(),
        Err(e) => store_err(e),
    }
}

/// `GET /tx/:txid` → full Esplora transaction JSON (incl. asm/type/address).
async fn tx_full(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match build_tx_json(&st.query, fk, st.network) {
                Ok(v) => Json(v).into_response(),
                Err(e) => store_err(e),
            },
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => match build_tx_json_from_tx(
                    &st.query,
                    &tx,
                    st.network,
                    None,
                    st.mempool.as_deref(),
                ) {
                    Ok(v) => Json(v).into_response(),
                    Err(e) => store_err(e),
                },
                None => not_found(),
            },
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/hex` → raw consensus-encoded transaction hex.
async fn tx_hex(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match st.query.tx_wire_bytes(fk) {
                Ok(raw) => plain_ok(rbitcoin_primitives::hex_encode(raw)),
                Err(e) => store_err(e),
            },
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => {
                    let raw = bitcoin::consensus::serialize(&tx);
                    plain_ok(rbitcoin_primitives::hex_encode(raw))
                }
                None => not_found(),
            },
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/status` → Esplora confirmation status JSON.
async fn tx_status(
    State(st): State<AppState>,
    Path(txid_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.tx_fk_by_txid(&txid) {
            Ok(Some(fk)) => {
                let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
                    Ok(v) => v,
                    Err(r) => return r,
                };
                let status = match &view {
                    Some(v) => tx_status_json_in(&st.query, fk, v),
                    None => Ok(json!({ "confirmed": false })),
                };
                match status {
                    Ok(v) => maybe_attach_view(Json(v).into_response(), view),
                    Err(e) => store_err(e),
                }
            }
            Ok(None) => {
                if asof.is_some() {
                    return not_found();
                }
                use bitcoin::hashes::Hash;
                let tid = bitcoin::Txid::from_byte_array(txid);
                if st.mempool.as_ref().is_some_and(|m| m.contains(&tid)) {
                    Json(json!({ "confirmed": false })).into_response()
                } else {
                    not_found()
                }
            }
            Err(e) => store_err(e),
        }
    })
    .await
}

async fn fallback_404() -> Response {
    not_found()
}

pub(crate) fn plain_ok(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

pub(crate) fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

pub(crate) fn store_err(e: rbitcoin_query::QueryError) -> Response {
    match e {
        StoreError::NotFound => not_found(),
        StoreError::Pruned { .. } => (StatusCode::NOT_FOUND, "pruned").into_response(),
        StoreError::Stale(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        StoreError::Rejected(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()).into_response(),
    }
}

/// Esplora / Core display order (internal hash bytes reversed).
pub(crate) fn block_hash_hex(hash: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(hash)
}

/// Parse 32-byte hash/txid hex (display order) → internal byte order.
pub(crate) fn parse_hash32(s: &str) -> Result<[u8; 32], ()> {
    rbitcoin_primitives::parse_display_hash32(s).map_err(|_| ())
}

pub(crate) fn mempool_wire(st: &AppState, txid: &[u8; 32]) -> Option<bitcoin::Transaction> {
    use bitcoin::hashes::Hash;
    let tid = bitcoin::Txid::from_byte_array(*txid);
    st.mempool.as_ref().and_then(|m| m.get_tx(&tid))
}

fn encode_header_hex(hdr: &bitcoin::block::Header) -> Result<String, String> {
    let mut buf = Vec::with_capacity(hdr.size());
    hdr.consensus_encode(&mut buf)
        .map_err(|_| "header encode".to_string())?;
    Ok(rbitcoin_primitives::hex_encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_json::tx_status_json;
    use axum::extract::ConnectInfo;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{Query, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use rbitcoin_query::testutil::FixtureChain;
    fn temp_query(label: &str) -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled(label)
    }

    fn coinbase(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xab;
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
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        (header, ta)
    }

    fn header_value(text: &str, name: &str) -> Option<String> {
        let want = name.to_ascii_lowercase();
        text.split("\r\n\r\n")
            .next()
            .unwrap_or("")
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(&want))
            .map(|(_, v)| v.trim().to_string())
    }

    async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let (status, _hdrs, body) = http_get_raw(addr, path).await;
        (status, body)
    }

    async fn http_get_raw(addr: SocketAddr, path: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        (status, text, body)
    }

    async fn http_post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        (status, body)
    }

    #[test]
    fn esplora_listen_parse_tcp_and_path() {
        assert!(matches!(
            EsploraListen::parse("127.0.0.1:3000", 3000).unwrap(),
            EsploraListen::Tcp(_)
        ));
        assert!(matches!(
            EsploraListen::parse("", 3000).unwrap(),
            EsploraListen::Tcp(a) if a.port() == 3000
        ));
        #[cfg(unix)]
        {
            assert!(matches!(
                EsploraListen::parse("/run/rbitcoin/esplora.sock", 3000).unwrap(),
                EsploraListen::Unix(_)
            ));
            assert!(matches!(
                EsploraListen::parse("./esplora.sock", 3000).unwrap(),
                EsploraListen::Unix(_)
            ));
        }
        assert!(EsploraListen::parse("not-an-addr", 3000).is_err());
    }

    #[test]
    fn join_idle_evicts_after_ttl() {
        let mut map = HashMap::new();
        let now = Instant::now();
        map.insert(
            "stale".into(),
            ClientJoins {
                last_req: now.checked_sub(JOIN_IDLE + Duration::from_secs(1)).unwrap(),
                ..ClientJoins::default()
            },
        );
        map.insert(
            "fresh".into(),
            ClientJoins {
                last_req: now,
                ..ClientJoins::default()
            },
        );
        sweep_clients(&mut map, now);
        assert!(!map.contains_key("stale"));
        assert!(map.contains_key("fresh"));
    }

    fn join_only_state(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>) -> AppState {
        AppState {
            query: q,
            network: Network::Regtest,
            mempool: None,
            max_body: 1 << 20,
            sh_join: cache,
            join_header_trusted: true,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn with_sh_join_empty_slot_unblocks_waiter() {
        let (_dir, q) = temp_query("join-empty-waiter");
        let st = Arc::new(join_only_state(
            Arc::new(q),
            Arc::new(Mutex::new(JoinCache::default())),
        ));
        let sh = [0x11u8; 32];
        let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_l = Arc::clone(&st);
        let leader = std::thread::spawn(move || {
            st_l.with_sh_join(Some("c1"), &sh, |slot| {
                *slot = None;
                let _ = leader_in.send(());
                let _ = release_rx.recv();
            });
        });
        leader_in_rx.recv().expect("leader entered f");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let st_w = Arc::clone(&st);
        let waiter = std::thread::spawn(move || {
            st_w.with_sh_join(Some("c1"), &sh, |slot| {
                let _ = done_tx.send(slot.is_none());
            });
        });
        std::thread::sleep(Duration::from_millis(50));
        let _ = release.send(());
        leader.join().expect("leader");
        let empty = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter unblocked after empty join");
        assert!(empty, "finished empty slot");
        waiter.join().expect("waiter");
    }

    #[test]
    fn with_sh_join_leader_panic_unblocks_waiter() {
        let (_dir, q) = temp_query("join-panic-waiter");
        let st = Arc::new(join_only_state(
            Arc::new(q),
            Arc::new(Mutex::new(JoinCache::default())),
        ));
        let sh = [0x22u8; 32];
        let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_l = Arc::clone(&st);
        let leader = std::thread::spawn(move || {
            st_l.with_sh_join(Some("c1"), &sh, |_slot| {
                let _ = leader_in.send(());
                let _ = release_rx.recv();
                panic!("join leader unwind");
            });
        });
        leader_in_rx.recv().expect("leader entered f");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let st_w = Arc::clone(&st);
        let waiter = std::thread::spawn(move || {
            st_w.with_sh_join(Some("c1"), &sh, |_slot| {
                let _ = done_tx.send(());
            });
        });
        std::thread::sleep(Duration::from_millis(50));
        let _ = release.send(());
        let _ = leader.join();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter unblocked after leader panic");
        waiter.join().expect("waiter");
    }

    #[tokio::test]
    async fn with_sh_join_last1_clone_visible_to_overlapping_get() {
        use rbitcoin_store::script_hash;

        let (_a1, spk1) = regtest_p2wpkh();
        let (dir, q) = temp_query("join-last1-clone");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(Height(1), &h1, &[cb1, two_script_pay(0x11, spk1.clone())])
            .unwrap();
        let q = Arc::new(q);
        let sh1 = script_hash(spk1.as_bytes());
        let h1hex = block_hash_hex(&sh1);
        let cache = Arc::new(Mutex::new(JoinCache::default()));
        let app = app_with_join(Arc::clone(&q), Arc::clone(&cache), true);
        let (st, body) =
            oneshot_http(&app, get_with_client(&format!("/scripthash/{h1hex}"), "c1")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(cache.lock().unwrap().last_sh_key("c1"), Some(sh1));

        let st = Arc::new(join_only_state(Arc::clone(&q), Arc::clone(&cache)));
        let (holder_in, holder_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_a = Arc::clone(&st);
        let holder = std::thread::spawn(move || {
            st_a.with_sh_join(Some("c1"), &sh1, |slot| {
                assert!(slot.is_some(), "holder must see warm last-1");
                let _ = holder_in.send(());
                let _ = release_rx.recv();
            });
        });
        holder_in_rx.recv().expect("holder entered f");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let st_b = Arc::clone(&st);
        let overlap = std::thread::spawn(move || {
            st_b.with_sh_join(Some("c1"), &sh1, |slot| {
                let _ = seen_tx.send(slot.is_some());
            });
        });
        let saw = seen_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("overlap entered f");
        assert!(
            saw,
            "overlapping same-sh GET must clone last-1, not take it"
        );
        let _ = release.send(());
        holder.join().expect("holder");
        overlap.join().expect("overlap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_sh_join_drops_last_sh_over_bulk_cap() {
        let (_dir, q) = temp_query("join-oversize-last-sh");
        let cache = Arc::new(Mutex::new(JoinCache::default()));
        let st = join_only_state(Arc::new(q), Arc::clone(&cache));
        let sh = [0x33u8; 32];
        let slot = rbitcoin_query::testutil::sh_join_slot_over_16mib();
        assert!(
            slot.packed_bytes() > JOIN_BULK_CAP,
            "fixture must exceed 16 MiB packed"
        );
        st.with_sh_join(Some("c1"), &sh, |s| {
            *s = Some(Arc::clone(&slot));
        });
        assert!(
            cache.lock().unwrap().last_sh_key("c1").is_none(),
            "oversize last-1 is used then not retained"
        );
    }

    #[cfg(unix)]
    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_socket_does_not_strip_dir_search() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        extern "C" {
            fn umask(mask: u32) -> u32;
        }
        let old = unsafe { umask(0o022) };
        let stop = Arc::new(AtomicBool::new(false));
        let bare = Arc::new(AtomicBool::new(false));
        let worker = {
            let stop = Arc::clone(&stop);
            let bare = Arc::clone(&bare);
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let path = std::env::temp_dir().join(format!(
                        "rbitcoin-umask-probe-esplora-{}-{}",
                        std::process::id(),
                        n
                    ));
                    n += 1;
                    if std::fs::create_dir(&path).is_err() {
                        continue;
                    }
                    let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o111);
                    let _ = std::fs::remove_dir(&path);
                    if mode.is_ok_and(|m| m == 0) {
                        bare.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            })
        };
        let dir = temp_query("esplora-umask").0;
        for i in 0..200 {
            let sock = dir.path().join(format!("s{i}.sock"));
            let listener = super::bind_unix_mode(&sock, 0o660).expect("bind");
            let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o660, "socket mode");
            drop(listener);
            let _ = std::fs::remove_file(&sock);
            if bare.load(Ordering::Relaxed) {
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = worker.join();
        unsafe { umask(old) };
        assert!(
            !bare.load(Ordering::Relaxed),
            "unix bind changed umask and a temp dir lost search permission"
        );
    }

    fn two_script_pay(tag: u8, spk: bitcoin::ScriptBuf) -> TxApply {
        let mut txid = [0u8; 32];
        txid[0] = tag;
        txid[31] = 0xaa;
        TxApply {
            tx: TxRecord {
                txid,
                version: 2,
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
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1_0000_0000, spk.to_bytes())],
        }
    }

    fn app_with_join(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>, trusted: bool) -> Router {
        let state = AppState {
            query: q,
            network: Network::Regtest,
            mempool: None,
            max_body: 1 << 20,
            sh_join: cache,
            join_header_trusted: trusted,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route("/scripthash/{hash}", get(handlers::scripthash_info))
            .route("/scripthash/{hash}/utxo", get(handlers::scripthash_utxo))
            .route("/scripthash/{hash}/txs", get(handlers::scripthash_txs))
            .route("/address/{addr}/utxo", get(handlers::address_utxo))
            .route("/scripthashes/txs", post(handlers::post_scripthashes_txs))
            .with_state(state)
    }

    async fn oneshot_http(
        app: &Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> (u16, String) {
        use tower::ServiceExt;
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get_with_client(path: &str, client: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(path)
            .header("X-Rbitcoin-Client", client)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn address_without_sh_index_is_503_disabled() {
        let (dir, q) = temp_query("esplora-sh-off");
        q.set_sh_index_enabled(false);
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let state = AppState {
            query: Arc::new(q),
            network: Network::Regtest,
            mempool: None,
            max_body: 1024,
            sh_join: Arc::new(Mutex::new(JoinCache::default())),
            join_header_trusted: false,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route("/address/{addr}/utxo", get(handlers::address_utxo))
            .route("/blocks/tip/height", get(tip_height))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                stamp_chain_view_mw,
            ))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let dummy = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8z5y2";
        let (st, body) = http_get(addr, &format!("/address/{dummy}/utxo")).await;
        assert_eq!(st, 503, "{body}");
        assert_eq!(body, rbitcoin_query::SCRIPTHASH_INDEX_DISABLED);
        let (st, body) = http_get(addr, "/blocks/tip/height").await;
        assert_eq!(st, 200, "tip must work without SH: {body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_503_chain_view_moved_omits_tip_header() {
        let (dir, q) = temp_query("http-503-moved");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let state = AppState {
            query: Arc::new(q),
            network: Network::Regtest,
            mempool: None,
            max_body: 1024,
            sh_join: Arc::new(Mutex::new(JoinCache::default())),
            join_header_trusted: false,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        };
        async fn die_tip(State(st): State<AppState>) -> &'static str {
            st.query.disconnect_tip().unwrap();
            "ok"
        }
        let app = Router::new()
            .route("/blocks/tip/hash", get(die_tip))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                stamp_chain_view_mw,
            ))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (st, raw, body) = http_get_raw(addr, "/blocks/tip/hash").await;
        assert_eq!(st, 503, "body={body}");
        assert!(
            body.contains("chain view moved"),
            "503 body must name the move: {body}"
        );
        assert!(
            header_value(&raw, HDR_CHAIN_TIP).is_none(),
            "503 must not stamp a fork tip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_defaults_use_public_proxy_limits() {
        let cfg = EsploraConfig::new("0.0.0.0:3000".parse().unwrap());
        assert_eq!(cfg.limits, ServeLimits::for_public_proxy());
    }

    #[test]
    fn asof_query_is_gated_to_documented_routes() {
        assert!(path_accepts_asof("/tx/ab/status"));
        assert!(path_accepts_asof("/tx/ab/outspends"));
        assert!(path_accepts_asof("/tx/ab/outspend/0"));
        assert!(path_accepts_asof("/scripthash/ab/utxo"));
        assert!(path_accepts_asof("/address/bcrt1q/txs/chain/cd"));
        assert!(!path_accepts_asof("/tx/ab"));
        assert!(!path_accepts_asof("/mempool"));
        assert!(!path_accepts_asof("/scripthash/ab/txs/mempool"));
        assert!(path_never_pins("/mempool"));
        assert!(path_never_pins("/mempool/txids"));
        assert!(path_never_pins("/fee-estimates"));
        assert!(path_never_pins("/tx"));
        assert!(!path_never_pins("/tx/ab"));
        assert!(parse_asof_param(&AsOfQuery { asof: None })
            .unwrap()
            .is_none());
        assert!(parse_asof_param(&AsOfQuery {
            asof: Some(String::new())
        })
        .is_err());
        assert!(parse_asof_param(&AsOfQuery {
            asof: Some("zz".into())
        })
        .is_err());
        assert!(parse_hash32("aa").is_err());
        assert!(parse_hash32("zz".repeat(32).as_str()).is_err());
    }

    /// No-hub Esplora: empty mempool, flat fee estimates, POST /tx is 503.
    /// Live `esplora_broadcast` always has a hub.
    #[tokio::test]
    async fn remaining_routes_fixture() {
        let (dir, q) = temp_query("remain");
        let (header, ta) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &header, &[ta]).unwrap();
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let (st, body) = http_get(addr, "/mempool").await;
        assert_eq!(st, 200, "{body}");
        let mem: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(mem["count"], 0);

        // No mempool, no estimate: 503, not an invented 1 sat/vB.
        let (st, body) = http_get(addr, "/fee-estimates").await;
        assert_eq!(st, 503, "{body}");
        assert!(body.contains("fee estimates unavailable"), "{body}");

        // mempool.space's tiers are its backend's /api/v1 surface, not Esplora's.
        for path in ["/fees/recommended", "/v1/fees/recommended"] {
            let (st, body) = http_get(addr, path).await;
            assert_eq!(st, 404, "{path}: {body}");
        }

        // mempool.space's websocket is its backend's /api/v1/ws, not Esplora's.
        for path in ["/ws", "/v1/ws"] {
            let (st, body) = http_get(addr, path).await;
            assert_eq!(st, 404, "{path}: {body}");
        }

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = "POST /tx HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab";
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("503") || text.contains("mempool"),
            "expected 503 without hub: {text}"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reconstruct meters + no-hub empty mempool lists (HTTP JSON/raw/status ride
    /// `esplora_broadcast_visible_in_rpc_and_electrum`).
    #[allow(clippy::cognitive_complexity)] // meters + leftover header/height/status needles
    #[tokio::test]
    async fn block_raw_summary_status_and_mempool_routes() {
        use bitcoin::consensus::encode::deserialize;
        use bitcoin::hashes::Hash;
        use bitcoin::{Block, MerkleBlock};

        let (dir, q) = temp_query("p0-block");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        let mut coinbase_txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let _ = q.sample_reset_reconstruct_archived();
        let h1 = block_hash_hex(&hashes[1]);
        let (st, body) = http_get(addr, &format!("/block/{h1}")).await;
        assert_eq!(st, 200, "block json {body}");
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/block JSON uses stamped size/weight"
        );

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req =
            format!("GET /block/{h1}/raw HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let sep = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("http headers");
        let raw = &buf[sep + 4..];
        assert!(
            String::from_utf8_lossy(&buf[..sep]).contains("200"),
            "raw status"
        );
        let block: Block = deserialize(raw).expect("decode raw block");
        assert_eq!(block.txdata.len(), 1);
        assert!(
            q.sample_reset_reconstruct_archived() >= 1,
            "/block/:hash/raw must reconstruct wire"
        );

        let _ = q.sample_reset_reconstruct_archived();
        let (st, _) = http_get(addr, "/blocks").await;
        assert_eq!(st, 200);
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/blocks summaries use stamped size/weight"
        );

        let txid0 = block_hash_hex(&coinbase_txids[0]);
        let _ = q.sample_reset_reconstruct_archived();
        let (st, body) = http_get(addr, &format!("/tx/{txid0}/merkleblock-proof")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "merkleblock-proof uses txid.body + header, not full reconstruct"
        );
        let mb_bytes = rbitcoin_primitives::hex_decode(&body).unwrap();
        let mb: MerkleBlock = deserialize(&mb_bytes).expect("merkleblock");
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        mb.extract_matches(&mut matches, &mut indexes).unwrap();
        assert_eq!(indexes, vec![0]);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0],
            bitcoin::Txid::from_byte_array(coinbase_txids[0])
        );

        let (st, body) = http_get(addr, "/mempool/txids").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");
        let (st, body) = http_get(addr, "/mempool/recent").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");

        let sh = rbitcoin_store::script_hash(&[0x51]);
        let sh_hex = block_hash_hex(&sh);
        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/mempool")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");

        let (st, body) = http_get(addr, "/block-height/1").await;
        assert_eq!(st, 200, "block-height body={body}");
        assert_eq!(body, block_hash_hex(&hashes[1]));
        let (st, _) = http_get(addr, "/block-height/99").await;
        assert_eq!(st, 404);

        let hash_disp = block_hash_hex(&hashes[1]);
        let (st, body) = http_get(addr, &format!("/block/{hash_disp}/header")).await;
        assert_eq!(st, 200, "header body len={}", body.len());
        assert_eq!(body.len(), 160);
        let wire = q.wire_header_at_height(Height(1)).unwrap();
        let expected = encode_header_hex(&wire).unwrap();
        assert_eq!(body, expected);
        let miss = "ff".repeat(32);
        let (st, _) = http_get(addr, &format!("/block/{miss}/header")).await;
        assert_eq!(st, 404);

        let (fk, _) = q.get_tx_by_txid(&coinbase_txids[0]).unwrap().unwrap();
        let st_json = tx_status_json(&q, fk).unwrap();
        assert_eq!(st_json["confirmed"], true);
        assert_eq!(st_json["block_height"], 0);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regtest P2WPKH address + scriptPubKey.
    fn regtest_p2wpkh() -> (String, bitcoin::ScriptBuf) {
        regtest_p2wpkh_sk(7)
    }

    fn regtest_p2wpkh_sk(fill: u8) -> (String, bitcoin::ScriptBuf) {
        use bitcoin::key::CompressedPublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::{Address, Network, PrivateKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[fill; 32]).expect("sk");
        let pk = PrivateKey::new(sk, Network::Regtest);
        let cpk = CompressedPublicKey::from_private_key(&secp, &pk).expect("cpk");
        let addr = Address::p2wpkh(&cpk, Network::Regtest);
        let spk = addr.script_pubkey();
        (addr.to_string(), spk)
    }

    fn display_txid(txid: bitcoin::Txid) -> String {
        use bitcoin::hashes::Hash;
        rbitcoin_primitives::display_hash_hex(&txid.to_byte_array())
    }

    include!("esplora_sh_journey.rs");
    include!("esplora_http_journey.rs");
}
