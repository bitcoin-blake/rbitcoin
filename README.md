# rbitcoin — the Bitcoin Knots BLAKE2b chains

This is [bitcoin-blake](https://github.com/bitcoin-blake)'s fork of
[reardencode/rbitcoin](https://github.com/reardencode/rbitcoin), a Bitcoin full
node in Rust, taught the Bitcoin Knots BLAKE2b hardfork chains
(`v29.4.1.knots20260508`). It is a second, independent implementation of the
fork's consensus rules, with rbitcoin's relational archive and in-process
Electrum/Esplora behind it. The upstream README follows below; everything in it
about mainnet, signet and regtest still holds.

| network | alias | history | first v2 block |
|---|---|---|---|
| `mainnet-blake2b` | `xbt` | mainnet to 961,639 | 961,640 |
| `testnet4-blake2b` | `txbt4` | testnet4 to 150,307 | 150,308 |

Plain `testnet4` (Core's chain, BIP94) is also new here; upstream has no testnet4.

**What is implemented** (branch `blake2b`): the 164-byte v2 header and its
BLAKE2b proof of work (in a patched rust-bitcoin,
[bitcoin-blake/rust-bitcoin `v2-header`](https://github.com/bitcoin-blake/rust-bitcoin/tree/v2-header),
checked against Knots' vectors); schema **27** header rows; v2 exactly from the
fork height, the header height field, the reserved flag bits, the one-off
target shift, the tx count in the header, the mainnet fork-block headline and
the three mainnet fork checkpoints; the 800,000 WU cap, the RDTS script rules
and the 34-byte output scripts while RDTS is active; and the unified signature
hash (`SIGHASH_UNIFIED`, Knots' 166 vectors). A fresh `testnet4-blake2b` sync
from genesis, every script checked, reaches Knots' tip with the same best-block
hash in under four minutes from a local peer.

**Not yet**: relay policy on the fork chains (the mempool does not opt in to
the unified sighash or apply RDTS as policy), `getblocktemplate` / `submitblock`
/ the SV2 template provider for v2 blocks, and Electrum/Esplora serving 164-byte
headers. Run it as a validating, archiving, RPC node behind a Knots peer, not as
a mining or wallet backend, until those land. The fork is not offered upstream.

```bash
cargo build --release -p rbitcoin-node -p rbitcoin-cli
./target/release/rbitcoin-node --network testnet4-blake2b --datadir ~/rbitcoin-txbt4 \
    --connect 127.0.0.1:48343 --no-seeds --rpc --milestone 0
./target/release/rbitcoin-cli --rpc-socket ~/rbitcoin-txbt4/rpc.sock getblockchaininfo
```

`--connect` names a Knots node (Knots keeps testnet4's magic and port 48333, so
Core's testnet4 peers connect too and are dropped at 150,308 by the v2 rule);
drop `--no-seeds` to use Knots' DNS seeds. Use a **release** build: a debug
build verifies scripts at about two blocks a second. `--milestone 0` checks
every script; `mainnet-blake2b` keeps upstream's mainnet default (840,000,
anchored) since the history below the fork is mainnet's.

**Disk**: the archive holds the whole history, txindex-equivalent. `testnet4-blake2b`
is about **14 GB** at the tip (8.6 GB of that is `seqsigwit`, the scriptSig/witness
store, which `--datadir-cold` can put on a slower volume), roughly what a Knots
node with `txindex=1` uses, growing with the chain and not with time. The
post-fork chain is small (blocks are capped at 800,000 WU while RDTS is active).
`mainnet-blake2b` is mainnet's history plus a small tail: the ~200 GB hot /
~700 GB total in the upstream section below.

A schema-26 datadir from upstream is widened to 27 on open; a datadir synced as
`testnet4` can be reopened as `testnet4-blake2b` (same genesis) and continues
past the fork. Changes are listed in
[`changelog.d/blake2b-header.md`](./changelog.d/blake2b-header.md) and
[`changelog.d/network-testnet4.md`](./changelog.d/network-testnet4.md).

---

# rbitcoin

[![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/reardencode/rbitcoin/badges/coverage.json)](TESTING.md)

Bitcoin **full node** in Rust aimed at **production server-side** use: multi-peer
IBD, tip follow, block/tx relay (tip mode), optional **Core-class JSON-RPC**, and
in-process **Electrum + optional Esplora REST** (scripthash index via
`--sh-index`, default off; **0.8** Core+electrs drop-in:
[`COMPAT.md`](./COMPAT.md)) — built
around a **relational archive (Class A/B/C)** and a **pure-Rust
consensus/script** path.

> **0.7.99** is the in-tree version (pre-**0.8.0**). Last published GitHub
> Release tag is **0.7.0** (patch line **`v0.7.x`**: Linux musl + Windows
> CRT-static + Darwin aarch64). Occupied **0.6.x** stores **refuse** — wipe
> the datadir and redo IBD.
> **Not 1.0:** schema can still refuse a named wipe ([`SCHEMA.md`](./SCHEMA.md),
> [`OPERATOR.md`](./OPERATOR.md));
> default mainnet **`--milestone` is block 840000**
> (`0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5`):
> script/sig checks skip only on that header path once chain work meets
> the minimum (`--milestone 0` is full scripts; an explicit height is
> height-only). Signet’s default milestone is **0** (every script).
> Electrum/Esplora need **`--sh-index`**
> (default off) after tip. Run **signet first**, then mainnet with monitoring.
> Report security issues privately: [`SECURITY.md`](./SECURITY.md). Runbook:
> [`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

| | |
|--|--|
| **License** | MIT OR Apache-2.0 ([`LICENSE-MIT`](./LICENSE-MIT), [`LICENSE-APACHE`](./LICENSE-APACHE)) |
| **Version** | **0.7.99** (pre-0.8.0) — [`CHANGELOG.md`](./CHANGELOG.md) |
| **Platform** | **Linux musl** is the operator path. Windows / Darwin are published snapshots (no IoRing; Darwin not notarized) |
| **Security** | [`SECURITY.md`](./SECURITY.md) — **0.7.x** supported published line; no LTS until 1.0 |
| **Design** | [`docs/architecture.md`](./docs/architecture.md) — why this node is different |
| **Develop** | rustup 1.95, no Nix — [`CONTRIBUTING.md`](./CONTRIBUTING.md) |
| **Coverage** | Live production-file LCOV (badge; last green `master` `coverage` job). Every PR **must not drop** that ratio. Highest published line coverage among bitcoin full nodes — [`TESTING.md`](./TESTING.md) |

## Why this node is different

Most full nodes center a **UTXO set + block files** (Bitcoin Core). Most Electrum
backends are **external indexers** of another node. rbitcoin does neither:
**no UTXO set** (relational archive), **Electrum + txindex in-process**.

- **~200 GiB** hot pin/annotate set (schema 17); **~700 GiB** with cold `seqsigwit` —
  census in [`SCHEMA.md`](./SCHEMA.md), `--sh-index` costs in [`OPERATOR.md`](./OPERATOR.md)
- **Under ~30 h** IBD on a laptop-class host with **`--milestone 0`**
- **Modest RAM** during sync — no multi‑GiB `dbcache` pause
- **Pure-Rust** consensus/scripts (**no** `libbitcoinconsensus`)
- **Highest published line coverage** among bitcoin full nodes (live production-file LCOV on the badge; every PR **must not drop** that ratio) — [`TESTING.md`](./TESTING.md)
- **Reproducible static musl** for ordinary Linux hosts

Core / Fulcrum contrasts: **[`docs/architecture.md`](./docs/architecture.md)**.
Product surface: [`COMPAT.md`](./COMPAT.md). RPC subset: [`docs/rpc.md`](./docs/rpc.md).

## Status

Core pipelines exist (store, consensus, P2P IBD, tip follow, scripthash,
Electrum, Esplora REST, libre mempool) for the **server-side / wallet-client
backend** role. **0.7 mainnet** is early production / high-scrutiny — not a
Core or Fulcrum replacement, not a soak badge. Run **signet first**, then
mainnet with monitoring ([`OPERATOR.md`](./OPERATOR.md)). First hour on
regtest (mine → Electrum → Esplora): [`docs/operator/operations.md`](./docs/operator/operations.md#first-hour-regtest).
Finishing any one operator’s first full mainnet sync is **not** a gate for
using or packaging this tree. 1.0 gates:
[`docs/road-to-1.0.md`](./docs/road-to-1.0.md).

**0.8:** drop-in for **mempool/electrs or Blockstream electrs HTTP** (not
address-prefix, not their `/api/v1/` Node process). Core RPC for that stack
is unix `{datadir}/rpc.sock` plus a documented mempool `CORE_RPC` socket
patch, not cookie. Product surface: [`COMPAT.md`](./COMPAT.md).

**Authorship:** first-party code is **AI-written** (Grok / xAI) under
**Brandon Black** ([@reardencode](https://github.com/reardencode)) prompting —
details in [`SECURITY.md`](./SECURITY.md). Default milestone and script skip:
[`OPERATOR.md`](./OPERATOR.md). Signet lab:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

## Build

### Develop (any OS, Nix optional)

**Nix is not required.** Rust **1.95** via [rustup](https://rustup.rs)
([`rust-toolchain.toml`](./rust-toolchain.toml)). Clone, first build, `--smoke`,
and Windows/macOS notes: **[`CONTRIBUTING.md`](./CONTRIBUTING.md)** (Getting
started).

```bash
git clone https://github.com/reardencode/rbitcoin.git && cd rbitcoin
cargo build -p rbitcoin-node -p rbitcoin-cli
```

Linux-only optional pin (`nix develop` / `nix-shell`, same `flake.lock` as
release). Agents use one worktree per session (topic branch per PR) and let
Actions run workspace/coverage gates — [`AGENTS.md`](./AGENTS.md).

### Portable static release (Linux operator)

Pinned **nixpkgs + Cargo.lock** musl static binaries. Commands and
byte-identity: [`docs/reproducible-builds.md`](./docs/reproducible-builds.md).
Day-to-day flags: [`OPERATOR.md`](./OPERATOR.md). Experimental mainnet:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

Do **not** use `cargo build --release` inside `nix-shell` / `nix develop` as the
operator binary — that links against the Nix store glibc and fails outside the
store.

## Crates

Workspace crate ownership and dependency orientation:
[`docs/CRATES.md`](./docs/CRATES.md).

## Documentation

Full map (one owner per fact): **[`docs/README.md`](./docs/README.md)**.

| Audience | Start |
|----------|-------|
| Operator | [`OPERATOR.md`](./OPERATOR.md) |
| Product / interop | [`COMPAT.md`](./COMPAT.md) |
| Contributor | [`CONTRIBUTING.md`](./CONTRIBUTING.md) (getting started: rustup, Linux / macOS / Windows) |
| Agent | [`AGENTS.md`](./AGENTS.md) |
| On-disk | [`SCHEMA.md`](./SCHEMA.md) |
| Tests | [`TESTING.md`](./TESTING.md) |

Design uniqueness: [`docs/architecture.md`](./docs/architecture.md).
Security contact: [`SECURITY.md`](./SECURITY.md).

## What this is not

- Production multi-tenant Electrum or “drop-in Core”
- Wallet, mining, GUI, or pruning
- Full Core JSON-RPC surface
- A claim of complete mainnet script validation under the **default** milestone
  (use `--milestone 0` for full scripts)
- A multi-OS port — **Linux is the supported IO target** today

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions. See
[`CONTRIBUTING.md`](./CONTRIBUTING.md).
