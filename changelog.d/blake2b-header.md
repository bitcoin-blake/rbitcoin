Added

- **Bitcoin Knots BLAKE2b chains.** `--network mainnet-blake2b` (`xbt`) and
  `--network testnet4-blake2b` (`txbt4`) run Knots' hardfork chains
  (`v29.4.1.knots20260508`): mainnet history to 961,639 / testnet4 to
  150,307, then v2 headers with BLAKE2b proof of work. Consensus follows
  Knots: v2 exactly from the fork height, header height field, reserved
  flag bits, tx count in the header, the one-off target shift at the fork
  block, the mainnet fork-block headline, the three mainnet fork
  checkpoints, and the 800,000 WU cap while RDTS is active (parent
  median-time-past below the expiry). RDTS script rules and the unified
  sighash are not enforced yet.
- **Bitcoin Knots v2 block header.** `bitcoin` comes from
  bitcoin-blake/rust-bitcoin (`v2-header`): a header with version bit 31
  carries the 84-byte Knots extension and hashes with the BLAKE2b
  pipeline. Schema **27**: `header.body` rows are 172 B (the 88 consensus
  bytes plus the v2 tail); a 26 datadir is widened on open. `header.adopt`
  slots are 164 B (magic `rbtchdr2`). Block size and weight count a
  164-byte header where the row says so.
