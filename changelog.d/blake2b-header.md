Added

- **Bitcoin Knots v2 block header.** `bitcoin` comes from
  bitcoin-blake/rust-bitcoin (`v2-header`): a header with version bit 31
  carries the 84-byte Knots extension and hashes with the BLAKE2b
  pipeline. Schema **27**: `header.body` rows are 172 B (the 88 consensus
  bytes plus the v2 tail); a 26 datadir is widened on open. Block size and
  weight count a 164-byte header where the row says so.
