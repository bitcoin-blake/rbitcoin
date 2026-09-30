Added

- **testnet4.** `--network testnet4` (conf `network=testnet4` or bare
  `testnet4`) runs Core's testnet4: magic `1c163f28`, ports 48333/48332,
  Core's DNS seeds, every buried deployment at height 1, default
  milestone 0. BIP94 is enforced: a retarget takes its base from the
  first block of the period, and the first block of a period is not
  more than 600 s earlier than its parent.
