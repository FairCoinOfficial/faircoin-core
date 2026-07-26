/**
 * Hardcoded block-header checkpoints, mirroring `Checkpoints::CheckBlock` in
 * FairCoin core: if a header lands on a checkpoint height, its id must match.
 *
 * Why this matters more here than on a pure proof-of-work chain: FairCoin is
 * proof-of-stake above `nLastPOWBlock` (10000 on mainnet), and a header-only
 * client cannot verify a PoS block's work — there is none to verify. Below
 * that height the SPV client checks `quarkHash <= target`; above it,
 * checkpoints plus prev-hash linkage are the only thing standing between the
 * wallet and a fabricated chain from a hostile peer. A checkpoint at height H
 * transitively pins every header below it, because each header commits to its
 * parent.
 *
 * Every hash below was read from a synced header store and independently
 * confirmed against the live network: a `faircoin Core:3.0.0` node
 * (80.240.127.240) accepted each as a block locator and returned the same
 * successor we hold, and height 10000 also matches explorer.fairco.in.
 *
 * The chain runs at roughly 200 blocks/day, so this list should be extended
 * periodically — an old newest checkpoint leaves the recent chain unpinned.
 */

export interface Checkpoint {
  height: number;
  /**
   * Block id in DISPLAY byte order — the form explorers, `getblockhash` and
   * `NetworkConfig.genesisHash` use, i.e. the reverse of the internal
   * `uint256` bytes returned by `hashBlockHeader`. Consumers comparing against
   * a computed hash must reverse one side.
   */
  hash: string;
  timestamp: number; // block timestamp
}

export const MAINNET_CHECKPOINTS: readonly Checkpoint[] = [
  {
    height: 0,
    hash: "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6",
    timestamp: 1744156800,
  },
  // Last proof-of-work block (`nLastPOWBlock`). Everything above is PoS.
  {
    height: 10000,
    hash: "00000000a840c1a7ca180f542fa26beed769bf0a91ba60c65b1d3d60911308c0",
    timestamp: 1777017373,
  },
  {
    height: 20000,
    hash: "c9b4742161c6a1f6d2c763f9fb5f067e23b9c19352b1c38eb3258f194a861ae5",
    timestamp: 1781420649,
  },
  {
    height: 30000,
    hash: "6b2e630fd84a8e6d686ebc43f801f5023f53f20c8e50d163b86dc29bdbf0b085",
    timestamp: 1782026601,
  },
  {
    height: 40000,
    hash: "a566ea3627452fb962821e560c3dcd82ac0a31c47ce2db6c0d33ed076dd43c97",
    timestamp: 1782634734,
  },
  {
    height: 50000,
    hash: "d6552da241eda6ef39cdae0e1a40ad8698e50f129bd900f912124af11114f972",
    timestamp: 1783239013,
  },
  {
    height: 60000,
    hash: "b4b9316575a222c5a7076cefef61bc77b1c28ccaa4c3d95a8740c617f41e7120",
    timestamp: 1783843225,
  },
] as const;

// Testnet carries genesis only: no testnet chain data has been verified, and
// an unverified checkpoint is worse than none — it would reject the real chain.
export const TESTNET_CHECKPOINTS: readonly Checkpoint[] = [
  {
    height: 0,
    hash: "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6",
    timestamp: 1744156800,
  },
] as const;

export function getCheckpoints(
  network: "mainnet" | "testnet",
): readonly Checkpoint[] {
  return network === "mainnet" ? MAINNET_CHECKPOINTS : TESTNET_CHECKPOINTS;
}

export function getLatestCheckpoint(
  network: "mainnet" | "testnet",
): Checkpoint {
  const cps = getCheckpoints(network);
  return cps[cps.length - 1];
}

export function isCheckpointHeight(
  height: number,
  network: "mainnet" | "testnet",
): boolean {
  return getCheckpoints(network).some((cp) => cp.height === height);
}

export function getCheckpointHash(
  height: number,
  network: "mainnet" | "testnet",
): string | null {
  const cp = getCheckpoints(network).find((c) => c.height === height);
  return cp ? cp.hash : null;
}
