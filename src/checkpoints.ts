/**
 * Hardcoded block header checkpoints for fast SPV sync verification.
 * These are known block hashes at specific heights used to validate
 * the chain during initial sync.
 */

export interface Checkpoint {
  height: number;
  hash: string; // hex, internal byte order
  timestamp: number; // block timestamp
}

// FairCoin mainnet checkpoints
// Genesis block and placeholder checkpoints for future chain growth
export const MAINNET_CHECKPOINTS: readonly Checkpoint[] = [
  {
    height: 0,
    hash: "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6",
    timestamp: 1744156800,
  },
] as const;

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
