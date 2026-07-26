/**
 * Checkpoint table integrity.
 *
 * Checkpoints are the wallet's only defence against a fabricated chain above
 * `nLastPOWBlock`, where there is no proof of work to verify. A malformed or
 * mis-ordered entry is therefore not a cosmetic problem: a wrong hash rejects
 * the real chain outright, and a missing one leaves the chain unpinned.
 *
 * Correctness of the individual hashes is established by provenance (see the
 * module docblock in `checkpoints.ts`); these tests pin the invariants the
 * lookup helpers rely on.
 */

import { describe, test, expect } from "bun:test";

import {
  MAINNET_CHECKPOINTS,
  TESTNET_CHECKPOINTS,
  getCheckpointHash,
  getCheckpoints,
  getLatestCheckpoint,
  isCheckpointHeight,
} from "../src/checkpoints.js";
import { getNetwork } from "../src/network.js";

describe("checkpoint tables", () => {
  for (const [name, table] of [
    ["mainnet", MAINNET_CHECKPOINTS],
    ["testnet", TESTNET_CHECKPOINTS],
  ] as const) {
    describe(name, () => {
      test("starts at genesis and matches the network's genesis hash", () => {
        expect(table[0].height).toBe(0);
        expect(table[0].hash).toBe(getNetwork(name).genesisHash);
      });

      test("heights are unique and strictly ascending", () => {
        const heights = table.map((c) => c.height);
        expect([...heights].sort((a, b) => a - b)).toEqual(heights);
        expect(new Set(heights).size).toBe(heights.length);
      });

      test("timestamps advance with height", () => {
        for (let i = 1; i < table.length; i++) {
          expect(table[i].timestamp).toBeGreaterThan(table[i - 1].timestamp);
        }
      });

      test("hashes are 64 lowercase hex characters", () => {
        for (const cp of table) {
          expect(cp.hash).toMatch(/^[0-9a-f]{64}$/);
        }
      });

      test("hashes are unique", () => {
        expect(new Set(table.map((c) => c.hash)).size).toBe(table.length);
      });
    });
  }

  test("mainnet pins the proof-of-work boundary at nLastPOWBlock", () => {
    // Above 10000 the chain is proof-of-stake and unverifiable header-only, so
    // the boundary block itself must be checkpointed.
    expect(isCheckpointHeight(10_000, "mainnet")).toBe(true);
  });

  test("mainnet pins the chain beyond the PoW era", () => {
    expect(getLatestCheckpoint("mainnet").height).toBeGreaterThan(10_000);
  });
});

describe("lookup helpers", () => {
  test("getCheckpoints selects by network", () => {
    expect(getCheckpoints("mainnet")).toBe(MAINNET_CHECKPOINTS);
    expect(getCheckpoints("testnet")).toBe(TESTNET_CHECKPOINTS);
  });

  test("getLatestCheckpoint returns the highest entry", () => {
    const latest = getLatestCheckpoint("mainnet");
    for (const cp of MAINNET_CHECKPOINTS) {
      expect(latest.height).toBeGreaterThanOrEqual(cp.height);
    }
  });

  test("getCheckpointHash returns the hash at a checkpoint height", () => {
    for (const cp of MAINNET_CHECKPOINTS) {
      expect(getCheckpointHash(cp.height, "mainnet")).toBe(cp.hash);
    }
  });

  test("getCheckpointHash returns null between checkpoints", () => {
    expect(getCheckpointHash(10_001, "mainnet")).toBeNull();
    expect(isCheckpointHeight(10_001, "mainnet")).toBe(false);
  });
});
