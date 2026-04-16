/**
 * Tests for FairCoin network configs.
 *
 * These assertions guard the mainnet / testnet constants against accidental
 * mutation. Changing any of these values would corrupt wallet addresses,
 * break P2P handshakes, or switch the user between chains — they should
 * only change as part of a deliberate protocol update.
 */

import { describe, test, expect } from "bun:test";

import { MAINNET, TESTNET, getNetwork, type NetworkType } from "../src/network.js";
import { UNITS_PER_COIN } from "../src/branding.js";

// ---------------------------------------------------------------------------
// MAINNET
// ---------------------------------------------------------------------------

describe("MAINNET", () => {
  test("basic identity", () => {
    expect(MAINNET.name).toBe("mainnet");
    expect(MAINNET.ticker).toBe("FAIR");
  });

  test("P2P / RPC ports", () => {
    expect(MAINNET.p2pPort).toBe(46372);
    expect(MAINNET.rpcPort).toBe(46373);
  });

  test("magic bytes", () => {
    expect(MAINNET.magicBytes).toEqual([0xa3, 0xd7, 0xe1, 0xb4]);
    expect(MAINNET.magicBytes.length).toBe(4);
  });

  test("address version bytes", () => {
    expect(MAINNET.pubKeyHash).toBe(35);
    expect(MAINNET.scriptHash).toBe(16);
    expect(MAINNET.wifPrefix).toBe(163);
  });

  test("BIP32 version bytes are non-zero", () => {
    expect(MAINNET.bip32.public).toBe(0x022d2533);
    expect(MAINNET.bip32.private).toBe(0x0221312b);
  });

  test("BIP44 coin type (FairCoin = 119)", () => {
    expect(MAINNET.bip44CoinType).toBe(119);
  });

  test("protocol version", () => {
    expect(MAINNET.protocolVersion).toBe(71000);
  });

  test("genesis fields are set", () => {
    expect(MAINNET.genesisHash.length).toBe(64);
    expect(MAINNET.genesisMerkle.length).toBe(64);
    expect(MAINNET.genesisTime).toBeGreaterThan(0);
    expect(MAINNET.genesisNonce).toBeGreaterThan(0);
    expect(MAINNET.genesisBits).toBeGreaterThan(0);
  });

  test("DNS seed list is non-empty", () => {
    expect(MAINNET.dnsSeeds.length).toBeGreaterThan(0);
    for (const seed of MAINNET.dnsSeeds) {
      expect(typeof seed).toBe("string");
      expect(seed.length).toBeGreaterThan(0);
    }
  });

  test("economic parameters", () => {
    expect(MAINNET.coin).toBe(UNITS_PER_COIN);
    expect(MAINNET.maxMoney).toBe(33_000_000n * UNITS_PER_COIN);
    expect(MAINNET.masternodeCollateral).toBe(5_000n * UNITS_PER_COIN);
    expect(MAINNET.minRelayFee).toBeGreaterThan(0n);
  });

  test("block / chain parameters", () => {
    expect(MAINNET.coinbaseMaturity).toBeGreaterThan(0);
    expect(MAINNET.maxBlockSize).toBeGreaterThan(0);
    expect(MAINNET.targetSpacing).toBe(120);
    expect(MAINNET.maxReorgDepth).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// TESTNET
// ---------------------------------------------------------------------------

describe("TESTNET", () => {
  test("basic identity", () => {
    expect(TESTNET.name).toBe("testnet");
    expect(TESTNET.ticker).toBe("FAIR");
  });

  test("P2P / RPC ports differ from mainnet", () => {
    expect(TESTNET.p2pPort).not.toBe(MAINNET.p2pPort);
    expect(TESTNET.rpcPort).not.toBe(MAINNET.rpcPort);
    expect(TESTNET.p2pPort).toBe(46374);
  });

  test("magic bytes differ from mainnet", () => {
    expect(TESTNET.magicBytes).not.toEqual(MAINNET.magicBytes);
  });

  test("address version bytes differ from mainnet", () => {
    expect(TESTNET.pubKeyHash).not.toBe(MAINNET.pubKeyHash);
    expect(TESTNET.scriptHash).not.toBe(MAINNET.scriptHash);
    expect(TESTNET.wifPrefix).not.toBe(MAINNET.wifPrefix);
  });

  test("BIP32 version bytes differ from mainnet", () => {
    expect(TESTNET.bip32.public).not.toBe(MAINNET.bip32.public);
    expect(TESTNET.bip32.private).not.toBe(MAINNET.bip32.private);
  });

  test("BIP44 coin type is 1 (standard testnet convention)", () => {
    expect(TESTNET.bip44CoinType).toBe(1);
  });

  test("DNS seeds differ from mainnet", () => {
    expect(TESTNET.dnsSeeds).not.toEqual(MAINNET.dnsSeeds);
    expect(TESTNET.dnsSeeds.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// getNetwork
// ---------------------------------------------------------------------------

describe("getNetwork", () => {
  test("returns mainnet", () => {
    expect(getNetwork("mainnet")).toBe(MAINNET);
  });

  test("returns testnet", () => {
    expect(getNetwork("testnet")).toBe(TESTNET);
  });

  test("throws on unknown network type", () => {
    const bogus = "devnet" as NetworkType;
    expect(() => getNetwork(bogus)).toThrow();
  });
});
