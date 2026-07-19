/**
 * FairCoin network constants.
 * Values sourced from FairCoin's C++ source (chainparams.cpp).
 */

import { UNITS_PER_COIN } from "./branding.js";

export type NetworkType = "mainnet" | "testnet";

/** 1 FAIR = 100,000,000 base units. Re-exported from branding for local clarity. */
const COIN = UNITS_PER_COIN;

export interface NetworkConfig {
  readonly name: NetworkType;
  readonly ticker: string;
  readonly p2pPort: number;
  readonly rpcPort: number;
  readonly magicBytes: readonly [number, number, number, number];
  readonly pubKeyHash: number;
  readonly scriptHash: number;
  readonly wifPrefix: number;
  readonly bip32: {
    readonly public: number;
    readonly private: number;
  };
  readonly bip44CoinType: number;
  readonly protocolVersion: number;
  readonly genesisHash: string;
  readonly genesisMerkle: string;
  readonly genesisTime: number;
  readonly genesisNonce: number;
  readonly genesisBits: number;
  readonly dnsSeeds: readonly string[];
  readonly coinbaseMaturity: number;
  readonly maxBlockSize: number;
  readonly targetSpacing: number;
  /**
   * Total money supply cap in base units, mirroring `nMaxMoneyOut` in
   * FairCoin's `chainparams.cpp` (`33000000 * COIN`, both mainnet and
   * testnet). Enforced on output values by `assertValidOutputValue`
   * (transaction.ts), shared by `buildTransaction` and `buildMultisigSpend`.
   */
  readonly maxMoney: bigint;
  readonly coin: bigint;
  readonly masternodeCollateral: bigint;
  readonly minRelayFee: bigint;
  readonly maxReorgDepth: number;
}

export const MAINNET: NetworkConfig = {
  name: "mainnet",
  ticker: "FAIR",
  p2pPort: 46372,
  rpcPort: 46373,
  magicBytes: [0xa3, 0xd7, 0xe1, 0xb4],
  pubKeyHash: 35,
  scriptHash: 16,
  wifPrefix: 163,
  bip32: {
    public: 0x022d2533,
    private: 0x0221312b,
  },
  bip44CoinType: 119,
  protocolVersion: 71000,
  genesisHash:
    "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6",
  genesisMerkle:
    "9645f9761cc7212b2c8c79bcb2713a10d6e54623b24a8425b7bef2f16200a863",
  genesisTime: 1744156800,
  genesisNonce: 1299007,
  genesisBits: 0x1e0ffff0,
  dnsSeeds: ["seed1.fairco.in", "seed2.fairco.in"],
  coinbaseMaturity: 6,
  maxBlockSize: 1_000_000,
  targetSpacing: 120,
  maxMoney: 33_000_000n * COIN,
  coin: COIN,
  masternodeCollateral: 5_000n * COIN,
  minRelayFee: 10_000n,
  maxReorgDepth: 100,
} as const;

export const TESTNET: NetworkConfig = {
  name: "testnet",
  ticker: "FAIR",
  p2pPort: 46374,
  rpcPort: 46375,
  magicBytes: [0xb5, 0x2e, 0x9c, 0xf3],
  pubKeyHash: 65,
  scriptHash: 12,
  wifPrefix: 193,
  bip32: {
    public: 0x3a8061a0,
    private: 0x3a805837,
  },
  bip44CoinType: 1,
  protocolVersion: 71000,
  genesisHash:
    "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6",
  genesisMerkle:
    "9645f9761cc7212b2c8c79bcb2713a10d6e54623b24a8425b7bef2f16200a863",
  genesisTime: 1744156800,
  genesisNonce: 1299007,
  genesisBits: 0x1e0ffff0,
  dnsSeeds: ["testnet-seed1.fairco.in", "testnet-seed2.fairco.in"],
  coinbaseMaturity: 15,
  maxBlockSize: 1_000_000,
  targetSpacing: 120,
  maxMoney: 33_000_000n * COIN,
  coin: COIN,
  masternodeCollateral: 5_000n * COIN,
  minRelayFee: 10_000n,
  maxReorgDepth: 100,
} as const;

const NETWORKS: Record<NetworkType, NetworkConfig> = {
  mainnet: MAINNET,
  testnet: TESTNET,
};

export function getNetwork(type: NetworkType): NetworkConfig {
  const network = NETWORKS[type];
  if (!network) {
    throw new Error(`Unknown network type: ${String(type)}`);
  }
  return network;
}
