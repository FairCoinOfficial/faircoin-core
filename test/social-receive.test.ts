import { describe, test, expect } from "bun:test";
import { hexToBytes, bytesToHex } from "../src/encoding.js";
import { getNetwork } from "../src/network.js";
import {
  deriveSocialReceiveAddress,
  deriveSocialReceiveSpendingKey,
  publicKeyFromPrivateKey,
  MAX_SOCIAL_RECEIVE_INDEX,
} from "../src/social-receive.js";

const IDENTITY_PRIV_A = hexToBytes("aa".repeat(32));
const IDENTITY_PRIV_B = hexToBytes("bb".repeat(32));
const IDENTITY_PUB_A_COMPRESSED = hexToBytes(
  "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3",
);
const IDENTITY_PUB_A_UNCOMPRESSED = hexToBytes(
  "046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6",
);
const TESTNET = getNetwork("testnet");
const MAINNET = getNetwork("mainnet");

describe("publicKeyFromPrivateKey", () => {
  test("derives the pinned compressed public key for a fixed private key", () => {
    expect(bytesToHex(publicKeyFromPrivateKey(IDENTITY_PRIV_A))).toBe(
      bytesToHex(IDENTITY_PUB_A_COMPRESSED),
    );
  });
});

describe("deriveSocialReceiveAddress", () => {
  test("derives the pinned addr(0..2) for a fixed identity on testnet", () => {
    expect(deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 0, TESTNET)).toBe(
      "TGW3g56Q5PvpA8UangXnzX6va2MkfaRx5r",
    );
    expect(deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 1, TESTNET)).toBe(
      "TERWsvgi5BFcdDKgpM1PsHMqenLuGggZqQ",
    );
    expect(deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 2, TESTNET)).toBe(
      "TVsFKn7zkDN1QnMNe1thrJUEXBGiqnu19g",
    );
  });

  test("derives the pinned addr(0) for the same identity on mainnet (network changes the address)", () => {
    expect(deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 0, MAINNET)).toBe(
      "FCMx8p9kmz2Xd8Hz46YESkwKgtdTPCUC74",
    );
  });

  test("CRITICAL: a compressed and an uncompressed encoding of the SAME public key produce the SAME address", () => {
    // Regression test for the normalization bug caught during design
    // verification — a caller may pass either encoding (e.g. Oxy's
    // resolveDid() publicKeyHex is uncompressed while a private-key-derived
    // probe's .publicKey is compressed). Both MUST resolve to the same branch.
    const compressed = deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 0, TESTNET);
    const uncompressed = deriveSocialReceiveAddress(IDENTITY_PUB_A_UNCOMPRESSED, 0, TESTNET);
    expect(uncompressed).toBe(compressed);
  });

  test("a different identity yields a different addr(0)", () => {
    const pubB = publicKeyFromPrivateKey(IDENTITY_PRIV_B);
    const addrB = deriveSocialReceiveAddress(pubB, 0, TESTNET);
    expect(addrB).toBe("TS2vNQ9Kbv9L4S8iyZZoD5278mAeVduLYn");
    expect(addrB).not.toBe(deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 0, TESTNET));
  });

  test("distinct indexes yield distinct addresses", () => {
    const a0 = deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 0, TESTNET);
    const a1 = deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 1, TESTNET);
    expect(a1).not.toBe(a0);
  });

  test("rejects a negative index", () => {
    expect(() => deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, -1, TESTNET)).toThrow(
      /index/,
    );
  });

  test("rejects a non-integer index", () => {
    expect(() => deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, 1.5, TESTNET)).toThrow(
      /index/,
    );
  });

  test("rejects an index at or beyond the hardened offset", () => {
    expect(() =>
      deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, MAX_SOCIAL_RECEIVE_INDEX + 1, TESTNET),
    ).toThrow(/index/);
  });

  test("accepts the maximum legal index without throwing", () => {
    expect(() =>
      deriveSocialReceiveAddress(IDENTITY_PUB_A_COMPRESSED, MAX_SOCIAL_RECEIVE_INDEX, TESTNET),
    ).not.toThrow();
  });
});

describe("deriveSocialReceiveSpendingKey", () => {
  test("derives the pinned spending key at index 0 for a fixed identity", () => {
    const key = deriveSocialReceiveSpendingKey(IDENTITY_PRIV_A, 0);
    expect(bytesToHex(key)).toBe(
      "42d089c0f361d67b6add7279d67718bc89ddd35d2218696991c24d3902d26c86".slice(0, 64),
    );
  });

  test("never returns the raw identity private key (no leak)", () => {
    const key = deriveSocialReceiveSpendingKey(IDENTITY_PRIV_A, 0);
    expect(bytesToHex(key)).not.toBe(bytesToHex(IDENTITY_PRIV_A));
  });

  test("KEY PROPERTY: for every index, the address derived from the PUBLIC key equals publicKeyToAddress of the spending key derived from the PRIVATE key", () => {
    const { publicKeyToAddress } = require("../src/address.js") as {
      publicKeyToAddress: (pubKey: Uint8Array, network: ReturnType<typeof getNetwork>) => string;
    };
    for (const index of [0, 1, 2, 41, MAX_SOCIAL_RECEIVE_INDEX]) {
      const addressFromPublicPath = deriveSocialReceiveAddress(
        IDENTITY_PUB_A_COMPRESSED,
        index,
        TESTNET,
      );
      const spendingKey = deriveSocialReceiveSpendingKey(IDENTITY_PRIV_A, index);
      const spendingPub = publicKeyFromPrivateKey(spendingKey);
      const addressFromPrivatePath = publicKeyToAddress(spendingPub, TESTNET);
      expect(addressFromPrivatePath).toBe(addressFromPublicPath);
    }
  });

  test("rejects an out-of-range index the same way the public path does", () => {
    expect(() => deriveSocialReceiveSpendingKey(IDENTITY_PRIV_A, -1)).toThrow(/index/);
    expect(() =>
      deriveSocialReceiveSpendingKey(IDENTITY_PRIV_A, MAX_SOCIAL_RECEIVE_INDEX + 1),
    ).toThrow(/index/);
  });
});
