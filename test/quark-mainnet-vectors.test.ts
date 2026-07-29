/**
 * Quark block-header hash — REAL FairCoin mainnet vectors.
 *
 * This file exists because the Quark implementation silently regressed once
 * already: 0.1.1 shipped a correct BMW-512 `add_elt_b` and Groestl-512
 * (T0 table byte order, QC64 round constant, ROTR row combine, and the
 * `state[15] = out_size` init), and 0.2.0 shipped a rebuilt version with all
 * of those reverted. Nothing caught it, because the existing quark tests only
 * assert that the function is deterministic and input-sensitive — properties a
 * completely wrong hash satisfies just as well.
 *
 * A wrong block hash is not a cosmetic bug: the SPV client keys its header
 * chain, its merkle-block association and its proof-of-work check on it, so a
 * regression here silently breaks *all* syncing and every balance derived from
 * it.
 *
 * Provenance of the vectors below: read from a synced wallet's header store
 * and independently confirmed against the live network — block 5000's raw
 * 80-byte header was pulled from `faircoin Core:3.0.0` at 80.240.127.240 over
 * P2P (`getdata MSG_BLOCK`) and its id matched, and the same node confirmed
 * the chain at heights 20000/40000/60000. Height 10000 additionally matches
 * explorer.fairco.in.
 *
 * Heights <= 10000 (`nLastPOWBlock`) are proof-of-work, so their hashes must
 * also satisfy their own difficulty target — an independent check that no
 * incorrect implementation can pass by accident.
 */

import { describe, test, expect } from "bun:test";

import { bytesToHex, hexToBytes } from "../src/encoding.js";
import { hashBlockHeader, type BlockHeader } from "../src/quark-hash.js";
import { compactToTarget, hashToUint256, meetsProofOfWork } from "../src/proof-of-work.js";
import { getNetwork } from "../src/network.js";

interface MainnetVector {
  readonly height: number;
  /** Block id in internal (`uint256`) byte order. */
  readonly hash: string;
  readonly header: BlockHeader;
  readonly bits: number;
}

function vector(
  height: number,
  hash: string,
  prev: string,
  merkle: string,
  timestamp: number,
  bits: number,
  nonce: number,
  version: number,
): MainnetVector {
  return {
    height,
    hash,
    bits,
    header: {
      version,
      prevHash: hexToBytes(prev),
      merkleRoot: hexToBytes(merkle),
      timestamp,
      bits,
      nonce,
    },
  };
}

/** Proof-of-work era: height <= LAST_POW_BLOCK (10000). */
const POW_VECTORS: readonly MainnetVector[] = [
  vector(1, "0c9f2cd54e4d620a724bc93a8176dc6f3ec24ec933d243a2344f16e17b0c0000", "e676a5a1a9f8c3d377cf71cee42fd775df14877465cd85cf674513cb32020000", "3aa0965b37178a6e8daa6f6115ee76e14ca35089a9f43a0931b3d2d4a427368f", 1775716724, 504365055, 176, 3),
  vector(4999, "7a4bcc2ab2010c6abda1046f38c2d58702798b1850dfd70b8d73fb6300000000", "6f28a253f9d420abebe9ec5c31d2a2f9df0a2cd371fec591cc089aef00000000", "0edf20d7a1279d53bcdd4fd94bdb5fef269f7ce829545cb982eb488eb2b7a86e", 1776386570, 486602493, 2452187169, 3),
  vector(5000, "6f12847cf400cd558b19936c9bced0ef06e15efa715c8583c3955f1c00000000", "7a4bcc2ab2010c6abda1046f38c2d58702798b1850dfd70b8d73fb6300000000", "5d836168c80c2390bd6abe826c6280e95ab0ddbd2ff751f3df8e0214bfbe9162", 1776386749, 486611763, 3560544522, 3),
  vector(10000, "c0081391603d1d5bc660ba910abf69d7ee6ba22f540f18caa7c140a800000000", "981927ce14fdcbb1765bde9bb4ab8db8062b9759ce09481212a59e9000000000", "846131c3b3e6a783cd319244124b53555df29f1896a2cda5912a1ec52c719d29", 1777017373, 486602133, 702131462, 3),
];

/** Proof-of-stake era: height > LAST_POW_BLOCK, nonce is always 0. */
const POS_VECTORS: readonly MainnetVector[] = [
  vector(10001, "74f40550d67f099c58368b89961829dc00995b90db03ae7e8b2b293bf246195d", "c0081391603d1d5bc660ba910abf69d7ee6ba22f540f18caa7c140a800000000", "21030367347090ea38c8bf09f0190de461a4f97967362ee13f4780bb63265716", 1780828992, 486605583, 0, 3),
  vector(33333, "ea8d5eac28aba2ef7f891416739ac26f15b616103177c82c312888ce645ec4a9", "0e7ad41fd00317f62dc0aa48cee02bd2e2aaaa74a325d3e857b35fa171cb2635", "39b43a98a2858bcd0098e789acfa5b4f0b4ea3670e5f79f9c5f32b2c1e457b3f", 1782229107, 454114518, 0, 3),
  vector(50000, "72f91411f14a1212f900d99b120fe59886ad401a0eaecd39efa6ed41a22d55d6", "78b6fd5eafbb6abec16c0df207523e07688cf8ce616c88723d8c6c6284c8de0d", "8b4d643208d441db65e154de4f168bf614b05fb71a1b5003b4f8c048648da32b", 1783239013, 454952363, 0, 3),
  vector(67767, "7ee7f799f28ca4c263bca712d286e939343346f058b695687cdcbb793154c6a6", "0b7def7b2f178a9098bedca723949da18b94bd2343d97670a857fbd83879a6f0", "1cb86cc093f0e7fee0884fc0864ab6fa47e547f333afc8afc836c7e6d6677392", 1784312378, 453370014, 0, 3),
];

const ALL_VECTORS = [...POW_VECTORS, ...POS_VECTORS];

describe("hashBlockHeader — mainnet vectors", () => {
  for (const v of ALL_VECTORS) {
    test(`block ${v.height} hashes to its canonical id`, () => {
      expect(bytesToHex(hashBlockHeader(v.header))).toBe(v.hash);
    });
  }

  test("distinct blocks produce distinct hashes", () => {
    const hashes = new Set(
      ALL_VECTORS.map((v) => bytesToHex(hashBlockHeader(v.header))),
    );
    expect(hashes.size).toBe(ALL_VECTORS.length);
  });
});

describe("proof of work confirms the hashes independently", () => {
  for (const v of POW_VECTORS) {
    test(`block ${v.height} satisfies its difficulty target`, () => {
      const hash = hashBlockHeader(v.header);
      expect(hashToUint256(hash)).toBeLessThanOrEqual(compactToTarget(v.bits).target);
    });
  }

  test("a one-bit change to the nonce destroys the work", () => {
    const v = POW_VECTORS[2];
    const tampered = hashBlockHeader({
      ...v.header,
      nonce: v.header.nonce ^ 1,
    });
    expect(meetsProofOfWork(tampered, v.bits)).toBe(false);
  });
});

describe("lastPowBlock matches where the work actually stops", () => {
  const { lastPowBlock } = getNetwork("mainnet");

  test("every PoW-era vector is at or below it and meets its target", () => {
    for (const v of POW_VECTORS) {
      expect(v.height).toBeLessThanOrEqual(lastPowBlock);
      expect(meetsProofOfWork(hashBlockHeader(v.header), v.bits)).toBe(true);
    }
  });

  test("every PoS-era vector is above it and meets no target", () => {
    // If `lastPowBlock` were ever raised past a real PoS block, the wallet
    // would start rejecting the live chain. This pins the boundary to data.
    for (const v of POS_VECTORS) {
      expect(v.height).toBeGreaterThan(lastPowBlock);
      expect(meetsProofOfWork(hashBlockHeader(v.header), v.bits)).toBe(false);
    }
  });
});
