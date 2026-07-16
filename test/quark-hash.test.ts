/**
 * Tests for the Quark hash algorithm and block header serialization.
 *
 * The correctness tests in the `quarkHash correctness` block originally
 * exposed a bug in the pure-TS BLAKE-512 implementation that caused many
 * inputs (notably all 80-byte block headers) to collapse to the same
 * hash. That bug has since been fixed by swapping the broken custom
 * BLAKE-512 for @noble/hashes/blake1 — the tests now pass and act as a
 * regression guard against the bug re-appearing.
 *
 * Quark chains BLAKE-512, BMW-512, Groestl-512, JH-512, Keccak-512, and
 * Skein-512. Every stage has been verified byte-for-byte against the FairCoin
 * C reference (src/crypto/*.c → HashQuark). Two bugs were fixed in the process:
 *   - BMW-512 `add_elt_b` double-counted the rotation offset (+1 twice).
 *   - Groestl-512 used the wrong T-table byte order, rotated left instead of
 *     right, placed the Q round constant in the MSB instead of the LSB, and
 *     seeded the IV with 512<<56 instead of 512.
 * The `reference block ids` test below locks this in: `hashBlockHeader` must
 * reproduce real mainnet block hashes (genesis, the first PoW blocks, and a
 * PoS-era block), which is only possible if the whole Quark chain is correct.
 */

import { describe, test, expect } from "bun:test";

import { bytesToHex, hexToBytes } from "../src/encoding.js";
import {
  doubleSha256,
  hashBlockHeader,
  quarkHash,
  serializeBlockHeader,
  type BlockHeader,
} from "../src/quark-hash.js";

// ---------------------------------------------------------------------------
// serializeBlockHeader
// ---------------------------------------------------------------------------

describe("serializeBlockHeader", () => {
  const genesisHeader: BlockHeader = {
    version: 1,
    prevHash: new Uint8Array(32),
    merkleRoot: hexToBytes(
      "9645f9761cc7212b2c8c79bcb2713a10d6e54623b24a8425b7bef2f16200a863",
    ),
    timestamp: 1744156800,
    bits: 0x1e0ffff0,
    nonce: 1299007,
  };

  test("output length is exactly 80 bytes", () => {
    const serialized = serializeBlockHeader(genesisHeader);
    expect(serialized.length).toBe(80);
  });

  test("serialisation is deterministic", () => {
    const a = serializeBlockHeader(genesisHeader);
    const b = serializeBlockHeader(genesisHeader);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("known serialisation for FairCoin genesis fields", () => {
    const serialized = serializeBlockHeader(genesisHeader);
    // version(1, LE) + prevHash(32 zeros) + merkleRoot(32) + timestamp(LE)
    // + bits(LE) + nonce(LE)
    expect(bytesToHex(serialized)).toBe(
      "01000000" + // version 1 LE
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "9645f9761cc7212b2c8c79bcb2713a10d6e54623b24a8425b7bef2f16200a863" +
        "80b8f567" + // timestamp 1744156800 LE
        "f0ff0f1e" + // bits 0x1e0ffff0 LE
        "3fd21300", // nonce 1299007 LE
    );
  });

  test("rejects prevHash of wrong length", () => {
    expect(() =>
      serializeBlockHeader({ ...genesisHeader, prevHash: new Uint8Array(31) }),
    ).toThrow();
  });

  test("rejects merkleRoot of wrong length", () => {
    expect(() =>
      serializeBlockHeader({
        ...genesisHeader,
        merkleRoot: new Uint8Array(31),
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// doubleSha256
// ---------------------------------------------------------------------------

describe("doubleSha256", () => {
  test("empty string", () => {
    // SHA256(SHA256("")) — standard reference value.
    expect(bytesToHex(doubleSha256(new Uint8Array(0)))).toBe(
      "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
    );
  });

  test("output length is 32 bytes", () => {
    expect(doubleSha256(new Uint8Array(1)).length).toBe(32);
    expect(doubleSha256(new Uint8Array(1024)).length).toBe(32);
  });

  test("single-byte vector", () => {
    // SHA256(SHA256("abc")) — standard reference value.
    const data = new TextEncoder().encode("abc");
    expect(bytesToHex(doubleSha256(data))).toBe(
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
    );
  });

  test("is deterministic", () => {
    const data = new TextEncoder().encode("hello");
    expect(bytesToHex(doubleSha256(data))).toBe(bytesToHex(doubleSha256(data)));
  });
});

// ---------------------------------------------------------------------------
// quarkHash (smoke / correctness properties)
// ---------------------------------------------------------------------------

describe("quarkHash", () => {
  test("output length is 32 bytes for empty input", () => {
    const h = quarkHash(new Uint8Array(0));
    expect(h.length).toBe(32);
  });

  test("output length is 32 bytes for 80-byte block header", () => {
    const h = quarkHash(new Uint8Array(80));
    expect(h.length).toBe(32);
  });

  test("output length is 32 bytes for large input", () => {
    const h = quarkHash(new Uint8Array(1024));
    expect(h.length).toBe(32);
  });

  test("is deterministic for the same input", () => {
    const data = new TextEncoder().encode("FairCoin");
    expect(bytesToHex(quarkHash(data))).toBe(bytesToHex(quarkHash(data)));
  });
});

// ---------------------------------------------------------------------------
// quarkHash — correctness properties
//
// These tests encode invariants that any correct cryptographic hash MUST
// satisfy. They used to fail due to the broken pure-TS BLAKE-512; after
// the fix they all pass and act as a regression guard.
// ---------------------------------------------------------------------------

describe("quarkHash correctness", () => {
  test("different 1-byte inputs produce different hashes", () => {
    const a = bytesToHex(quarkHash(new Uint8Array([0x00])));
    const b = bytesToHex(quarkHash(new Uint8Array([0x01])));
    const c = bytesToHex(quarkHash(new Uint8Array([0xff])));
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
    expect(b).not.toBe(c);
  });

  test("empty input and a 1-byte input produce different hashes", () => {
    const empty = bytesToHex(quarkHash(new Uint8Array(0)));
    const one = bytesToHex(quarkHash(new Uint8Array([0x42])));
    expect(empty).not.toBe(one);
  });

  test("different block headers produce different hashes", () => {
    const a: BlockHeader = {
      version: 1,
      prevHash: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 1000,
      bits: 0x1e0ffff0,
      nonce: 1,
    };
    const b: BlockHeader = { ...a, nonce: 2 };
    expect(bytesToHex(hashBlockHeader(a))).not.toBe(
      bytesToHex(hashBlockHeader(b)),
    );
  });
});

// ---------------------------------------------------------------------------
// quarkHash — reference block ids (the real acceptance test)
//
// hashBlockHeader() must reproduce actual FairCoin mainnet block hashes. This
// only passes if BLAKE/BMW/Groestl/JH/Keccak/Skein AND the conditional Quark
// routing are all byte-exact against the C reference. Hashes fetched from
// explorer.fairco.in; header fields are the canonical (display) hex, reversed
// to internal byte order for prevHash/merkleRoot.
// ---------------------------------------------------------------------------

describe("quarkHash reference block ids", () => {
  const reverse = (b: Uint8Array): Uint8Array => b.slice().reverse();
  const realBlocks: ReadonlyArray<{
    id: string;
    version: number;
    prev: string;
    merkle: string;
    time: number;
    bits: number;
    nonce: number;
  }> = [
    { id: "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6", version: 1, prev: "0000000000000000000000000000000000000000000000000000000000000000", merkle: "9645f9761cc7212b2c8c79bcb2713a10d6e54623b24a8425b7bef2f16200a863", time: 1744156800, bits: 0x1e0ffff0, nonce: 1299007 },
    { id: "00000c7be1164f34a243d233c94ec23e6fdc76813ac94b720a624d4ed52c9f0c", version: 3, prev: "00000232cb134567cf85cd65748714df75d72fe4ce71cf77d3c3f8a9a1a576e6", merkle: "8f3627a4d4d2b331093af4a98950a34ce176ee15616faa8d6e8a17375b96a03a", time: 1775716724, bits: 0x1e0fffff, nonce: 176 },
    { id: "00000249d1a699df65c397d848a7c71932243fc94463256e9bb3fe290985335b", version: 3, prev: "00000c7be1164f34a243d233c94ec23e6fdc76813ac94b720a624d4ed52c9f0c", merkle: "745c590e9aa96f20633f606aa6e682f76b406096a4c967b575a6ba73b891eea9", time: 1775716725, bits: 0x1e0fffff, nonce: 160 },
    { id: "4ebe8bf5fa04f9e8143ec441f84eb9cea482693ec7a54cd18d66b9b5d925232b", version: 3, prev: "193c40867eba6f4b19ce06fa3dc2c1da6164ea45a6145ce70295abe74192f5f9", merkle: "f9aee8962cb5ac61ed682f9a7ecbfabb99c0ac52c74be30d7a909e203897e698", time: 1784145480, bits: 0x1b0c07bb, nonce: 0 },
  ];

  for (const b of realBlocks) {
    test(`block ${b.id.slice(0, 12)}… hashes correctly`, () => {
      const internal = hashBlockHeader({
        version: b.version,
        prevHash: reverse(hexToBytes(b.prev)),
        merkleRoot: reverse(hexToBytes(b.merkle)),
        timestamp: b.time,
        bits: b.bits,
        nonce: b.nonce,
      });
      expect(bytesToHex(reverse(internal))).toBe(b.id);
    });
  }
});

// ---------------------------------------------------------------------------
// hashBlockHeader
// ---------------------------------------------------------------------------

describe("hashBlockHeader", () => {
  test("returns 32 bytes", () => {
    const header: BlockHeader = {
      version: 1,
      prevHash: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 0,
      bits: 0,
      nonce: 0,
    };
    expect(hashBlockHeader(header).length).toBe(32);
  });

  test("serialises then hashes", () => {
    const header: BlockHeader = {
      version: 1,
      prevHash: new Uint8Array(32),
      merkleRoot: new Uint8Array(32),
      timestamp: 12345,
      bits: 0x1d00ffff,
      nonce: 42,
    };
    const direct = hashBlockHeader(header);
    const viaSerialize = quarkHash(serializeBlockHeader(header));
    expect(bytesToHex(direct)).toBe(bytesToHex(viaSerialize));
  });
});
