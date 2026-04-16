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
 * NOTE: Quark also chains custom implementations of BMW-512, Groestl-512,
 * JH-512, Skein-512, and Keccak-512. Only Keccak is vendored from
 * @noble/hashes; the rest are pure-TS ports that have not been verified
 * against the reference C implementation. These tests prove that the
 * algorithm is input-sensitive and data-deterministic, but they do NOT
 * prove the output matches the FairCoin C reference. See SPV_AUDIT.md.
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
