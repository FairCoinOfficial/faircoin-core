/**
 * Quark hash algorithm — 9-round multi-hash used for FairCoin block headers.
 *
 * The Quark algorithm chains six different 512-bit hash functions with
 * conditional branches based on bit tests of intermediate results.
 *
 * From FairCoin's hash.h:
 *  1. BLAKE-512(input)  -> h1
 *  2. BMW-512(h1)       -> h2
 *  3. if (h2[0] & 8): Groestl-512(h2)  else: Skein-512(h2) -> h3
 *  4. Groestl-512(h3)   -> h4
 *  5. JH-512(h4)        -> h5
 *  6. if (h5[0] & 8): BLAKE-512(h5)    else: BMW-512(h5)   -> h6
 *  7. Keccak-512(h6)    -> h7
 *  8. Skein-512(h7)     -> h8
 *  9. if (h8[0] & 8): Keccak-512(h8)   else: JH-512(h8)   -> h9
 * 10. Return first 32 bytes of h9
 *
 * All SPH hash functions implemented in pure TypeScript using BigInt
 * for 64-bit arithmetic.
 *
 * License: MIT (SPH reference implementations by Thomas Pornin,
 * Projet RNRT SAPHIR)
 */

import { blake512 as nobleBlake512 } from "@noble/hashes/blake1";
import { keccak_512 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha256";
import { BufferWriter } from "./encoding.js";

// ---------------------------------------------------------------------------
// Block header
// ---------------------------------------------------------------------------

export interface BlockHeader {
  /** Block version (int32). */
  version: number;
  /** Previous block hash (32 bytes, internal byte order). */
  prevHash: Uint8Array;
  /** Merkle root (32 bytes, internal byte order). */
  merkleRoot: Uint8Array;
  /** Block timestamp (uint32, seconds since epoch). */
  timestamp: number;
  /** Compact difficulty target (uint32). */
  bits: number;
  /** Nonce (uint32). */
  nonce: number;
}

/**
 * Serialize a block header to 80 bytes (standard Bitcoin header format).
 */
export function serializeBlockHeader(header: BlockHeader): Uint8Array {
  if (header.prevHash.length !== 32) {
    throw new Error(
      `prevHash must be 32 bytes, got ${header.prevHash.length}`,
    );
  }
  if (header.merkleRoot.length !== 32) {
    throw new Error(
      `merkleRoot must be 32 bytes, got ${header.merkleRoot.length}`,
    );
  }

  const writer = new BufferWriter(80);
  writer.writeInt32LE(header.version);
  writer.writeBytes(header.prevHash);
  writer.writeBytes(header.merkleRoot);
  writer.writeUInt32LE(header.timestamp);
  writer.writeUInt32LE(header.bits);
  writer.writeUInt32LE(header.nonce);
  return writer.toBytes();
}

// ---------------------------------------------------------------------------
// 64-bit arithmetic helpers (all operations mod 2^64 via BigInt masking)
// ---------------------------------------------------------------------------

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

function t64(x: bigint): bigint {
  return x & MASK64;
}

function rotl64(x: bigint, n: number): bigint {
  const nn = BigInt(n);
  return t64((x << nn) | (x >> (64n - nn)));
}

function rotr64(x: bigint, n: number): bigint {
  const nn = BigInt(n);
  return t64((x >> nn) | (x << (64n - nn)));
}

/** Read a 64-bit big-endian value from bytes at offset */
function readBE64(buf: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v = (v << 8n) | BigInt(buf[off + i]);
  }
  return v;
}

/** Write a 64-bit big-endian value to bytes at offset */
function writeBE64(buf: Uint8Array, off: number, val: bigint): void {
  const v = t64(val);
  buf[off + 0] = Number((v >> 56n) & 0xFFn);
  buf[off + 1] = Number((v >> 48n) & 0xFFn);
  buf[off + 2] = Number((v >> 40n) & 0xFFn);
  buf[off + 3] = Number((v >> 32n) & 0xFFn);
  buf[off + 4] = Number((v >> 24n) & 0xFFn);
  buf[off + 5] = Number((v >> 16n) & 0xFFn);
  buf[off + 6] = Number((v >> 8n) & 0xFFn);
  buf[off + 7] = Number(v & 0xFFn);
}

/** Read a 64-bit little-endian value from bytes at offset */
function readLE64(buf: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[off + i]);
  }
  return v;
}

/** Write a 64-bit little-endian value to bytes at offset */
function writeLE64(buf: Uint8Array, off: number, val: bigint): void {
  const v = t64(val);
  for (let i = 0; i < 8; i++) {
    buf[off + i] = Number((v >> BigInt(i * 8)) & 0xFFn);
  }
}

// ===========================================================================
// BLAKE-512
// ===========================================================================

const BLAKE512_IV: readonly bigint[] = [
  0x6A09E667F3BCC908n, 0xBB67AE8584CAA73Bn,
  0x3C6EF372FE94F82Bn, 0xA54FF53A5F1D36F1n,
  0x510E527FADE682D1n, 0x9B05688C2B3E6C1Fn,
  0x1F83D9ABFB41BD6Bn, 0x5BE0CD19137E2179n,
];

const BLAKE512_CB: readonly bigint[] = [
  0x243F6A8885A308D3n, 0x13198A2E03707344n,
  0xA4093822299F31D0n, 0x082EFA98EC4E6C89n,
  0x452821E638D01377n, 0xBE5466CF34E90C6Cn,
  0xC0AC29B7C97C50DDn, 0x3F84D5B5B5470917n,
  0x9216D5D98979FB1Bn, 0xD1310BA698DFB5ACn,
  0x2FFD72DBD01ADFB7n, 0xB8E1AFED6A267E96n,
  0xBA7C9045F12C7F99n, 0x24A19947B3916CF7n,
  0x0801F2E2858EFC16n, 0x636920D871574E69n,
];

const BLAKE512_SIGMA: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
];

function blake512Compress(
  h: bigint[],
  m: bigint[],
  s: bigint[],
  t0: bigint,
  t1: bigint,
): void {
  const v = new Array<bigint>(16);
  v[0] = h[0]; v[1] = h[1]; v[2] = h[2]; v[3] = h[3];
  v[4] = h[4]; v[5] = h[5]; v[6] = h[6]; v[7] = h[7];
  v[8] = s[0] ^ BLAKE512_CB[0];
  v[9] = s[1] ^ BLAKE512_CB[1];
  v[10] = s[2] ^ BLAKE512_CB[2];
  v[11] = s[3] ^ BLAKE512_CB[3];
  v[12] = t0 ^ BLAKE512_CB[4];
  v[13] = t0 ^ BLAKE512_CB[5];
  v[14] = t1 ^ BLAKE512_CB[6];
  v[15] = t1 ^ BLAKE512_CB[7];

  function gb(
    a: number, b: number, c: number, d: number,
    m0: bigint, m1: bigint, c0: bigint, c1: bigint,
  ): void {
    v[a] = t64(v[a] + v[b] + (m0 ^ c1));
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = t64(v[c] + v[d]);
    v[b] = rotr64(v[b] ^ v[c], 25);
    v[a] = t64(v[a] + v[b] + (m1 ^ c0));
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = t64(v[c] + v[d]);
    v[b] = rotr64(v[b] ^ v[c], 11);
  }

  for (let r = 0; r < 16; r++) {
    const sig = BLAKE512_SIGMA[r];
    gb(0, 4, 8, 12, m[sig[0]], m[sig[1]], BLAKE512_CB[sig[0]], BLAKE512_CB[sig[1]]);
    gb(1, 5, 9, 13, m[sig[2]], m[sig[3]], BLAKE512_CB[sig[2]], BLAKE512_CB[sig[3]]);
    gb(2, 6, 10, 14, m[sig[4]], m[sig[5]], BLAKE512_CB[sig[4]], BLAKE512_CB[sig[5]]);
    gb(3, 7, 11, 15, m[sig[6]], m[sig[7]], BLAKE512_CB[sig[6]], BLAKE512_CB[sig[7]]);
    gb(0, 5, 10, 15, m[sig[8]], m[sig[9]], BLAKE512_CB[sig[8]], BLAKE512_CB[sig[9]]);
    gb(1, 6, 11, 12, m[sig[10]], m[sig[11]], BLAKE512_CB[sig[10]], BLAKE512_CB[sig[11]]);
    gb(2, 7, 8, 13, m[sig[12]], m[sig[13]], BLAKE512_CB[sig[12]], BLAKE512_CB[sig[13]]);
    gb(3, 4, 9, 14, m[sig[14]], m[sig[15]], BLAKE512_CB[sig[14]], BLAKE512_CB[sig[15]]);
  }

  for (let i = 0; i < 8; i++) {
    h[i] ^= s[i & 3] ^ v[i] ^ v[i + 8];
  }
}

/**
 * BLAKE-512 hash — thin wrapper around @noble/hashes/blake1 `blake512`.
 *
 * NOTE: the pure-TS implementation that previously lived here was broken:
 * for many input lengths (including the 80-byte block header) it collapsed
 * to a constant value, making Quark hash not actually depend on the block
 * header content. The original implementation is preserved below as
 * `_legacyBlake512Broken` for reference but is no longer used.
 */
function blake512(data: Uint8Array): Uint8Array {
  return nobleBlake512(data);
}

function _legacyBlake512Broken(data: Uint8Array): Uint8Array {
  const h = [...BLAKE512_IV];
  const s = [0n, 0n, 0n, 0n];
  let t0 = 0n;
  let t1 = 0n;

  const buf = new Uint8Array(128);
  let ptr = 0;
  let remaining = data.length;
  let dataOff = 0;

  // Process full blocks
  while (remaining > 0) {
    const clen = Math.min(128 - ptr, remaining);
    buf.set(data.subarray(dataOff, dataOff + clen), ptr);
    ptr += clen;
    dataOff += clen;
    remaining -= clen;

    if (ptr === 128) {
      t0 = t64(t0 + 1024n);
      if (t0 < 1024n) {
        t1 = t64(t1 + 1n);
      }
      const m = new Array<bigint>(16);
      for (let i = 0; i < 16; i++) {
        m[i] = readBE64(buf, i * 8);
      }
      blake512Compress(h, m, s, t0, t1);
      ptr = 0;
    }
  }

  // Finalization (close)
  const tl = t64(t0 + BigInt(ptr * 8));
  const th = t1;

  if (ptr === 0) {
    t0 = 0xFFFFFFFFFFFFFC00n;
    t1 = 0xFFFFFFFFFFFFFFFFn;
  } else if (t0 === 0n) {
    t0 = t64(0xFFFFFFFFFFFFFC00n + BigInt(ptr * 8));
    t1 = t64(t1 - 1n);
  } else {
    t0 = t64(t0 - BigInt(1024 - ptr * 8));
  }

  const pad = new Uint8Array(128);
  pad[ptr] = 0x80;
  // Fill zeros from ptr+1 to end

  if (ptr * 8 <= 894) {
    // Fits in one block
    for (let i = ptr + 1; i < 111; i++) {
      pad[i] = 0;
    }
    pad[111] |= 0x01; // out_size_w64 == 8 flag
    writeBE64(pad, 112, th);
    writeBE64(pad, 120, tl);

    // Process this final padding as one block
    const m = new Array<bigint>(16);
    for (let i = 0; i < 16; i++) {
      m[i] = readBE64(pad, i * 8);
    }
    blake512Compress(h, m, s, t0, t1);
  } else {
    // Need two blocks
    for (let i = ptr + 1; i < 128; i++) {
      pad[i] = 0;
    }
    const m1 = new Array<bigint>(16);
    for (let i = 0; i < 16; i++) {
      m1[i] = readBE64(pad, i * 8);
    }
    blake512Compress(h, m1, s, t0, t1);

    t0 = 0xFFFFFFFFFFFFFC00n;
    t1 = 0xFFFFFFFFFFFFFFFFn;

    const pad2 = new Uint8Array(128);
    pad2[111] = 0x01;
    writeBE64(pad2, 112, th);
    writeBE64(pad2, 120, tl);
    const m2 = new Array<bigint>(16);
    for (let i = 0; i < 16; i++) {
      m2[i] = readBE64(pad2, i * 8);
    }
    blake512Compress(h, m2, s, t0, t1);
  }

  const out = new Uint8Array(64);
  for (let k = 0; k < 8; k++) {
    writeBE64(out, k * 8, h[k]);
  }
  return out;
}

// ===========================================================================
// BMW-512 (Blue Midnight Wish)
// ===========================================================================

const BMW512_IV: readonly bigint[] = [
  0x8081828384858687n, 0x88898A8B8C8D8E8Fn,
  0x9091929394959697n, 0x98999A9B9C9D9E9Fn,
  0xA0A1A2A3A4A5A6A7n, 0xA8A9AAABACADAEAFn,
  0xB0B1B2B3B4B5B6B7n, 0xB8B9BABBBCBDBEBFn,
  0xC0C1C2C3C4C5C6C7n, 0xC8C9CACBCCCDCECFn,
  0xD0D1D2D3D4D5D6D7n, 0xD8D9DADBDCDDDEDFn,
  0xE0E1E2E3E4E5E6E7n, 0xE8E9EAEBECEDEEEFn,
  0xF0F1F2F3F4F5F6F7n, 0xF8F9FAFBFCFDFEFFn,
];

const BMW512_FINAL: readonly bigint[] = [
  0xAAAAAAAAAAAAAAA0n, 0xAAAAAAAAAAAAAAA1n,
  0xAAAAAAAAAAAAAAA2n, 0xAAAAAAAAAAAAAAA3n,
  0xAAAAAAAAAAAAAAA4n, 0xAAAAAAAAAAAAAAA5n,
  0xAAAAAAAAAAAAAAA6n, 0xAAAAAAAAAAAAAAA7n,
  0xAAAAAAAAAAAAAAA8n, 0xAAAAAAAAAAAAAAA9n,
  0xAAAAAAAAAAAAAAAAn, 0xAAAAAAAAAAAAAAABn,
  0xAAAAAAAAAAAAAAACn, 0xAAAAAAAAAAAAAAADn,
  0xAAAAAAAAAAAAAAAEn, 0xAAAAAAAAAAAAAAAFn,
];

function sb0(x: bigint): bigint {
  return t64((x >> 1n) ^ (x << 3n) ^ rotl64(x, 4) ^ rotl64(x, 37));
}
function sb1(x: bigint): bigint {
  return t64((x >> 1n) ^ (x << 2n) ^ rotl64(x, 13) ^ rotl64(x, 43));
}
function sb2(x: bigint): bigint {
  return t64((x >> 2n) ^ (x << 1n) ^ rotl64(x, 19) ^ rotl64(x, 53));
}
function sb3(x: bigint): bigint {
  return t64((x >> 2n) ^ (x << 2n) ^ rotl64(x, 28) ^ rotl64(x, 59));
}
function sb4(x: bigint): bigint {
  return t64((x >> 1n) ^ x);
}
function sb5(x: bigint): bigint {
  return t64((x >> 2n) ^ x);
}

function rb1(x: bigint): bigint { return rotl64(x, 5); }
function rb2(x: bigint): bigint { return rotl64(x, 11); }
function rb3(x: bigint): bigint { return rotl64(x, 27); }
function rb4(x: bigint): bigint { return rotl64(x, 32); }
function rb5(x: bigint): bigint { return rotl64(x, 37); }
function rb6(x: bigint): bigint { return rotl64(x, 43); }
function rb7(x: bigint): bigint { return rotl64(x, 53); }

function bmw512CompressBig(
  data: Uint8Array,
  hIn: readonly bigint[],
  dh: bigint[],
): void {
  const mv = new Array<bigint>(16);
  for (let i = 0; i < 16; i++) {
    mv[i] = readLE64(data, i * 8);
  }

  function M(x: number): bigint { return mv[x]; }
  function H(x: number): bigint { return hIn[x]; }

  // Compute W values
  const w = new Array<bigint>(16);
  w[0]  = t64((M(5) ^ H(5)) - (M(7) ^ H(7)) + (M(10) ^ H(10)) + (M(13) ^ H(13)) + (M(14) ^ H(14)));
  w[1]  = t64((M(6) ^ H(6)) - (M(8) ^ H(8)) + (M(11) ^ H(11)) + (M(14) ^ H(14)) - (M(15) ^ H(15)));
  w[2]  = t64((M(0) ^ H(0)) + (M(7) ^ H(7)) + (M(9) ^ H(9)) - (M(12) ^ H(12)) + (M(15) ^ H(15)));
  w[3]  = t64((M(0) ^ H(0)) - (M(1) ^ H(1)) + (M(8) ^ H(8)) - (M(10) ^ H(10)) + (M(13) ^ H(13)));
  w[4]  = t64((M(1) ^ H(1)) + (M(2) ^ H(2)) + (M(9) ^ H(9)) - (M(11) ^ H(11)) - (M(14) ^ H(14)));
  w[5]  = t64((M(3) ^ H(3)) - (M(2) ^ H(2)) + (M(10) ^ H(10)) - (M(12) ^ H(12)) + (M(15) ^ H(15)));
  w[6]  = t64((M(4) ^ H(4)) - (M(0) ^ H(0)) - (M(3) ^ H(3)) - (M(11) ^ H(11)) + (M(13) ^ H(13)));
  w[7]  = t64((M(1) ^ H(1)) - (M(4) ^ H(4)) - (M(5) ^ H(5)) - (M(12) ^ H(12)) - (M(14) ^ H(14)));
  w[8]  = t64((M(2) ^ H(2)) - (M(5) ^ H(5)) - (M(6) ^ H(6)) + (M(13) ^ H(13)) - (M(15) ^ H(15)));
  w[9]  = t64((M(0) ^ H(0)) - (M(3) ^ H(3)) + (M(6) ^ H(6)) - (M(7) ^ H(7)) + (M(14) ^ H(14)));
  w[10] = t64((M(8) ^ H(8)) - (M(1) ^ H(1)) - (M(4) ^ H(4)) - (M(7) ^ H(7)) + (M(15) ^ H(15)));
  w[11] = t64((M(8) ^ H(8)) - (M(0) ^ H(0)) - (M(2) ^ H(2)) - (M(5) ^ H(5)) + (M(9) ^ H(9)));
  w[12] = t64((M(1) ^ H(1)) + (M(3) ^ H(3)) - (M(6) ^ H(6)) - (M(9) ^ H(9)) + (M(10) ^ H(10)));
  w[13] = t64((M(2) ^ H(2)) + (M(4) ^ H(4)) + (M(7) ^ H(7)) + (M(10) ^ H(10)) + (M(11) ^ H(11)));
  w[14] = t64((M(3) ^ H(3)) - (M(5) ^ H(5)) + (M(8) ^ H(8)) - (M(11) ^ H(11)) - (M(12) ^ H(12)));
  w[15] = t64((M(12) ^ H(12)) - (M(4) ^ H(4)) - (M(6) ^ H(6)) - (M(9) ^ H(9)) + (M(13) ^ H(13)));

  // Compute Q[0..15] using sb functions
  const qt = new Array<bigint>(32);
  const sbFuncs = [sb0, sb1, sb2, sb3, sb4, sb0, sb1, sb2, sb3, sb4, sb0, sb1, sb2, sb3, sb4, sb0];
  const hOff = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0];
  for (let i = 0; i < 16; i++) {
    qt[i] = t64(sbFuncs[i](w[i]) + H(hOff[i]));
  }

  // Kb(j) = j * 0x0555555555555555
  function Kb(j: number): bigint {
    return t64(BigInt(j) * 0x0555555555555555n);
  }

  // add_elt_b for expand
  // The index mapping for M16_16..M16_31 and I16_16..I16_31
  const I16: readonly (readonly number[])[] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],     // 16
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],     // 17
    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],     // 18
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],     // 19
    [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],     // 20
    [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],     // 21
    [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],     // 22
    [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22],     // 23
    [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],     // 24
    [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],   // 25
    [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],   // 26
    [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26],   // 27
    [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27],   // 28
    [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28],   // 29
    [14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29],   // 30
    [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30],   // 31
  ];

  // add_elt_b(j) from the SPH reference, computed directly from the expansion
  // index so there is no lookup table to get out of sync:
  //   rol_off(off) = ROTL64( M[(j+off) & 15], ((j+off) & 15) + 1 )
  //   add_elt_b(j) = ( rol_off(0) + rol_off(3) - rol_off(10) + Kb(j+16) ) ^ H[(j+7) & 15]
  // The rotation amount is ((j+off) & 15) + 1, which reaches 16 on the wrap
  // rows (a rotate-by-16, NOT by 0) — the reason a mod-16 lookup table was
  // wrong. `j16` is the qt index (16..31); the reference `j` is `j16 - 16`.
  function addEltB(j16: number): bigint {
    const j = j16 - 16;
    const m0 = (j + 0) & 15;
    const m3 = (j + 3) & 15;
    const m10 = (j + 10) & 15;
    const h7 = (j + 7) & 15;
    return t64(
      t64(
        rotl64(M(m0), m0 + 1)
        + rotl64(M(m3), m3 + 1)
        - rotl64(M(m10), m10 + 1)
        + Kb(j16),
      ) ^ H(h7),
    );
  }

  function Qb(j: number): bigint { return qt[j]; }

  // Expand1 for Q[16..17]
  for (let j16 = 16; j16 <= 17; j16++) {
    const idx = j16 - 16;
    const ii = I16[idx];
    qt[j16] = t64(
      sb1(Qb(ii[0])) + sb2(Qb(ii[1])) + sb3(Qb(ii[2])) + sb0(Qb(ii[3]))
      + sb1(Qb(ii[4])) + sb2(Qb(ii[5])) + sb3(Qb(ii[6])) + sb0(Qb(ii[7]))
      + sb1(Qb(ii[8])) + sb2(Qb(ii[9])) + sb3(Qb(ii[10])) + sb0(Qb(ii[11]))
      + sb1(Qb(ii[12])) + sb2(Qb(ii[13])) + sb3(Qb(ii[14])) + sb0(Qb(ii[15]))
      + addEltB(j16),
    );
  }

  // Expand2 for Q[18..31]
  for (let j16 = 18; j16 <= 31; j16++) {
    const idx = j16 - 16;
    const ii = I16[idx];
    qt[j16] = t64(
      Qb(ii[0]) + rb1(Qb(ii[1])) + Qb(ii[2]) + rb2(Qb(ii[3]))
      + Qb(ii[4]) + rb3(Qb(ii[5])) + Qb(ii[6]) + rb4(Qb(ii[7]))
      + Qb(ii[8]) + rb5(Qb(ii[9])) + Qb(ii[10]) + rb6(Qb(ii[11]))
      + Qb(ii[12]) + rb7(Qb(ii[13])) + sb4(Qb(ii[14])) + sb5(Qb(ii[15]))
      + addEltB(j16),
    );
  }

  // FOLD
  let xl = t64(qt[16] ^ qt[17] ^ qt[18] ^ qt[19] ^ qt[20] ^ qt[21] ^ qt[22] ^ qt[23]);
  const xh = t64(xl ^ qt[24] ^ qt[25] ^ qt[26] ^ qt[27] ^ qt[28] ^ qt[29] ^ qt[30] ^ qt[31]);

  dh[0] = t64(((xh << 5n) ^ (qt[16] >> 5n) ^ M(0)) + (xl ^ qt[24] ^ qt[0]));
  dh[1] = t64(((xh >> 7n) ^ (qt[17] << 8n) ^ M(1)) + (xl ^ qt[25] ^ qt[1]));
  dh[2] = t64(((xh >> 5n) ^ (qt[18] << 5n) ^ M(2)) + (xl ^ qt[26] ^ qt[2]));
  dh[3] = t64(((xh >> 1n) ^ (qt[19] << 5n) ^ M(3)) + (xl ^ qt[27] ^ qt[3]));
  dh[4] = t64(((xh >> 3n) ^ (qt[20]) ^ M(4)) + (xl ^ qt[28] ^ qt[4]));
  dh[5] = t64(((xh << 6n) ^ (qt[21] >> 6n) ^ M(5)) + (xl ^ qt[29] ^ qt[5]));
  dh[6] = t64(((xh >> 4n) ^ (qt[22] << 6n) ^ M(6)) + (xl ^ qt[30] ^ qt[6]));
  dh[7] = t64(((xh >> 11n) ^ (qt[23] << 2n) ^ M(7)) + (xl ^ qt[31] ^ qt[7]));

  dh[8] = t64(rotl64(dh[4], 9) + (xh ^ qt[24] ^ M(8)) + ((xl << 8n) ^ qt[23] ^ qt[8]));
  dh[9] = t64(rotl64(dh[5], 10) + (xh ^ qt[25] ^ M(9)) + ((xl >> 6n) ^ qt[16] ^ qt[9]));
  dh[10] = t64(rotl64(dh[6], 11) + (xh ^ qt[26] ^ M(10)) + ((xl << 6n) ^ qt[17] ^ qt[10]));
  dh[11] = t64(rotl64(dh[7], 12) + (xh ^ qt[27] ^ M(11)) + ((xl << 4n) ^ qt[18] ^ qt[11]));
  dh[12] = t64(rotl64(dh[0], 13) + (xh ^ qt[28] ^ M(12)) + ((xl >> 3n) ^ qt[19] ^ qt[12]));
  dh[13] = t64(rotl64(dh[1], 14) + (xh ^ qt[29] ^ M(13)) + ((xl >> 4n) ^ qt[20] ^ qt[13]));
  dh[14] = t64(rotl64(dh[2], 15) + (xh ^ qt[30] ^ M(14)) + ((xl >> 7n) ^ qt[21] ^ qt[14]));
  dh[15] = t64(rotl64(dh[3], 16) + (xh ^ qt[31] ^ M(15)) + ((xl >> 2n) ^ qt[22] ^ qt[15]));
}

function bmw512(data: Uint8Array): Uint8Array {
  const h = [...BMW512_IV];
  let bitCount = 0n;
  const buf = new Uint8Array(128);
  let ptr = 0;

  bitCount = BigInt(data.length) << 3n;

  const htmp = new Array<bigint>(16);
  let h1 = h;
  let h2 = htmp;
  let dataOff = 0;
  let remaining = data.length;

  while (remaining > 0) {
    const clen = Math.min(128 - ptr, remaining);
    buf.set(data.subarray(dataOff, dataOff + clen), ptr);
    dataOff += clen;
    remaining -= clen;
    ptr += clen;
    if (ptr === 128) {
      bmw512CompressBig(buf, h1, h2);
      const tmp = h1;
      h1 = h2;
      h2 = tmp;
      ptr = 0;
    }
  }

  if (h1 !== h) {
    for (let i = 0; i < 16; i++) {
      h[i] = h1[i];
    }
  }

  // Close
  const closeBuf = new Uint8Array(128);
  closeBuf.set(buf.subarray(0, ptr));
  closeBuf[ptr] = 0x80;
  ptr++;

  let hPtr = h;
  const h1c = new Array<bigint>(16);
  const h2c = new Array<bigint>(16);

  if (ptr > 128 - 8) {
    for (let i = ptr; i < 128; i++) closeBuf[i] = 0;
    bmw512CompressBig(closeBuf, hPtr, h1c);
    ptr = 0;
    hPtr = h1c;
    closeBuf.fill(0);
  } else {
    for (let i = ptr; i < 128 - 8; i++) closeBuf[i] = 0;
  }

  // Write bit count in LE at position 120
  writeLE64(closeBuf, 120, t64(bitCount));
  bmw512CompressBig(closeBuf, hPtr, h2c);

  // Second compression with final constant
  const finalBuf = new Uint8Array(128);
  for (let u = 0; u < 16; u++) {
    writeLE64(finalBuf, u * 8, h2c[u]);
  }
  bmw512CompressBig(finalBuf, BMW512_FINAL, h1c);

  // Output last 8 words (indices 8..15)
  const out = new Uint8Array(64);
  for (let u = 0; u < 8; u++) {
    writeLE64(out, u * 8, h1c[u + 8]);
  }
  return out;
}

// ===========================================================================
// Groestl-512
// ===========================================================================

// Groestl uses AES-based S-box and MDS operations. We use the T-table approach
// from the SPH reference, but with a big-endian internal representation since
// we can't easily detect endianness. We store the T-tables as big-endian.

const GROESTL_T0 = buildGroestlTable();

function buildGroestlTable(): bigint[] {
  // AES S-box
  const SBOX: readonly number[] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];

  // GF(256) multiplication
  function gfMul(a: number, b: number): number {
    let r = 0;
    let aa = a;
    let bb = b;
    while (bb > 0) {
      if (bb & 1) r ^= aa;
      aa <<= 1;
      if (aa & 0x100) aa ^= 0x11b;
      bb >>= 1;
    }
    return r;
  }

  // Build the SPH `T0` table exactly as the reference groestl.c (SPH_GROESTL_64
  // path). The MixBytes column, in MSB..LSB byte order, is [2,7,5,3,5,4,3,2] of
  // S(x) — NOT [2,2,3,4,5,3,5,7]. This is the byte order that pairs with the
  // ROTR-based row combine below; e.g. T0[0x00] == 0xc632f4a5f497a5c6.
  const table = new Array<bigint>(256);
  for (let x = 0; x < 256; x++) {
    const s = SBOX[x];
    const b0 = gfMul(s, 2);
    const b1 = gfMul(s, 7);
    const b2 = gfMul(s, 5);
    const b3 = gfMul(s, 3);
    const b4 = gfMul(s, 5);
    const b5 = gfMul(s, 4);
    const b6 = gfMul(s, 3);
    const b7 = gfMul(s, 2);
    table[x] = (BigInt(b0) << 56n) | (BigInt(b1) << 48n) | (BigInt(b2) << 40n)
             | (BigInt(b3) << 32n) | (BigInt(b4) << 24n) | (BigInt(b5) << 16n)
             | (BigInt(b6) << 8n)  | BigInt(b7);
  }
  return table;
}

function groestlRound(
  state: bigint[],
  numCols: number,
  isP: boolean,
  roundNum: number,
): void {
  const temp = new Array<bigint>(numCols);

  // AddRoundConstant
  for (let i = 0; i < numCols; i++) {
    if (isP) {
      // PC64(j, r) = ((j) + (r)) << 56 — column constant j = i*0x10 in the MSB
      // (row 0), matching the reference SPH_GROESTL_64 path.
      state[i] ^= BigInt((i << 4) + roundNum) << 56n;
    } else {
      // QC64(j, r) = r ^ ~j (full 64-bit, NOT shifted): every byte is 0xff
      // except the LSB (row 7), which holds 0xff ^ (i*0x10) ^ r. The previous
      // code placed the column/round bits in the MSB, which is wrong.
      state[i] ^= t64(0xFFFFFFFFFFFFFFFFn ^ BigInt(i << 4)) ^ BigInt(roundNum);
    }
  }

  // SubBytes + ShiftBytes + MixBytes combined via T-tables
  // For Groestl-512 (wide variant), numCols = 16, shift offsets differ for P and Q
  const shiftP = [0, 1, 2, 3, 4, 5, 6, 11];
  const shiftQ = [1, 3, 5, 11, 0, 2, 4, 6];
  const shifts = isP ? shiftP : shiftQ;

  for (let col = 0; col < numCols; col++) {
    let val = 0n;
    for (let row = 0; row < 8; row++) {
      const srcCol = (col + shifts[row]) % numCols;
      const byteVal = Number((state[srcCol] >> BigInt((7 - row) * 8)) & 0xFFn);
      const tval = GROESTL_T0[byteVal];
      // Reference RBTT uses R64 = SPH_ROTR64 (rows 0..3 from T0, rows 4..7 from
      // T4 = ROTR(T0,32)); with a single T0 that is ROTR by row*8. Must be ROTR,
      // not ROTL — the two are not equivalent for this reflected T0 layout.
      val ^= rotr64(tval, row * 8);
    }
    temp[col] = t64(val);
  }

  for (let i = 0; i < numCols; i++) {
    state[i] = temp[i];
  }
}

function groestl512(data: Uint8Array): Uint8Array {
  const NUM_COLS = 16;
  const BLOCK_SIZE = 128; // 1024 bits for 512-bit variant
  const NUM_ROUNDS = 14;

  // Initialize state: the last column holds the output size (512) as a plain
  // big-endian 64-bit integer — reference `state.wide[15] = out_size` — i.e.
  // 0x0000000000000200, NOT 512 << 56. (The value sits in the LSBs.)
  const hState = new Array<bigint>(NUM_COLS).fill(0n);
  hState[NUM_COLS - 1] = 512n;

  let blockCount = 0n;

  // Pad message
  const msgLen = data.length;

  // Compute padded length: msg + 1 byte (0x80) + zeros + 8 bytes (block count)
  let paddedLen = msgLen + 1;
  while (paddedLen % BLOCK_SIZE !== (BLOCK_SIZE - 8)) {
    paddedLen++;
  }
  paddedLen += 8;

  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  // block count = number of message blocks including padding
  const numBlocks = BigInt(paddedLen / BLOCK_SIZE);
  // Write block count as big-endian 64-bit at end
  writeBE64(padded, paddedLen - 8, numBlocks);

  // Process all blocks
  for (let off = 0; off < paddedLen; off += BLOCK_SIZE) {
    blockCount++;

    // Read message block as columns (big-endian)
    const mBlock = new Array<bigint>(NUM_COLS);
    for (let i = 0; i < NUM_COLS; i++) {
      mBlock[i] = readBE64(padded, off + i * 8);
    }

    // Compute P(H ^ M) and Q(M)
    const pState = new Array<bigint>(NUM_COLS);
    const qState = new Array<bigint>(NUM_COLS);
    for (let i = 0; i < NUM_COLS; i++) {
      pState[i] = hState[i] ^ mBlock[i];
      qState[i] = mBlock[i];
    }

    for (let r = 0; r < NUM_ROUNDS; r++) {
      groestlRound(pState, NUM_COLS, true, r);
      groestlRound(qState, NUM_COLS, false, r);
    }

    // H = P(H^M) ^ Q(M) ^ H
    for (let i = 0; i < NUM_COLS; i++) {
      hState[i] ^= pState[i] ^ qState[i];
    }
  }

  // Output transformation: Omega(H) = P(H) ^ H
  const omegaState = new Array<bigint>(NUM_COLS);
  for (let i = 0; i < NUM_COLS; i++) {
    omegaState[i] = hState[i];
  }
  for (let r = 0; r < NUM_ROUNDS; r++) {
    groestlRound(omegaState, NUM_COLS, true, r);
  }
  for (let i = 0; i < NUM_COLS; i++) {
    omegaState[i] ^= hState[i];
  }

  // Extract last 64 bytes (last 8 columns, big-endian)
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    writeBE64(out, i * 8, omegaState[i + 8]);
  }
  return out;
}

// ===========================================================================
// JH-512
// ===========================================================================

// JH round constants (big-endian representation)
const JH_C: readonly bigint[] = [
  0x72d5dea2df15f867n, 0x7b84150ab7231557n, 0x81abd6904d5a87f6n, 0x4e9f4fc5c3d12b40n,
  0xea983ae05c45fa9cn, 0x03c5d29966b2999an, 0x660296b4f2bb538an, 0xb556141a88dba231n,
  0x03a35a5c9a190edbn, 0x403fb20a87c14410n, 0x1c051980849e951dn, 0x6f33ebad5ee7cddcn,
  0x10ba139202bf6b41n, 0xdc786515f7bb27d0n, 0x0a2c813937aa7850n, 0x3f1abfd2410091d3n,
  0x422d5a0df6cc7e90n, 0xdd629f9c92c097cen, 0x185ca70bc72b44acn, 0xd1df65d663c6fc23n,
  0x976e6c039ee0b81an, 0x2105457e446ceca8n, 0xeef103bb5d8e61fan, 0xfd9697b294838197n,
  0x4a8e8537db03302fn, 0x2a678d2dfb9f6a95n, 0x8afe7381f8b8696cn, 0x8ac77246c07f4214n,
  0xc5f4158fbdc75ec4n, 0x75446fa78f11bb80n, 0x52de75b7aee488bcn, 0x82b8001e98a6a3f4n,
  0x8ef48f33a9a36315n, 0xaa5f5624d5b7f989n, 0xb6f1ed207c5ae0fdn, 0x36cae95a06422c36n,
  0xce2935434efe983dn, 0x533af974739a4ba7n, 0xd0f51f596f4e8186n, 0x0e9dad81afd85a9fn,
  0xa7050667ee34626an, 0x8b0b28be6eb91727n, 0x47740726c680103fn, 0xe0a07e6fc67e487bn,
  0x0d550aa54af8a4c0n, 0x91e3e79f978ef19en, 0x8676728150608dd4n, 0x7e9e5a41f3e5b062n,
  0xfc9f1fec4054207an, 0xe3e41a00cef4c984n, 0x4fd794f59dfa95d8n, 0x552e7e1124c354a5n,
  0x5bdf7228bdfe6e28n, 0x78f57fe20fa5c4b2n, 0x05897cefee49d32en, 0x447e9385eb28597fn,
  0x705f6937b324314an, 0x5e8628f11dd6e465n, 0xc71b770451b920e7n, 0x74fe43e823d4878an,
  0x7d29e8a3927694f2n, 0xddcb7a099b30d9c1n, 0x1d1b30fb5bdc1be0n, 0xda24494ff29c82bfn,
  0xa4e7ba31b470bfffn, 0x0d324405def8bc48n, 0x3baefc3253bbd339n, 0x459fc3c1e0298ba0n,
  0xe5c905fdf7ae090fn, 0x947034124290f134n, 0xa271b701e344ed95n, 0xe93b8e364f2f984an,
  0x88401d63a06cf615n, 0x47c1444b8752afffn, 0x7ebb4af1e20ac630n, 0x4670b6c5cc6e8ce6n,
  0xa4d5a456bd4fca00n, 0xda9d844bc83e18aen, 0x7357ce453064d1adn, 0xe8a6ce68145c2567n,
  0xa3da8cf2cb0ee116n, 0x33e906589a94999an, 0x1f60b220c26f847bn, 0xd1ceac7fa0d18518n,
  0x32595ba18ddd19d3n, 0x509a1cc0aaa5b446n, 0x9f3d6367e4046bban, 0xf6ca19ab0b56ee7en,
  0x1fb179eaa9282174n, 0xe9bdf7353b3651een, 0x1d57ac5a7550d376n, 0x3a46c2fea37d7001n,
  0xf735c1af98a4d842n, 0x78edec209e6b6779n, 0x41836315ea3adba8n, 0xfac33b4d32832c83n,
  0xa7403b1f1c2747f3n, 0x5940f034b72d769an, 0xe73e4e6cd2214ffdn, 0xb8fd8d39dc5759efn,
  0x8d9b0c492b49ebdan, 0x5ba2d74968f3700dn, 0x7d3baed07a8d5584n, 0xf5a5e9f0e4f88e65n,
  0xa0b8a2f436103b53n, 0x0ca8079e753eec5an, 0x9168949256e8884fn, 0x5bb05c55f8babc4cn,
  0xe3bb3b99f387947bn, 0x75daf4d6726b1c5dn, 0x64aeac28dc34b36dn, 0x6c34a550b828db71n,
  0xf861e2f2108d512an, 0xe3db643359dd75fcn, 0x1cacbcf143ce3fa2n, 0x67bbd13c02e843b0n,
  0x330a5bca8829a175n, 0x7f34194db416535cn, 0x923b94c30e794d1en, 0x797475d7b6eeaf3fn,
  0xeaa8d4f7be1a3921n, 0x5cf47e094c232751n, 0x26a32453ba323cd2n, 0x44a3174a6da6d5adn,
  0xb51d3ea6aff2c908n, 0x83593d98916b3c56n, 0x4cf87ca17286604dn, 0x46e23ecc086ec7f6n,
  0x2f9833b3b1bc765en, 0x2bd666a5efc4e62an, 0x06f4b6e8bec1d436n, 0x74ee8215bcef2163n,
  0xfdc14e0df453c969n, 0xa77d5ac406585826n, 0x7ec1141606e0fa16n, 0x7e90af3d28639d3fn,
  0xd2c9f2e3009bd20cn, 0x5faace30b7d40c30n, 0x742a5116f2e03298n, 0x0deb30d8e3cef89an,
  0x4bc59e7bb5f17992n, 0xff51e66e048668d3n, 0x9b234d57e6966731n, 0xcce6a6f3170a7505n,
  0xb17681d913326ccen, 0x3c175284f805a262n, 0xf42bcbb378471547n, 0xff46548223936a48n,
  0x38df58074e5e6565n, 0xf2fc7c89fc86508en, 0x31702e44d00bca86n, 0xf04009a23078474en,
  0x65a0ee39d1f73883n, 0xf75ee937e42c3abdn, 0x2197b2260113f86fn, 0xa344edd1ef9fdee7n,
  0x8ba0df15762592d9n, 0x3c85f7f612dc42ben, 0xd8a7ec7cab27b07en, 0x538d7ddaaa3ea8den,
  0xaa25ce93bd0269d8n, 0x5af643fd1a7308f9n, 0xc05fefda174a19a5n, 0x974d66334cfd216an,
  0x35b49831db411570n, 0xea1e0fbbedcd549bn, 0x9ad063a151974072n, 0xf6759dbf91476fe2n,
];

const JH_IV512: readonly bigint[] = [
  0x6fd14b963e00aa17n, 0x636a2e057a15d543n, 0x8a225e8d0c97ef0bn, 0xe9341259f2b3c361n,
  0x891da0c1536f801en, 0x2aa9056bea2b6d80n, 0x588eccdb2075baa6n, 0xa90f3a76baf83bf7n,
  0x0169e60541e34a69n, 0x46b58a8e2e6fe65an, 0x1047a7d0c1843c24n, 0x3b6e71b12d5ac199n,
  0xcf57f6ec9db1f856n, 0xa706887c5716b156n, 0xe3c2fcdfe68517fbn, 0x545a4678cc8cdd4bn,
];

function jhSb(x0: bigint, x1: bigint, x2: bigint, x3: bigint, c: bigint): [bigint, bigint, bigint, bigint] {
  let r3 = ~x3 & MASK64;
  let r0 = x0 ^ (c & (~x2 & MASK64));
  const tmp = (c ^ (r0 & x1)) & MASK64;
  r0 = (r0 ^ (x2 & r3)) & MASK64;
  r3 = (r3 ^ ((~x1 & MASK64) & x2)) & MASK64;
  let r1 = (x1 ^ (r0 & x2)) & MASK64;
  let r2 = (x2 ^ (r0 & (~r3 & MASK64))) & MASK64;
  r0 = (r0 ^ (r1 | r3)) & MASK64;
  r3 = (r3 ^ (r1 & r2)) & MASK64;
  r1 = (r1 ^ (tmp & r0)) & MASK64;
  r2 = (r2 ^ tmp) & MASK64;
  return [r0, r1, r2, r3];
}

function jhLb(
  x0: bigint, x1: bigint, x2: bigint, x3: bigint,
  x4: bigint, x5: bigint, x6: bigint, x7: bigint,
): [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint] {
  let r4 = x4 ^ x1;
  let r5 = x5 ^ x2;
  let r6 = x6 ^ x3 ^ x0;
  let r7 = x7 ^ x0;
  let r0 = x0 ^ r5;
  let r1 = x1 ^ r6;
  let r2 = x2 ^ r7 ^ r4;
  let r3 = x3 ^ r4;
  return [r0, r1, r2, r3, r4, r5, r6, r7];
}

function jhWz(hi: bigint, lo: bigint, c: bigint, n: number): [bigint, bigint] {
  const nn = BigInt(n);
  let thi = (hi & c) << nn;
  const rhi = ((hi >> nn) & c) | t64(thi);
  let tlo = (lo & c) << nn;
  const rlo = ((lo >> nn) & c) | t64(tlo);
  return [t64(rhi), t64(rlo)];
}

function jhW(
  hi: bigint, lo: bigint, wIdx: number,
): [bigint, bigint] {
  switch (wIdx) {
    case 0: return jhWz(hi, lo, 0x5555555555555555n, 1);
    case 1: return jhWz(hi, lo, 0x3333333333333333n, 2);
    case 2: return jhWz(hi, lo, 0x0F0F0F0F0F0F0F0Fn, 4);
    case 3: return jhWz(hi, lo, 0x00FF00FF00FF00FFn, 8);
    case 4: return jhWz(hi, lo, 0x0000FFFF0000FFFFn, 16);
    case 5: return jhWz(hi, lo, 0x00000000FFFFFFFFn, 32);
    case 6: return [lo, hi]; // swap hi and lo
    default: return [hi, lo];
  }
}

function jh512(data: Uint8Array): Uint8Array {
  // State: 16 x 64-bit words (1024-bit state), stored in big-endian
  const state = new Array<bigint>(16);
  for (let i = 0; i < 16; i++) {
    state[i] = JH_IV512[i];
  }

  let blockCount = 0n;
  const BLOCK_SIZE = 64; // 512-bit message block
  const buf = new Uint8Array(64);
  let ptr = 0;

  // Process data
  let dataOff = 0;
  let remaining = data.length;

  while (remaining > 0) {
    const clen = Math.min(BLOCK_SIZE - ptr, remaining);
    buf.set(data.subarray(dataOff, dataOff + clen), ptr);
    ptr += clen;
    dataOff += clen;
    remaining -= clen;

    if (ptr === BLOCK_SIZE) {
      jhProcessBlock(state, buf);
      blockCount++;
      ptr = 0;
    }
  }

  // Finalization

  // Padding
  let numz: number;
  if (ptr === 0) {
    numz = 47;
  } else {
    numz = 111 - ptr;
  }

  const closeBuf = new Uint8Array(numz + 17);
  closeBuf[0] = 0x80;
  // zeros from 1..numz (already zero)

  const totalBits = t64((blockCount << 9n) + BigInt(ptr * 8));
  const totalBitsHigh = t64(blockCount >> 55n);
  writeBE64(closeBuf, numz + 1, totalBitsHigh);
  writeBE64(closeBuf, numz + 9, totalBits);

  // Process remaining data + close buffer
  const allClose = new Uint8Array(ptr + closeBuf.length);
  allClose.set(buf.subarray(0, ptr));
  allClose.set(closeBuf, ptr);

  let closeOff = 0;
  let closeRemaining = allClose.length;
  const closeProcBuf = new Uint8Array(64);
  let closePtr = 0;

  while (closeRemaining > 0) {
    const clen = Math.min(BLOCK_SIZE - closePtr, closeRemaining);
    closeProcBuf.set(allClose.subarray(closeOff, closeOff + clen), closePtr);
    closePtr += clen;
    closeOff += clen;
    closeRemaining -= clen;

    if (closePtr === BLOCK_SIZE) {
      jhProcessBlock(state, closeProcBuf);
      closePtr = 0;
    }
  }

  // Output: last 8 words (indices 8..15)
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    writeBE64(out, i * 8, state[i + 8]);
  }
  return out;
}

function jhProcessBlock(state: bigint[], buf: Uint8Array): void {
  // Read message as 4 pairs of (hi, lo) = 8 x 64-bit words
  const m = new Array<bigint>(8);
  for (let i = 0; i < 8; i++) {
    m[i] = readBE64(buf, i * 8);
  }

  // XOR message into first half of state
  state[0] ^= m[0];
  state[1] ^= m[1];
  state[2] ^= m[2];
  state[3] ^= m[3];
  state[4] ^= m[4];
  state[5] ^= m[5];
  state[6] ^= m[6];
  state[7] ^= m[7];

  // E8 permutation: 42 rounds
  // State is organized as h0h,h0l, h1h,h1l, ... h7h,h7l
  // h0 = (state[0], state[1]), h1 = (state[2], state[3]), etc.
  let h0h = state[0], h0l = state[1];
  let h1h = state[2], h1l = state[3];
  let h2h = state[4], h2l = state[5];
  let h3h = state[6], h3l = state[7];
  let h4h = state[8], h4l = state[9];
  let h5h = state[10], h5l = state[11];
  let h6h = state[12], h6l = state[13];
  let h7h = state[14], h7l = state[15];

  for (let r = 0; r < 42; r++) {
    const cEvenHi = JH_C[(r << 2) + 0];
    const cEvenLo = JH_C[(r << 2) + 1];
    const cOddHi = JH_C[(r << 2) + 2];
    const cOddLo = JH_C[(r << 2) + 3];

    // S-box on even group
    [h0h, h2h, h4h, h6h] = jhSb(h0h, h2h, h4h, h6h, cEvenHi);
    [h0l, h2l, h4l, h6l] = jhSb(h0l, h2l, h4l, h6l, cEvenLo);

    // S-box on odd group
    [h1h, h3h, h5h, h7h] = jhSb(h1h, h3h, h5h, h7h, cOddHi);
    [h1l, h3l, h5l, h7l] = jhSb(h1l, h3l, h5l, h7l, cOddLo);

    // Linear layer
    [h0h, h2h, h4h, h6h, h1h, h3h, h5h, h7h] = jhLb(h0h, h2h, h4h, h6h, h1h, h3h, h5h, h7h);
    [h0l, h2l, h4l, h6l, h1l, h3l, h5l, h7l] = jhLb(h0l, h2l, h4l, h6l, h1l, h3l, h5l, h7l);

    // Word permutation W_(r mod 7)
    const wIdx = r % 7;
    [h1h, h1l] = jhW(h1h, h1l, wIdx);
    [h3h, h3l] = jhW(h3h, h3l, wIdx);
    [h5h, h5l] = jhW(h5h, h5l, wIdx);
    [h7h, h7l] = jhW(h7h, h7l, wIdx);
  }

  state[0] = h0h; state[1] = h0l;
  state[2] = h1h; state[3] = h1l;
  state[4] = h2h; state[5] = h2l;
  state[6] = h3h; state[7] = h3l;
  state[8] = h4h; state[9] = h4l;
  state[10] = h5h; state[11] = h5l;
  state[12] = h6h; state[13] = h6l;
  state[14] = h7h; state[15] = h7l;

  // XOR message into second half
  state[8] ^= m[0];
  state[9] ^= m[1];
  state[10] ^= m[2];
  state[11] ^= m[3];
  state[12] ^= m[4];
  state[13] ^= m[5];
  state[14] ^= m[6];
  state[15] ^= m[7];
}

// ===========================================================================
// Skein-512
// ===========================================================================

const SKEIN512_IV: readonly bigint[] = [
  0x4903ADFF749C51CEn, 0x0D95DE399746DF03n,
  0x8FD1934127C79BCEn, 0x9A255629FF352CB1n,
  0x5DB62599DF6CA7B0n, 0xEABE394CA9D5C3F4n,
  0x991112C71A75B523n, 0xAE18A40B660FCC33n,
];

const SKEIN_KS_PARITY = 0x1BD11BDAA9FC1A22n;

function skeinMix(x0: bigint, x1: bigint, rc: number): [bigint, bigint] {
  const r0 = t64(x0 + x1);
  const r1 = rotl64(x1, rc) ^ r0;
  return [r0, r1];
}

function skein512UBI(
  hIn: bigint[],
  buf: Uint8Array,
  bcount: bigint,
  etype: number,
  extra: number,
): void {
  const m = new Array<bigint>(8);
  for (let i = 0; i < 8; i++) {
    m[i] = readLE64(buf, i * 8);
  }

  let p0 = m[0], p1 = m[1], p2 = m[2], p3 = m[3];
  let p4 = m[4], p5 = m[5], p6 = m[6], p7 = m[7];

  const t0 = t64((bcount << 6n) + BigInt(extra));
  const t1 = t64((bcount >> 58n) + (BigInt(etype) << 55n));
  const t2 = t0 ^ t1;

  // Key schedule
  const h = new Array<bigint>(9);
  for (let i = 0; i < 8; i++) {
    h[i] = hIn[i];
  }
  h[8] = SKEIN_KS_PARITY;
  for (let i = 0; i < 8; i++) {
    h[8] ^= h[i];
  }

  const ts = [t0, t1, t2];

  // Threefish-512: 72 rounds in 9 groups of 8
  for (let d = 0; d < 18; d++) {
    const s = d;
    // AddKey
    p0 = t64(p0 + h[(s + 0) % 9]);
    p1 = t64(p1 + h[(s + 1) % 9]);
    p2 = t64(p2 + h[(s + 2) % 9]);
    p3 = t64(p3 + h[(s + 3) % 9]);
    p4 = t64(p4 + h[(s + 4) % 9]);
    p5 = t64(p5 + h[(s + 5) % 9] + ts[s % 3]);
    p6 = t64(p6 + h[(s + 6) % 9] + ts[(s + 1) % 3]);
    p7 = t64(p7 + h[(s + 7) % 9] + BigInt(s));

    // 4 rounds of even type
    [p0, p1] = skeinMix(p0, p1, 46); [p2, p3] = skeinMix(p2, p3, 36);
    [p4, p5] = skeinMix(p4, p5, 19); [p6, p7] = skeinMix(p6, p7, 37);
    [p2, p1] = skeinMix(p2, p1, 33); [p4, p7] = skeinMix(p4, p7, 27);
    [p6, p5] = skeinMix(p6, p5, 14); [p0, p3] = skeinMix(p0, p3, 42);
    [p4, p1] = skeinMix(p4, p1, 17); [p6, p3] = skeinMix(p6, p3, 49);
    [p0, p5] = skeinMix(p0, p5, 36); [p2, p7] = skeinMix(p2, p7, 39);
    [p6, p1] = skeinMix(p6, p1, 44); [p0, p7] = skeinMix(p0, p7, 9);
    [p2, p5] = skeinMix(p2, p5, 54); [p4, p3] = skeinMix(p4, p3, 56);

    d++;

    // AddKey for odd round
    const s2 = d;
    p0 = t64(p0 + h[(s2 + 0) % 9]);
    p1 = t64(p1 + h[(s2 + 1) % 9]);
    p2 = t64(p2 + h[(s2 + 2) % 9]);
    p3 = t64(p3 + h[(s2 + 3) % 9]);
    p4 = t64(p4 + h[(s2 + 4) % 9]);
    p5 = t64(p5 + h[(s2 + 5) % 9] + ts[s2 % 3]);
    p6 = t64(p6 + h[(s2 + 6) % 9] + ts[(s2 + 1) % 3]);
    p7 = t64(p7 + h[(s2 + 7) % 9] + BigInt(s2));

    // 4 rounds of odd type
    [p0, p1] = skeinMix(p0, p1, 39); [p2, p3] = skeinMix(p2, p3, 30);
    [p4, p5] = skeinMix(p4, p5, 34); [p6, p7] = skeinMix(p6, p7, 24);
    [p2, p1] = skeinMix(p2, p1, 13); [p4, p7] = skeinMix(p4, p7, 50);
    [p6, p5] = skeinMix(p6, p5, 10); [p0, p3] = skeinMix(p0, p3, 17);
    [p4, p1] = skeinMix(p4, p1, 25); [p6, p3] = skeinMix(p6, p3, 29);
    [p0, p5] = skeinMix(p0, p5, 39); [p2, p7] = skeinMix(p2, p7, 43);
    [p6, p1] = skeinMix(p6, p1, 8); [p0, p7] = skeinMix(p0, p7, 35);
    [p2, p5] = skeinMix(p2, p5, 56); [p4, p3] = skeinMix(p4, p3, 22);
  }

  // Final AddKey (s=18)
  p0 = t64(p0 + h[18 % 9]);
  p1 = t64(p1 + h[19 % 9]);
  p2 = t64(p2 + h[20 % 9]);
  p3 = t64(p3 + h[21 % 9]);
  p4 = t64(p4 + h[22 % 9]);
  p5 = t64(p5 + h[23 % 9] + ts[18 % 3]);
  p6 = t64(p6 + h[24 % 9] + ts[19 % 3]);
  p7 = t64(p7 + h[25 % 9] + 18n);

  // Feedforward
  hIn[0] = m[0] ^ p0;
  hIn[1] = m[1] ^ p1;
  hIn[2] = m[2] ^ p2;
  hIn[3] = m[3] ^ p3;
  hIn[4] = m[4] ^ p4;
  hIn[5] = m[5] ^ p5;
  hIn[6] = m[6] ^ p6;
  hIn[7] = m[7] ^ p7;
}

function skein512(data: Uint8Array): Uint8Array {
  const h = [...SKEIN512_IV];
  let bcount = 0n;
  const buf = new Uint8Array(64);
  let ptr = 0;

  // Process data - need to keep last block in buffer
  let dataOff = 0;
  let remaining = data.length;

  if (remaining <= 64 - ptr) {
    buf.set(data.subarray(dataOff, dataOff + remaining), ptr);
    ptr += remaining;
    remaining = 0;
  } else {
    while (remaining > 0) {
      const clen = Math.min(64 - ptr, remaining);
      buf.set(data.subarray(dataOff, dataOff + clen), ptr);
      ptr += clen;
      dataOff += clen;
      remaining -= clen;

      if (ptr === 64 && remaining > 0) {
        bcount++;
        const firstFlag = (bcount === 1n) ? 128 : 0;
        skein512UBI(h, buf, bcount, 96 + firstFlag, 0);
        ptr = 0;
      }
    }
  }

  // Close
  // Zero-pad remaining buffer
  for (let i = ptr; i < 64; i++) {
    buf[i] = 0;
  }

  const et = 352 + ((bcount === 0n) ? 128 : 0);
  skein512UBI(h, buf, bcount, et, ptr);

  // Output block
  const outBuf = new Uint8Array(64);
  outBuf.fill(0);
  // Encode counter 0 as LE 8 bytes (already zero)
  bcount = 0n;
  skein512UBI(h, outBuf, bcount, 510, 8);

  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    writeLE64(out, i * 8, h[i]);
  }
  return out;
}

// ===========================================================================
// Keccak-512
// ===========================================================================

function keccak512(data: Uint8Array): Uint8Array {
  return keccak_512(data);
}

// ---------------------------------------------------------------------------
// Quark hash
// ---------------------------------------------------------------------------

/**
 * Compute the Quark hash of arbitrary data.
 * Returns a 32-byte hash.
 */
export function quarkHash(data: Uint8Array): Uint8Array {
  // Round 1: BLAKE-512
  const h1 = blake512(data);

  // Round 2: BMW-512
  const h2 = bmw512(h1);

  // Round 3: conditional Groestl-512 or Skein-512
  const h3 = (h2[0] & 8) !== 0 ? groestl512(h2) : skein512(h2);

  // Round 4: Groestl-512
  const h4 = groestl512(h3);

  // Round 5: JH-512
  const h5 = jh512(h4);

  // Round 6: conditional BLAKE-512 or BMW-512
  const h6 = (h5[0] & 8) !== 0 ? blake512(h5) : bmw512(h5);

  // Round 7: Keccak-512
  const h7 = keccak512(h6);

  // Round 8: Skein-512
  const h8 = skein512(h7);

  // Round 9: conditional Keccak-512 or JH-512
  const h9 = (h8[0] & 8) !== 0 ? keccak512(h8) : jh512(h8);

  // Return first 32 bytes
  return h9.slice(0, 32);
}

/**
 * Hash a block header using the Quark algorithm.
 * Serializes the 80-byte header and computes quarkHash.
 */
export function hashBlockHeader(header: BlockHeader): Uint8Array {
  const raw = serializeBlockHeader(header);
  return quarkHash(raw);
}

/**
 * Double SHA-256 hash (used for transaction hashing, merkle trees, etc.).
 * This is NOT the Quark hash; it's the standard Bitcoin double-hash.
 */
export function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}
