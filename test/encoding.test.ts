/**
 * Tests for binary encoding primitives.
 *
 * Covers:
 *  - hex <-> bytes round trip and error cases
 *  - varint (CompactSize) encoding across all size class boundaries
 *  - Base58Check encode/decode and checksum validation
 *  - WIF encoding/decoding
 *  - BufferWriter/BufferReader round trips
 */

import { describe, test, expect } from "bun:test";

import {
  BufferReader,
  BufferWriter,
  base58CheckDecode,
  base58CheckEncode,
  bytesToHex,
  decodeAddress,
  decodeWIF,
  encodeAddress,
  encodeWIF,
  hexToBytes,
  readUInt32LE,
  readUInt64LE,
  readVarInt,
  writeUInt32LE,
  writeUInt64LE,
  writeVarInt,
} from "../src/encoding.js";
import { MAINNET, TESTNET } from "../src/network.js";

// ---------------------------------------------------------------------------
// Hex conversion
// ---------------------------------------------------------------------------

describe("hexToBytes / bytesToHex", () => {
  test("empty round trip", () => {
    expect(bytesToHex(hexToBytes(""))).toBe("");
  });

  test("simple round trip", () => {
    const hex = "deadbeef";
    expect(bytesToHex(hexToBytes(hex))).toBe(hex);
  });

  test("all byte values", () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    const roundTripped = hexToBytes(bytesToHex(bytes));
    expect(roundTripped).toEqual(bytes);
  });

  test("accepts uppercase hex on decode", () => {
    const bytes = hexToBytes("DEADBEEF");
    expect(bytesToHex(bytes)).toBe("deadbeef");
  });

  test("throws on odd length", () => {
    expect(() => hexToBytes("abc")).toThrow();
  });

  test("throws on invalid character", () => {
    expect(() => hexToBytes("zz")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// VarInt (CompactSize)
// ---------------------------------------------------------------------------

describe("writeVarInt / readVarInt", () => {
  // Reference values derived from Bitcoin's CompactSize specification.
  // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
  const CASES: Array<{ value: number; bytes: string; size: number }> = [
    { value: 0, bytes: "00", size: 1 },
    { value: 1, bytes: "01", size: 1 },
    { value: 0xfc, bytes: "fc", size: 1 }, // 252, the max 1-byte value
    { value: 0xfd, bytes: "fdfd00", size: 3 }, // first 3-byte value
    { value: 0xffff, bytes: "fdffff", size: 3 }, // max 3-byte value
    { value: 0x10000, bytes: "fe00000100", size: 5 }, // first 5-byte value
    { value: 0xffffffff, bytes: "feffffffff", size: 5 }, // max 5-byte value
    { value: 0x100000000, bytes: "ff0000000001000000", size: 9 }, // first 9-byte value
  ];

  test.each(CASES)("encodes %p", ({ value, bytes, size }) => {
    const encoded = writeVarInt(value);
    expect(bytesToHex(encoded)).toBe(bytes);
    expect(encoded.length).toBe(size);
  });

  test.each(CASES)("decodes %p", ({ value, bytes, size }) => {
    const result = readVarInt(hexToBytes(bytes), 0);
    expect(result.value).toBe(value);
    expect(result.bytesRead).toBe(size);
  });

  test("round trip a few random values", () => {
    const values = [0, 1, 252, 253, 254, 65535, 65536, 100_000, 1_000_000];
    for (const v of values) {
      const encoded = writeVarInt(v);
      const decoded = readVarInt(encoded, 0);
      expect(decoded.value).toBe(v);
      expect(decoded.bytesRead).toBe(encoded.length);
    }
  });

  test("readVarInt honours offset", () => {
    const buf = hexToBytes("00fdfd00");
    const a = readVarInt(buf, 0);
    expect(a).toEqual({ value: 0, bytesRead: 1 });
    const b = readVarInt(buf, 1);
    expect(b).toEqual({ value: 0xfd, bytesRead: 3 });
  });

  test("throws on negative values", () => {
    expect(() => writeVarInt(-1)).toThrow();
  });

  test("throws on truncated data", () => {
    expect(() => readVarInt(hexToBytes("fd"), 0)).toThrow();
    expect(() => readVarInt(hexToBytes("fe0000"), 0)).toThrow();
    expect(() => readVarInt(new Uint8Array(0), 0)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 32/64-bit LE helpers
// ---------------------------------------------------------------------------

describe("LE integer helpers", () => {
  test("writeUInt32LE / readUInt32LE round trip", () => {
    const values = [0, 1, 0xff, 0xffff, 0xff_ffff, 0xffff_ffff];
    for (const v of values) {
      const buf = writeUInt32LE(v);
      expect(readUInt32LE(buf, 0)).toBe(v);
    }
  });

  test("writeUInt32LE produces little-endian bytes", () => {
    expect(bytesToHex(writeUInt32LE(0x01020304))).toBe("04030201");
  });

  test("writeUInt64LE / readUInt64LE round trip", () => {
    const values = [
      0n,
      1n,
      0xffffffffn,
      0x1_0000_0000n,
      0xdeadbeefcafebaben,
      0xffffffffffffffffn,
    ];
    for (const v of values) {
      const buf = writeUInt64LE(v);
      expect(readUInt64LE(buf, 0)).toBe(v);
    }
  });

  test("writeUInt64LE rejects negatives", () => {
    expect(() => writeUInt64LE(-1n)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Base58Check
// ---------------------------------------------------------------------------

describe("base58Check", () => {
  test("round trip 21-byte address payload", () => {
    const payload = new Uint8Array(21);
    payload[0] = MAINNET.pubKeyHash;
    for (let i = 1; i < 21; i++) payload[i] = i;
    const encoded = base58CheckEncode(payload);
    const decoded = base58CheckDecode(encoded);
    expect(decoded).toEqual(payload);
  });

  test("detects invalid checksum", () => {
    const payload = new Uint8Array(21);
    payload[0] = MAINNET.pubKeyHash;
    const encoded = base58CheckEncode(payload);
    // Mutate the last character so the checksum fails
    const chars = encoded.split("");
    const lastChar = chars[chars.length - 1];
    chars[chars.length - 1] = lastChar === "1" ? "2" : "1";
    const mutated = chars.join("");
    expect(() => base58CheckDecode(mutated)).toThrow(/checksum/i);
  });

  test("rejects too-short input", () => {
    // Decodes to 3 bytes total — less than the 4-byte minimum (0-byte
    // payload + 4-byte checksum), so it must still be rejected.
    expect(() => base58CheckDecode("Ldp")).toThrow(/too short/i);
  });

  test("round trips a 0-byte payload", () => {
    // A valid Base58Check value is just a 4-byte checksum over an empty
    // payload. The old `< 5` guard rejected this, breaking the round trip.
    const payload = new Uint8Array(0);
    const encoded = base58CheckEncode(payload);
    const decoded = base58CheckDecode(encoded);
    expect(decoded.length).toBe(0);
    expect(decoded).toEqual(payload);
  });
});

// ---------------------------------------------------------------------------
// encodeAddress / decodeAddress
// ---------------------------------------------------------------------------

describe("encodeAddress / decodeAddress", () => {
  test("round trip on all-zero hash", () => {
    const hash = new Uint8Array(20); // all zeros
    const addr = encodeAddress(hash, MAINNET.pubKeyHash);
    const decoded = decodeAddress(addr);
    expect(decoded.version).toBe(MAINNET.pubKeyHash);
    expect(decoded.hash).toEqual(hash);
  });

  test("round trip on a fixed non-zero hash (mainnet)", () => {
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const addr = encodeAddress(hash, MAINNET.pubKeyHash);
    const decoded = decodeAddress(addr);
    expect(decoded.version).toBe(MAINNET.pubKeyHash);
    expect(decoded.hash).toEqual(hash);
  });

  test("round trip on a fixed non-zero hash (testnet)", () => {
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const addr = encodeAddress(hash, TESTNET.pubKeyHash);
    const decoded = decodeAddress(addr);
    expect(decoded.version).toBe(TESTNET.pubKeyHash);
    expect(decoded.hash).toEqual(hash);
  });

  test("mainnet and testnet addresses differ for same hash", () => {
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const main = encodeAddress(hash, MAINNET.pubKeyHash);
    const test = encodeAddress(hash, TESTNET.pubKeyHash);
    expect(main).not.toBe(test);
  });

  test("rejects hash of wrong length", () => {
    expect(() => encodeAddress(new Uint8Array(19), MAINNET.pubKeyHash)).toThrow();
    expect(() => encodeAddress(new Uint8Array(21), MAINNET.pubKeyHash)).toThrow();
  });

  test("rejects garbage address string", () => {
    expect(() => decodeAddress("not-a-valid-address")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// WIF
// ---------------------------------------------------------------------------

describe("encodeWIF / decodeWIF", () => {
  const privKey = hexToBytes(
    "0000000000000000000000000000000000000000000000000000000000000001",
  );

  test("compressed round trip on mainnet", () => {
    const wif = encodeWIF(privKey, true, MAINNET);
    const decoded = decodeWIF(wif);
    expect(decoded.privateKey).toEqual(privKey);
    expect(decoded.compressed).toBe(true);
    expect(decoded.networkPrefix).toBe(MAINNET.wifPrefix);
  });

  test("uncompressed round trip on mainnet", () => {
    const wif = encodeWIF(privKey, false, MAINNET);
    const decoded = decodeWIF(wif);
    expect(decoded.privateKey).toEqual(privKey);
    expect(decoded.compressed).toBe(false);
  });

  test("testnet prefix differs", () => {
    const mainWif = encodeWIF(privKey, true, MAINNET);
    const testWif = encodeWIF(privKey, true, TESTNET);
    expect(mainWif).not.toBe(testWif);
    expect(decodeWIF(testWif).networkPrefix).toBe(TESTNET.wifPrefix);
  });

  test("rejects wrong key length", () => {
    expect(() => encodeWIF(new Uint8Array(31), true, MAINNET)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// BufferWriter / BufferReader
// ---------------------------------------------------------------------------

describe("BufferWriter / BufferReader", () => {
  test("writes and reads mixed field types", () => {
    const writer = new BufferWriter();
    writer.writeUInt8(0x42);
    writer.writeUInt16LE(0xbeef);
    writer.writeUInt32LE(0xdeadbeef);
    writer.writeInt32LE(-1);
    writer.writeUInt64LE(0x1122334455667788n);
    writer.writeVarInt(300);
    writer.writeBytes(hexToBytes("cafe"));

    const bytes = writer.toBytes();
    const reader = new BufferReader(bytes);
    expect(reader.readUInt8()).toBe(0x42);
    expect(reader.readUInt16LE()).toBe(0xbeef);
    expect(reader.readUInt32LE()).toBe(0xdeadbeef);
    expect(reader.readInt32LE()).toBe(-1);
    expect(reader.readUInt64LE()).toBe(0x1122334455667788n);
    expect(reader.readVarInt()).toBe(300);
    expect(reader.readBytes(2)).toEqual(hexToBytes("cafe"));
    expect(reader.remaining).toBe(0);
  });

  test("writeHash reverses byte order (internal order)", () => {
    const writer = new BufferWriter();
    // Display-order hash (big-endian style as Bitcoin explorers show)
    const displayHex = "00".repeat(31) + "01";
    writer.writeHash(displayHex);
    const bytes = writer.toBytes();
    // Internal byte order: first byte is 0x01, last byte is 0x00
    expect(bytes[0]).toBe(0x01);
    expect(bytes[31]).toBe(0x00);
  });

  test("readHash reverses back to display order", () => {
    const writer = new BufferWriter();
    const displayHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    writer.writeHash(displayHex);
    const reader = new BufferReader(writer.toBytes());
    expect(reader.readHash()).toBe(displayHex);
  });

  test("grows the backing buffer past the initial capacity", () => {
    const writer = new BufferWriter(4);
    for (let i = 0; i < 1000; i++) {
      writer.writeUInt8(i & 0xff);
    }
    const bytes = writer.toBytes();
    expect(bytes.length).toBe(1000);
    for (let i = 0; i < 1000; i++) {
      expect(bytes[i]).toBe(i & 0xff);
    }
  });

  test("BufferReader throws when reading past end", () => {
    const reader = new BufferReader(new Uint8Array(2));
    reader.readUInt8();
    reader.readUInt8();
    expect(() => reader.readUInt8()).toThrow();
  });
});
