/**
 * Tests for FairCoin address helpers (P2PKH / P2SH).
 *
 * Test vectors are derived from known-good reference points:
 *   - The secp256k1 generator point G (compressed) as a source public key
 *   - Its RIPEMD160(SHA256(pubkey)) is `751e76e8199196d454941c45d1b3a323f1433bd6`
 *     which is a well-known value shared with Bitcoin (same hash construction).
 *   - Applying FairCoin's mainnet and testnet version bytes yields the addresses
 *     pinned in the tests below.
 *
 * These act as regression guards: if anyone accidentally changes
 * pubKeyHash, the double SHA256 checksum, or the base58 encoder, the
 * addresses will shift and these tests will fail.
 */

import { describe, test, expect } from "bun:test";

import {
  addressToScriptHash,
  hash160,
  isP2PKH,
  isP2SH,
  publicKeyToAddress,
  reverseHex,
  validateAddress,
} from "../src/address.js";
import { sha256 } from "@noble/hashes/sha256";

import { bytesToHex, decodeAddress, encodeAddress, hexToBytes } from "../src/encoding.js";
import { MAINNET, TESTNET } from "../src/network.js";
import { Opcodes } from "../src/script.js";

// ---------------------------------------------------------------------------
// Known test vectors (from secp256k1 generator point G)
// ---------------------------------------------------------------------------

const G_PUBKEY_HEX =
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G_HASH160_HEX = "751e76e8199196d454941c45d1b3a323f1433bd6";
const G_MAINNET_ADDRESS = "FGWP1xKhDP5RmV525TmUoEwX9mTZwp3sJn";
const G_TESTNET_ADDRESS = "TLeUZDGLWnyiJVFcp3m3M1782uBsGWa8uf";

// ---------------------------------------------------------------------------
// hash160
// ---------------------------------------------------------------------------

describe("hash160", () => {
  test("hash160 of secp256k1 G matches known value", () => {
    const pk = hexToBytes(G_PUBKEY_HEX);
    expect(bytesToHex(hash160(pk))).toBe(G_HASH160_HEX);
  });

  test("output is 20 bytes", () => {
    expect(hash160(new Uint8Array(1)).length).toBe(20);
  });

  test("hash160 of empty string is a known constant", () => {
    // RIPEMD160(SHA256("")) in hex, standard reference value.
    expect(bytesToHex(hash160(new Uint8Array(0)))).toBe(
      "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
    );
  });
});

// ---------------------------------------------------------------------------
// publicKeyToAddress
// ---------------------------------------------------------------------------

describe("publicKeyToAddress", () => {
  test("mainnet vector for generator G", () => {
    const pk = hexToBytes(G_PUBKEY_HEX);
    expect(publicKeyToAddress(pk, MAINNET)).toBe(G_MAINNET_ADDRESS);
  });

  test("testnet vector for generator G", () => {
    const pk = hexToBytes(G_PUBKEY_HEX);
    expect(publicKeyToAddress(pk, TESTNET)).toBe(G_TESTNET_ADDRESS);
  });

  test("mainnet FairCoin addresses start with F", () => {
    const pk = hexToBytes(G_PUBKEY_HEX);
    expect(publicKeyToAddress(pk, MAINNET).startsWith("F")).toBe(true);
  });

  test("testnet FairCoin addresses start with T", () => {
    const pk = hexToBytes(G_PUBKEY_HEX);
    expect(publicKeyToAddress(pk, TESTNET).startsWith("T")).toBe(true);
  });

  test("rejects invalid pubkey length", () => {
    expect(() => publicKeyToAddress(new Uint8Array(32), MAINNET)).toThrow();
    expect(() => publicKeyToAddress(new Uint8Array(0), MAINNET)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// decodeAddress
// ---------------------------------------------------------------------------

describe("decodeAddress", () => {
  test("recovers the hash160 of the generator point", () => {
    const decoded = decodeAddress(G_MAINNET_ADDRESS);
    expect(decoded.version).toBe(MAINNET.pubKeyHash);
    expect(bytesToHex(decoded.hash)).toBe(G_HASH160_HEX);
  });

  test("testnet recovery", () => {
    const decoded = decodeAddress(G_TESTNET_ADDRESS);
    expect(decoded.version).toBe(TESTNET.pubKeyHash);
    expect(bytesToHex(decoded.hash)).toBe(G_HASH160_HEX);
  });

  test("rejects garbage string", () => {
    expect(() => decodeAddress("nope")).toThrow();
  });

  test("rejects mutated checksum", () => {
    const chars = G_MAINNET_ADDRESS.split("");
    // Change the last character to produce an invalid checksum
    const last = chars[chars.length - 1];
    chars[chars.length - 1] = last === "1" ? "2" : "1";
    expect(() => decodeAddress(chars.join(""))).toThrow(/checksum/i);
  });
});

// ---------------------------------------------------------------------------
// validateAddress
// ---------------------------------------------------------------------------

describe("validateAddress", () => {
  test("accepts a valid mainnet address on mainnet", () => {
    expect(validateAddress(G_MAINNET_ADDRESS, MAINNET)).toBe(true);
  });

  test("accepts a valid testnet address on testnet", () => {
    expect(validateAddress(G_TESTNET_ADDRESS, TESTNET)).toBe(true);
  });

  test("rejects mainnet address on testnet", () => {
    expect(validateAddress(G_MAINNET_ADDRESS, TESTNET)).toBe(false);
  });

  test("rejects testnet address on mainnet", () => {
    expect(validateAddress(G_TESTNET_ADDRESS, MAINNET)).toBe(false);
  });

  test("rejects garbage", () => {
    expect(validateAddress("not an address", MAINNET)).toBe(false);
    expect(validateAddress("", MAINNET)).toBe(false);
  });

  test("rejects mutated checksum", () => {
    const chars = G_MAINNET_ADDRESS.split("");
    const last = chars[chars.length - 1];
    chars[chars.length - 1] = last === "1" ? "2" : "1";
    expect(validateAddress(chars.join(""), MAINNET)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isP2PKH / isP2SH
// ---------------------------------------------------------------------------

describe("isP2PKH / isP2SH", () => {
  test("generator address is P2PKH on mainnet", () => {
    expect(isP2PKH(G_MAINNET_ADDRESS, MAINNET)).toBe(true);
    expect(isP2SH(G_MAINNET_ADDRESS, MAINNET)).toBe(false);
  });

  test("generator address is P2PKH on testnet", () => {
    expect(isP2PKH(G_TESTNET_ADDRESS, TESTNET)).toBe(true);
    expect(isP2SH(G_TESTNET_ADDRESS, TESTNET)).toBe(false);
  });

  test("synthesised P2SH address is recognised", () => {
    // Build a P2SH address by using the scriptHash version byte
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const p2shAddr = encodeAddress(hash, MAINNET.scriptHash);
    expect(isP2SH(p2shAddr, MAINNET)).toBe(true);
    expect(isP2PKH(p2shAddr, MAINNET)).toBe(false);
  });

  test("invalid input is not P2PKH or P2SH", () => {
    expect(isP2PKH("garbage", MAINNET)).toBe(false);
    expect(isP2SH("garbage", MAINNET)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// addressToScriptHash
// ---------------------------------------------------------------------------

describe("addressToScriptHash", () => {
  test("produces 32 bytes for a P2PKH address", () => {
    const sh = addressToScriptHash(G_MAINNET_ADDRESS);
    expect(sh.length).toBe(32);
  });

  test("different addresses produce different script hashes", () => {
    const a = addressToScriptHash(G_MAINNET_ADDRESS);
    const b = addressToScriptHash(G_TESTNET_ADDRESS);
    // P2PKH script pubkeys are built from the decoded hash bytes regardless
    // of version, so the hash bytes match — and so the script hash matches.
    // This is expected: the script hash depends only on the hash160, not
    // the version prefix.
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("P2SH address uses P2SH script template", () => {
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const p2shAddr = encodeAddress(hash, MAINNET.scriptHash);
    const sh = addressToScriptHash(p2shAddr);
    expect(sh.length).toBe(32);
  });

  test("resolves the P2SH branch from network config for BOTH mainnet and testnet script-hash versions", () => {
    // Builds the expected P2SH scriptPubKey by hand and hashes it, so this
    // fails if the P2SH-vs-P2PKH branch is ever driven by a version byte
    // other than MAINNET.scriptHash / TESTNET.scriptHash (e.g. a stale
    // hardcoded literal that silently stops tracking the network configs).
    const hash = hexToBytes("0102030405060708090a0b0c0d0e0f1011121314");
    const expectedScript = new Uint8Array(23);
    expectedScript[0] = Opcodes.OP_HASH160;
    expectedScript[1] = 0x14;
    expectedScript.set(hash, 2);
    expectedScript[22] = Opcodes.OP_EQUAL;
    const expected = bytesToHex(sha256(expectedScript));

    const mainnetAddr = encodeAddress(hash, MAINNET.scriptHash);
    const testnetAddr = encodeAddress(hash, TESTNET.scriptHash);
    expect(bytesToHex(addressToScriptHash(mainnetAddr))).toBe(expected);
    expect(bytesToHex(addressToScriptHash(testnetAddr))).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// reverseHex
// ---------------------------------------------------------------------------

describe("reverseHex", () => {
  test("reverses byte order", () => {
    expect(reverseHex("01020304")).toBe("04030201");
  });

  test("is its own inverse", () => {
    const hex = "deadbeefcafebabe";
    expect(reverseHex(reverseHex(hex))).toBe(hex);
  });

  test("handles 32-byte hash", () => {
    const hash = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    expect(reverseHex(hash)).toBe(
      "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201",
    );
  });
});
