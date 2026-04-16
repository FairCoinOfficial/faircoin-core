/**
 * FairCoin address generation and validation.
 * Uses Hash160 (SHA-256 -> RIPEMD-160) per Bitcoin convention.
 */

import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";

import {
  decodeAddress,
  encodeAddress,
  hexToBytes,
  bytesToHex,
} from "./encoding.js";
import type { NetworkConfig } from "./network.js";
import { Opcodes } from "./script.js";

/**
 * Hash160 = RIPEMD-160(SHA-256(data)).
 * Standard Bitcoin-style address hash.
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * Derive a Base58Check-encoded P2PKH address from a compressed or
 * uncompressed public key.
 */
export function publicKeyToAddress(
  pubKey: Uint8Array,
  network: NetworkConfig,
): string {
  if (pubKey.length !== 33 && pubKey.length !== 65) {
    throw new Error(
      `Invalid public key length: expected 33 (compressed) or 65 (uncompressed), got ${pubKey.length}`,
    );
  }
  const pkHash = hash160(pubKey);
  return encodeAddress(pkHash, network.pubKeyHash);
}

/**
 * Convert an address to the Electrum-style script hash (used for indexing).
 * scriptHash = SHA-256(scriptPubKey), returned as raw bytes.
 */
export function addressToScriptHash(address: string): Uint8Array {
  const decoded = decodeAddress(address);
  let script: Uint8Array;

  // Build the scriptPubKey depending on version
  // P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  // P2SH:  OP_HASH160 <20-byte hash> OP_EQUAL
  // We determine type by the hash length (always 20) and build both patterns.
  // For a generic approach, we can look at version bytes but we don't have the
  // network config here. Since both P2PKH and P2SH have 20-byte hashes, we
  // use a heuristic: try to match known version ranges.
  // However, the safe approach is to build the standard P2PKH script since
  // most FairCoin addresses are P2PKH.
  // For correctness, we build the script for the decoded version.
  const hash = decoded.hash;

  // We don't know exactly which version is P2PKH vs P2SH without the network
  // config, so we look at standard Bitcoin-derived ranges:
  // P2PKH versions are typically used for single-key addresses.
  // P2SH versions are for multi-sig / script addresses.
  // FairCoin mainnet: pubKeyHash=35, scriptHash=16
  // FairCoin testnet: pubKeyHash=65, scriptHash=12
  // To handle both, we check against known values.
  const P2SH_VERSIONS = new Set([16, 12]);

  if (P2SH_VERSIONS.has(decoded.version)) {
    // OP_HASH160 <20 bytes> OP_EQUAL
    script = new Uint8Array(23);
    script[0] = Opcodes.OP_HASH160;
    script[1] = 0x14; // push 20 bytes
    script.set(hash, 2);
    script[22] = Opcodes.OP_EQUAL;
  } else {
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    script = new Uint8Array(25);
    script[0] = Opcodes.OP_DUP;
    script[1] = Opcodes.OP_HASH160;
    script[2] = 0x14; // push 20 bytes
    script.set(hash, 3);
    script[23] = Opcodes.OP_EQUALVERIFY;
    script[24] = Opcodes.OP_CHECKSIG;
  }

  return sha256(script);
}

/**
 * Validate a FairCoin address string: checks base58check encoding, length,
 * and that the version byte matches the given network.
 */
export function validateAddress(
  address: string,
  network: NetworkConfig,
): boolean {
  try {
    const decoded = decodeAddress(address);
    return (
      decoded.version === network.pubKeyHash ||
      decoded.version === network.scriptHash
    );
  } catch {
    // Invalid base58check encoding or checksum — address is not valid.
    return false;
  }
}

/** Check whether the address is a P2PKH address for the given network. */
export function isP2PKH(address: string, network: NetworkConfig): boolean {
  try {
    const decoded = decodeAddress(address);
    return decoded.version === network.pubKeyHash;
  } catch {
    // Invalid base58check encoding — not a valid P2PKH address.
    return false;
  }
}

/** Check whether the address is a P2SH address for the given network. */
export function isP2SH(address: string, network: NetworkConfig): boolean {
  try {
    const decoded = decodeAddress(address);
    return decoded.version === network.scriptHash;
  } catch {
    // Invalid base58check encoding — not a valid P2SH address.
    return false;
  }
}

/**
 * Reverse a hex-encoded hash (switch between internal and display byte order).
 */
export function reverseHex(hex: string): string {
  const bytes = hexToBytes(hex);
  const reversed = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    reversed[i] = bytes[bytes.length - 1 - i];
  }
  return bytesToHex(reversed);
}
