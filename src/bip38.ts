/**
 * BIP38 encrypted private key export/import.
 * Encrypts a private key with a passphrase using scrypt + AES-256-ECB.
 * Non-EC-multiply mode only (prefix 0x0142).
 */

import { sha256 } from "@noble/hashes/sha256";
import { scrypt } from "@noble/hashes/scrypt";
import * as secp256k1 from "@noble/secp256k1";

import { base58CheckEncode, base58CheckDecode, encodeAddress } from "./encoding.js";
import { publicKeyToAddress, hash160 as computeHash160 } from "./address.js";
import type { NetworkConfig } from "./network.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** BIP38 prefix bytes: 0x01, 0x42 */
const BIP38_PREFIX_0 = 0x01;
const BIP38_PREFIX_1 = 0x42;

/** Flag byte: 0xe0 for compressed, 0xc0 for uncompressed */
const FLAG_COMPRESSED = 0xe0;
const FLAG_UNCOMPRESSED = 0xc0;

// ---------------------------------------------------------------------------
// Minimal AES-256-ECB implementation (single 16-byte block)
// ---------------------------------------------------------------------------

/** AES S-Box lookup table. */
const SBOX: readonly number[] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/** AES inverse S-Box lookup table. */
const INV_SBOX: readonly number[] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/** AES round constants. */
const RCON: readonly number[] = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/** Number of AES-256 rounds. */
const AES256_ROUNDS = 14;

/** Number of 4-byte words in AES-256 key. */
const AES256_NK = 8;

/**
 * Galois Field multiplication of a by 2 in GF(2^8).
 */
function gmul2(a: number): number {
  return ((a << 1) ^ ((a >> 7) * 0x1b)) & 0xff;
}

/**
 * Galois Field multiplication of a by 3 in GF(2^8).
 */
function gmul3(a: number): number {
  return gmul2(a) ^ a;
}

/**
 * Galois Field multiplication in GF(2^8) for inverse MixColumns.
 */
function gmul(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  for (let i = 0; i < 8; i++) {
    if (bb & 1) {
      result ^= aa;
    }
    const hiBit = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hiBit) {
      aa ^= 0x1b;
    }
    bb >>= 1;
  }
  return result;
}

/**
 * Expand a 32-byte AES-256 key into round key words.
 * Returns an array of (AES256_ROUNDS + 1) * 4 = 60 uint32 words.
 */
function aes256KeyExpansion(key: Uint8Array): Uint32Array {
  const totalWords = (AES256_ROUNDS + 1) * 4; // 60
  const w = new Uint32Array(totalWords);

  // Copy initial key words
  for (let i = 0; i < AES256_NK; i++) {
    w[i] =
      (key[4 * i] << 24) |
      (key[4 * i + 1] << 16) |
      (key[4 * i + 2] << 8) |
      key[4 * i + 3];
  }

  for (let i = AES256_NK; i < totalWords; i++) {
    let temp = w[i - 1];
    if (i % AES256_NK === 0) {
      // RotWord + SubWord + Rcon
      temp =
        (SBOX[(temp >> 16) & 0xff] << 24) |
        (SBOX[(temp >> 8) & 0xff] << 16) |
        (SBOX[temp & 0xff] << 8) |
        SBOX[(temp >> 24) & 0xff];
      temp ^= RCON[(i / AES256_NK) - 1] << 24;
    } else if (i % AES256_NK === 4) {
      // SubWord only for Nk=8
      temp =
        (SBOX[(temp >> 24) & 0xff] << 24) |
        (SBOX[(temp >> 16) & 0xff] << 16) |
        (SBOX[(temp >> 8) & 0xff] << 8) |
        SBOX[temp & 0xff];
    }
    w[i] = w[i - AES256_NK] ^ temp;
  }

  return w;
}

/**
 * Get a 16-byte state array from the expanded key at a given round.
 */
function getRoundKey(roundKeys: Uint32Array, round: number): Uint8Array {
  const key = new Uint8Array(16);
  for (let col = 0; col < 4; col++) {
    const word = roundKeys[round * 4 + col];
    key[col * 4] = (word >> 24) & 0xff;
    key[col * 4 + 1] = (word >> 16) & 0xff;
    key[col * 4 + 2] = (word >> 8) & 0xff;
    key[col * 4 + 3] = word & 0xff;
  }
  return key;
}

/**
 * AES-256-ECB encrypt a single 16-byte block.
 */
function aes256EncryptBlock(block: Uint8Array, key: Uint8Array): Uint8Array {
  if (block.length !== 16) {
    throw new Error("AES block must be 16 bytes");
  }
  if (key.length !== 32) {
    throw new Error("AES-256 key must be 32 bytes");
  }

  const roundKeys = aes256KeyExpansion(key);
  // State is stored in column-major order as a flat 16-byte array
  const state = new Uint8Array(16);
  state.set(block);

  // AddRoundKey (initial)
  const rk0 = getRoundKey(roundKeys, 0);
  for (let i = 0; i < 16; i++) {
    state[i] ^= rk0[i];
  }

  // Rounds 1 through AES256_ROUNDS-1
  for (let round = 1; round < AES256_ROUNDS; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) {
      state[i] = SBOX[state[i]];
    }

    // ShiftRows
    shiftRows(state);

    // MixColumns
    mixColumns(state);

    // AddRoundKey
    const rk = getRoundKey(roundKeys, round);
    for (let i = 0; i < 16; i++) {
      state[i] ^= rk[i];
    }
  }

  // Final round (no MixColumns)
  for (let i = 0; i < 16; i++) {
    state[i] = SBOX[state[i]];
  }
  shiftRows(state);
  const rkFinal = getRoundKey(roundKeys, AES256_ROUNDS);
  for (let i = 0; i < 16; i++) {
    state[i] ^= rkFinal[i];
  }

  return state;
}

/**
 * AES-256-ECB decrypt a single 16-byte block.
 */
function aes256DecryptBlock(block: Uint8Array, key: Uint8Array): Uint8Array {
  if (block.length !== 16) {
    throw new Error("AES block must be 16 bytes");
  }
  if (key.length !== 32) {
    throw new Error("AES-256 key must be 32 bytes");
  }

  const roundKeys = aes256KeyExpansion(key);
  const state = new Uint8Array(16);
  state.set(block);

  // AddRoundKey (final round key first for decryption)
  const rkFinal = getRoundKey(roundKeys, AES256_ROUNDS);
  for (let i = 0; i < 16; i++) {
    state[i] ^= rkFinal[i];
  }

  // Inverse rounds: AES256_ROUNDS-1 down to 1
  for (let round = AES256_ROUNDS - 1; round >= 1; round--) {
    // InvShiftRows
    invShiftRows(state);

    // InvSubBytes
    for (let i = 0; i < 16; i++) {
      state[i] = INV_SBOX[state[i]];
    }

    // AddRoundKey
    const rk = getRoundKey(roundKeys, round);
    for (let i = 0; i < 16; i++) {
      state[i] ^= rk[i];
    }

    // InvMixColumns
    invMixColumns(state);
  }

  // Final inverse round (no InvMixColumns)
  invShiftRows(state);
  for (let i = 0; i < 16; i++) {
    state[i] = INV_SBOX[state[i]];
  }
  const rk0 = getRoundKey(roundKeys, 0);
  for (let i = 0; i < 16; i++) {
    state[i] ^= rk0[i];
  }

  return state;
}

/**
 * AES ShiftRows transformation.
 * State layout (row-major in 4x4 grid, stored column-major):
 *   index mapping: state[row + 4*col]
 * But we store row-major: state[row*4 + col]
 * Standard AES state is column-major, but we use row-major for simplicity:
 *   state[0..3] = row 0, state[4..7] = row 1, etc.
 */
function shiftRows(state: Uint8Array): void {
  // Row 1: shift left by 1
  const t1 = state[4];
  state[4] = state[5];
  state[5] = state[6];
  state[6] = state[7];
  state[7] = t1;

  // Row 2: shift left by 2
  const t2a = state[8];
  const t2b = state[9];
  state[8] = state[10];
  state[9] = state[11];
  state[10] = t2a;
  state[11] = t2b;

  // Row 3: shift left by 3 (= shift right by 1)
  const t3 = state[15];
  state[15] = state[14];
  state[14] = state[13];
  state[13] = state[12];
  state[12] = t3;
}

/**
 * AES InvShiftRows transformation.
 */
function invShiftRows(state: Uint8Array): void {
  // Row 1: shift right by 1
  const t1 = state[7];
  state[7] = state[6];
  state[6] = state[5];
  state[5] = state[4];
  state[4] = t1;

  // Row 2: shift right by 2
  const t2a = state[10];
  const t2b = state[11];
  state[10] = state[8];
  state[11] = state[9];
  state[8] = t2a;
  state[9] = t2b;

  // Row 3: shift right by 3 (= shift left by 1)
  const t3 = state[12];
  state[12] = state[13];
  state[13] = state[14];
  state[14] = state[15];
  state[15] = t3;
}

/**
 * AES MixColumns transformation.
 * Operates on each column of the 4x4 state.
 * With row-major layout: column c has bytes at [0*4+c, 1*4+c, 2*4+c, 3*4+c].
 */
function mixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const s0 = state[c];
    const s1 = state[4 + c];
    const s2 = state[8 + c];
    const s3 = state[12 + c];

    state[c] = gmul2(s0) ^ gmul3(s1) ^ s2 ^ s3;
    state[4 + c] = s0 ^ gmul2(s1) ^ gmul3(s2) ^ s3;
    state[8 + c] = s0 ^ s1 ^ gmul2(s2) ^ gmul3(s3);
    state[12 + c] = gmul3(s0) ^ s1 ^ s2 ^ gmul2(s3);
  }
}

/**
 * AES InvMixColumns transformation.
 */
function invMixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const s0 = state[c];
    const s1 = state[4 + c];
    const s2 = state[8 + c];
    const s3 = state[12 + c];

    state[c] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9);
    state[4 + c] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13);
    state[8 + c] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11);
    state[12 + c] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14);
  }
}

// ---------------------------------------------------------------------------
// Helper: convert state between row-major (for our AES) and standard byte order
// ---------------------------------------------------------------------------

/**
 * AES standard state layout is column-major (byte 0 = row0col0, byte 1 = row1col0, ...).
 * Our AES operates in row-major. Convert input bytes to row-major state.
 */
function bytesToState(bytes: Uint8Array): Uint8Array {
  const state = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      state[row * 4 + col] = bytes[col * 4 + row];
    }
  }
  return state;
}

/**
 * Convert our row-major state back to standard column-major byte order.
 */
function stateToBytes(state: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let col = 0; col < 4; col++) {
      bytes[col * 4 + row] = state[row * 4 + col];
    }
  }
  return bytes;
}

/**
 * Encrypt a single 16-byte block with AES-256-ECB.
 * Handles the column-major <-> row-major conversion internally.
 */
function aes256EcbEncrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  const state = bytesToState(plaintext);
  const encrypted = aes256EncryptBlock(state, key);
  return stateToBytes(encrypted);
}

/**
 * Decrypt a single 16-byte block with AES-256-ECB.
 * Handles the column-major <-> row-major conversion internally.
 */
function aes256EcbDecrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  const state = bytesToState(ciphertext);
  const decrypted = aes256DecryptBlock(state, key);
  return stateToBytes(decrypted);
}

// ---------------------------------------------------------------------------
// XOR helper
// ---------------------------------------------------------------------------

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// ---------------------------------------------------------------------------
// BIP38 double-SHA256 address hash
// ---------------------------------------------------------------------------

function computeAddressHash(address: string): Uint8Array {
  const encoder = new TextEncoder();
  const addressBytes = encoder.encode(address);
  const hash = sha256(sha256(addressBytes));
  return hash.slice(0, 4);
}

// ---------------------------------------------------------------------------
// Public key derivation from private key
// ---------------------------------------------------------------------------

function derivePublicKey(privateKey: Uint8Array, compressed: boolean): Uint8Array {
  return secp256k1.getPublicKey(privateKey, compressed);
}

// ---------------------------------------------------------------------------
// BIP38 Encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a private key using BIP38 (non-EC-multiply mode).
 *
 * @param privateKey - 32-byte raw private key
 * @param passphrase - User passphrase for encryption
 * @param compressed - Whether the key corresponds to a compressed public key
 * @param network - Network configuration for address derivation
 * @returns Base58Check-encoded encrypted key starting with "6P"
 */
export async function encryptBIP38(
  privateKey: Uint8Array,
  passphrase: string,
  compressed: boolean,
  network: NetworkConfig,
): Promise<string> {
  if (privateKey.length !== 32) {
    throw new Error("Private key must be 32 bytes");
  }

  // Step 1: Derive address from private key
  const pubKey = derivePublicKey(privateKey, compressed);
  const address = publicKeyToAddress(pubKey, network);

  // Step 2: Compute address hash (first 4 bytes of double-SHA256 of address string)
  const addressHash = computeAddressHash(address);

  // Step 3: Derive scrypt key
  const encoder = new TextEncoder();
  const passphraseBytes = encoder.encode(passphrase);
  const derivedKey = scrypt(passphraseBytes, addressHash, {
    N: 16384,
    r: 8,
    p: 8,
    dkLen: 64,
  });

  const derivedHalf1 = derivedKey.slice(0, 32);
  const derivedHalf2 = derivedKey.slice(32, 64);

  // Step 4: XOR private key halves with derived key halves, then AES encrypt
  const keyHalf1 = privateKey.slice(0, 16);
  const keyHalf2 = privateKey.slice(16, 32);

  const xored1 = xorBytes(keyHalf1, derivedHalf1.slice(0, 16));
  const xored2 = xorBytes(keyHalf2, derivedHalf1.slice(16, 32));

  const encryptedHalf1 = aes256EcbEncrypt(xored1, derivedHalf2);
  const encryptedHalf2 = aes256EcbEncrypt(xored2, derivedHalf2);

  // Step 5: Assemble BIP38 payload
  // 0x0142 + flagByte + addressHash(4) + encryptedHalf1(16) + encryptedHalf2(16) = 39 bytes
  const flagByte = compressed ? FLAG_COMPRESSED : FLAG_UNCOMPRESSED;
  const payload = new Uint8Array(39);
  payload[0] = BIP38_PREFIX_0;
  payload[1] = BIP38_PREFIX_1;
  payload[2] = flagByte;
  payload.set(addressHash, 3);
  payload.set(encryptedHalf1, 7);
  payload.set(encryptedHalf2, 23);

  return base58CheckEncode(payload);
}

// ---------------------------------------------------------------------------
// BIP38 Decrypt
// ---------------------------------------------------------------------------

export interface BIP38DecryptResult {
  privateKey: Uint8Array;
  compressed: boolean;
}

/**
 * Decrypt a BIP38-encrypted private key.
 *
 * @param encrypted - Base58Check-encoded encrypted key (starts with "6P")
 * @param passphrase - User passphrase used during encryption
 * @returns The decrypted private key and compression flag
 */
export async function decryptBIP38(
  encrypted: string,
  passphrase: string,
): Promise<BIP38DecryptResult> {
  const payload = base58CheckDecode(encrypted);

  if (payload.length !== 39) {
    throw new Error(
      `Invalid BIP38 payload length: expected 39, got ${payload.length}`,
    );
  }

  if (payload[0] !== BIP38_PREFIX_0 || payload[1] !== BIP38_PREFIX_1) {
    throw new Error("Invalid BIP38 prefix: expected 0x0142");
  }

  const flagByte = payload[2];
  let compressed: boolean;

  if (flagByte === FLAG_COMPRESSED) {
    compressed = true;
  } else if (flagByte === FLAG_UNCOMPRESSED) {
    compressed = false;
  } else {
    throw new Error(`Invalid BIP38 flag byte: 0x${flagByte.toString(16)}`);
  }

  const addressHash = payload.slice(3, 7);
  const encryptedHalf1 = payload.slice(7, 23);
  const encryptedHalf2 = payload.slice(23, 39);

  // Derive scrypt key using passphrase and address hash
  const encoder = new TextEncoder();
  const passphraseBytes = encoder.encode(passphrase);
  const derivedKey = scrypt(passphraseBytes, addressHash, {
    N: 16384,
    r: 8,
    p: 8,
    dkLen: 64,
  });

  const derivedHalf1 = derivedKey.slice(0, 32);
  const derivedHalf2 = derivedKey.slice(32, 64);

  // Decrypt and XOR to recover private key
  const decryptedHalf1 = aes256EcbDecrypt(encryptedHalf1, derivedHalf2);
  const decryptedHalf2 = aes256EcbDecrypt(encryptedHalf2, derivedHalf2);

  const keyHalf1 = xorBytes(decryptedHalf1, derivedHalf1.slice(0, 16));
  const keyHalf2 = xorBytes(decryptedHalf2, derivedHalf1.slice(16, 32));

  const privateKey = new Uint8Array(32);
  privateKey.set(keyHalf1, 0);
  privateKey.set(keyHalf2, 16);

  // Verify: derive address from recovered key and check address hash
  const pubKey = derivePublicKey(privateKey, compressed);
  // We need to verify the address hash matches. We don't have the network,
  // so we try both known FairCoin pubKeyHash versions.
  // FairCoin mainnet pubKeyHash=35, testnet pubKeyHash=65
  const KNOWN_PUBKEY_HASHES = [35, 65];
  let verified = false;

  for (const version of KNOWN_PUBKEY_HASHES) {
    const pkHash = computeHash160(pubKey);
    const address = encodeAddress(pkHash, version);
    const computedHash = computeAddressHash(address);

    if (
      computedHash[0] === addressHash[0] &&
      computedHash[1] === addressHash[1] &&
      computedHash[2] === addressHash[2] &&
      computedHash[3] === addressHash[3]
    ) {
      verified = true;
      break;
    }
  }

  if (!verified) {
    throw new Error(
      "BIP38 decryption failed: address hash mismatch (wrong passphrase or corrupted data)",
    );
  }

  return { privateKey, compressed };
}
