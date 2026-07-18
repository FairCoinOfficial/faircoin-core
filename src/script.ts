/**
 * Bitcoin-compatible script construction and parsing for FairCoin.
 */

import { decodeAddress, encodeAddress } from "./encoding.js";
import type { NetworkConfig } from "./network.js";

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

export const Opcodes = {
  OP_0: 0x00,
  OP_FALSE: 0x00,
  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51,
  OP_TRUE: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_8: 0x58,
  OP_9: 0x59,
  OP_10: 0x5a,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_13: 0x5d,
  OP_14: 0x5e,
  OP_15: 0x5f,
  OP_16: 0x60,
  OP_NOP: 0x61,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_RETURN: 0x6a,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_DUP: 0x76,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_HASH160: 0xa9,
  OP_CHECKSIG: 0xac,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKLOCKTIMEVERIFY: 0xb1,
  OP_CHECKSEQUENCEVERIFY: 0xb2,
} as const;

// ---------------------------------------------------------------------------
// Push data encoding
// ---------------------------------------------------------------------------

/**
 * Encode a data push according to Bitcoin script rules.
 * Returns the opcode(s) + data that push `data` onto the stack.
 */
export function pushData(data: Uint8Array): Uint8Array {
  const len = data.length;

  if (len === 0) {
    return new Uint8Array([Opcodes.OP_0]);
  }

  // Single byte 1-16 can use OP_1 through OP_16
  if (len === 1 && data[0] >= 1 && data[0] <= 16) {
    return new Uint8Array([Opcodes.OP_1 + data[0] - 1]);
  }

  if (len < Opcodes.OP_PUSHDATA1) {
    // Direct push: length byte followed by data
    const result = new Uint8Array(1 + len);
    result[0] = len;
    result.set(data, 1);
    return result;
  }

  if (len <= 0xff) {
    const result = new Uint8Array(2 + len);
    result[0] = Opcodes.OP_PUSHDATA1;
    result[1] = len;
    result.set(data, 2);
    return result;
  }

  if (len <= 0xffff) {
    const result = new Uint8Array(3 + len);
    result[0] = Opcodes.OP_PUSHDATA2;
    result[1] = len & 0xff;
    result[2] = (len >> 8) & 0xff;
    result.set(data, 3);
    return result;
  }

  const result = new Uint8Array(5 + len);
  result[0] = Opcodes.OP_PUSHDATA4;
  result[1] = len & 0xff;
  result[2] = (len >> 8) & 0xff;
  result[3] = (len >> 16) & 0xff;
  result[4] = (len >> 24) & 0xff;
  result.set(data, 5);
  return result;
}

// ---------------------------------------------------------------------------
// Standard script templates
// ---------------------------------------------------------------------------

/**
 * P2PKH scriptPubKey:
 * OP_DUP OP_HASH160 <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
 */
export function createP2PKHScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) {
    throw new Error("P2PKH hash160 must be 20 bytes");
  }
  const script = new Uint8Array(25);
  script[0] = Opcodes.OP_DUP;
  script[1] = Opcodes.OP_HASH160;
  script[2] = 0x14; // push 20 bytes
  script.set(hash160, 3);
  script[23] = Opcodes.OP_EQUALVERIFY;
  script[24] = Opcodes.OP_CHECKSIG;
  return script;
}

/**
 * P2SH scriptPubKey:
 * OP_HASH160 <20-byte script hash> OP_EQUAL
 */
export function createP2SHScript(hash160: Uint8Array): Uint8Array {
  if (hash160.length !== 20) {
    throw new Error("P2SH hash160 must be 20 bytes");
  }
  const script = new Uint8Array(23);
  script[0] = Opcodes.OP_HASH160;
  script[1] = 0x14; // push 20 bytes
  script.set(hash160, 2);
  script[22] = Opcodes.OP_EQUAL;
  return script;
}

/**
 * P2PKH scriptSig (input unlocking script):
 * <signature> <publicKey>
 */
export function createP2PKHScriptSig(
  signature: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array {
  const sigPush = pushData(signature);
  const pkPush = pushData(publicKey);
  const result = new Uint8Array(sigPush.length + pkPush.length);
  result.set(sigPush, 0);
  result.set(pkPush, sigPush.length);
  return result;
}

/**
 * Build the correct scriptPubKey for an address: P2SH if the address's
 * version byte matches the network's script-hash version, P2PKH if it
 * matches the pubkey-hash version. Used by transaction builders so a
 * multisig (P2SH) address is paid correctly instead of being mistaken for
 * a single-key destination.
 */
export function scriptForAddress(address: string, network: NetworkConfig): Uint8Array {
  const decoded = decodeAddress(address);
  if (decoded.version === network.scriptHash) {
    return createP2SHScript(decoded.hash);
  }
  if (decoded.version === network.pubKeyHash) {
    return createP2PKHScript(decoded.hash);
  }
  throw new Error(
    `Address ${address} does not match network ${network.name} (version byte ${decoded.version})`,
  );
}

// ---------------------------------------------------------------------------
// Script analysis
// ---------------------------------------------------------------------------

/** Check if a script matches the P2PKH pattern (25 bytes). */
export function isP2PKHScript(script: Uint8Array): boolean {
  return (
    script.length === 25 &&
    script[0] === Opcodes.OP_DUP &&
    script[1] === Opcodes.OP_HASH160 &&
    script[2] === 0x14 &&
    script[23] === Opcodes.OP_EQUALVERIFY &&
    script[24] === Opcodes.OP_CHECKSIG
  );
}

/** Check if a script matches the P2SH pattern (23 bytes). */
export function isP2SHScript(script: Uint8Array): boolean {
  return (
    script.length === 23 &&
    script[0] === Opcodes.OP_HASH160 &&
    script[1] === 0x14 &&
    script[22] === Opcodes.OP_EQUAL
  );
}

/**
 * Extract the destination address from a standard scriptPubKey.
 * Returns null for non-standard scripts.
 */
export function extractAddressFromScript(
  script: Uint8Array,
  network: NetworkConfig,
): string | null {
  if (isP2PKHScript(script)) {
    const hash = script.slice(3, 23);
    return encodeAddress(hash, network.pubKeyHash);
  }
  if (isP2SHScript(script)) {
    const hash = script.slice(2, 22);
    return encodeAddress(hash, network.scriptHash);
  }
  return null;
}
