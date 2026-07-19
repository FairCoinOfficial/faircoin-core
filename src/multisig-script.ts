/**
 * Generic m-of-n P2SH multisig redeem script construction and addressing.
 *
 * Mirrors address.ts/script.ts one level up: a "redeem script" here is what
 * a P2PKH scriptPubKey is there — the thing that gets hashed into an
 * address, except a multisig address requires the actual script (not just a
 * pubkey) to spend from, since OP_CHECKMULTISIG needs it on the stack.
 */
import { hash160 } from "./address.js";
import { encodeAddress } from "./encoding.js";
import type { NetworkConfig } from "./network.js";
import { Opcodes, pushData } from "./script.js";

/** Hard ceiling: only OP_1..OP_16 exist, so no more than 16 keys can be encoded. */
const MAX_PUBKEYS = 16;

/**
 * Bitcoin's standard-relay ceiling for a P2SH redeem script (MAX_SCRIPT_ELEMENT_SIZE).
 * A larger script is consensus-valid but non-standard: most nodes won't relay
 * or mine a spend from it, so a wallet must never construct one.
 */
const MAX_STANDARD_REDEEM_SCRIPT_SIZE = 520;

function opN(n: number): number {
  return Opcodes.OP_1 + n - 1;
}

/**
 * Build a raw m-of-n multisig redeem script:
 * `OP_m <pubkey1> <pubkey2> ... <pubkeyN> OP_n OP_CHECKMULTISIG`.
 *
 * Pubkeys must be given in the exact order all cosigners agree on — that
 * order is baked into the script (and therefore the address) and is also
 * the order `assembleMultisigScriptSig` (multisig-sign.ts) requires
 * signatures to be presented in.
 */
export function createMultisigRedeemScript(m: number, pubkeys: Uint8Array[]): Uint8Array {
  const n = pubkeys.length;

  if (!Number.isInteger(m) || m < 1) {
    throw new Error(`Invalid multisig threshold m=${m}: must be a positive integer`);
  }
  if (n < 1 || n > MAX_PUBKEYS) {
    throw new Error(`Invalid multisig pubkey count n=${n}: must be between 1 and ${MAX_PUBKEYS}`);
  }
  if (m > n) {
    throw new Error(`Invalid multisig threshold: m=${m} cannot exceed n=${n}`);
  }
  for (const pubkey of pubkeys) {
    if (pubkey.length !== 33 && pubkey.length !== 65) {
      throw new Error(
        `Invalid public key length: expected 33 (compressed) or 65 (uncompressed), got ${pubkey.length}`,
      );
    }
  }

  const parts: Uint8Array[] = [new Uint8Array([opN(m)])];
  for (const pubkey of pubkeys) {
    parts.push(pushData(pubkey));
  }
  parts.push(new Uint8Array([opN(n)]));
  parts.push(new Uint8Array([Opcodes.OP_CHECKMULTISIG]));

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  if (total > MAX_STANDARD_REDEEM_SCRIPT_SIZE) {
    throw new Error(
      `Redeem script is ${total} bytes, exceeding the ${MAX_STANDARD_REDEEM_SCRIPT_SIZE}-byte standard relay limit`,
    );
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** A redeem script parsed back into its threshold and ordered pubkeys. */
export interface ParsedMultisigRedeemScript {
  /** Required-signature threshold (`m` in m-of-n). */
  m: number;
  /** The cosigner pubkeys, in the exact order they appear in the script. */
  pubkeys: Uint8Array[];
}

/**
 * Parse an m-of-n redeem script produced by `createMultisigRedeemScript` back
 * into its threshold `m` and ordered pubkeys, validating the full
 * `OP_m <pubkey1>...<pubkeyN> OP_n OP_CHECKMULTISIG` structure and the
 * `1 <= m <= n <= 16` bounds. Throws on any malformed script. This is the
 * inverse of `createMultisigRedeemScript` and the single source of truth for
 * reading a redeem script's parameters (fee estimation and signature
 * assembly both derive `m` from here rather than trusting a passed-in value).
 */
export function parseMultisigRedeemScript(redeemScript: Uint8Array): ParsedMultisigRedeemScript {
  if (redeemScript.length < 3) {
    throw new Error("Redeem script too short to be a multisig script");
  }
  const mOpcode = redeemScript[0];
  if (mOpcode < Opcodes.OP_1 || mOpcode > Opcodes.OP_16) {
    throw new Error("Redeem script does not start with a valid OP_m");
  }
  const m = mOpcode - Opcodes.OP_1 + 1;

  const pubkeys: Uint8Array[] = [];
  let offset = 1;
  while (offset < redeemScript.length) {
    const next = redeemScript[offset];
    if (next >= Opcodes.OP_1 && next <= Opcodes.OP_16) {
      if (
        offset + 2 !== redeemScript.length ||
        redeemScript[offset + 1] !== Opcodes.OP_CHECKMULTISIG
      ) {
        throw new Error("Malformed multisig redeem script");
      }
      const n = next - Opcodes.OP_1 + 1;
      if (n !== pubkeys.length) {
        throw new Error(
          `Redeem script declares n=${n} but contains ${pubkeys.length} pubkey pushes`,
        );
      }
      if (m > n) {
        throw new Error(`Invalid multisig redeem script: m=${m} cannot exceed n=${n}`);
      }
      return { m, pubkeys };
    }

    const len = next;
    if (len === 0 || len >= Opcodes.OP_PUSHDATA1) {
      throw new Error("Malformed multisig redeem script: expected a pubkey push");
    }
    // A multisig cosigner is a secp256k1 EC point: 33 bytes compressed
    // (0x02/0x03 prefix) or 65 bytes uncompressed (0x04 prefix). Any other
    // push length can only come from an attacker-crafted or corrupted
    // script -- createMultisigRedeemScript never produces one -- so reject
    // it here rather than silently parsing garbage as a "pubkey".
    if (len !== 33 && len !== 65) {
      throw new Error(
        `Malformed multisig redeem script: pubkey push must be 33 (compressed) or 65 (uncompressed) bytes, got ${len}`,
      );
    }
    if (offset + 1 + len > redeemScript.length) {
      throw new Error("Malformed multisig redeem script: truncated pubkey push");
    }
    pubkeys.push(redeemScript.slice(offset + 1, offset + 1 + len));
    offset += 1 + len;
  }

  throw new Error("Malformed multisig redeem script: missing OP_n OP_CHECKMULTISIG tail");
}

/**
 * Read just the required-signature threshold `m` from a redeem script. A thin
 * wrapper over `parseMultisigRedeemScript` for callers (fee estimation) that
 * only need `m` -- it still fully validates the script, so a malformed or
 * mismatched script can never silently yield a wrong threshold.
 */
export function readMultisigThreshold(redeemScript: Uint8Array): number {
  return parseMultisigRedeemScript(redeemScript).m;
}

/**
 * Derive the P2SH address for a redeem script: `hash160(redeemScript)`
 * encoded with the network's script-hash version byte.
 */
export function multisigAddress(redeemScript: Uint8Array, network: NetworkConfig): string {
  return encodeAddress(hash160(redeemScript), network.scriptHash);
}
