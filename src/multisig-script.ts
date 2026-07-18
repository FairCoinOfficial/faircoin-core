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

/**
 * Derive the P2SH address for a redeem script: `hash160(redeemScript)`
 * encoded with the network's script-hash version byte.
 */
export function multisigAddress(redeemScript: Uint8Array, network: NetworkConfig): string {
  return encodeAddress(hash160(redeemScript), network.scriptHash);
}
