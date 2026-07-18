/**
 * Multisig (P2SH) input signing for FairCoin transactions.
 *
 * Bitcoin's OP_CHECKMULTISIG requires the sighash for a P2SH multisig input
 * to be computed against the REDEEM SCRIPT (not the P2SH scriptPubKey) --
 * this is the BIP16 "scriptCode substitution" rule. `computeMultisigSigHash`
 * is the multisig analogue of the private `computeSigHash` in
 * transaction.ts; `signMultisigInput` returns a BARE DER signature (never a
 * finished scriptSig -- the P2SH scriptSig needs `m` of these from
 * different cosigners before it can be finalized, see
 * `assembleMultisigScriptSig` further down this file, added in Task 3).
 *
 * Importing from transaction.ts below also runs its module-level
 * `secp256k1.etc.hmacSha256Sync` configuration (deterministic RFC6979
 * signing) as a side effect of ES module evaluation -- that assignment
 * happens once, the first time transaction.ts is loaded, so it is not
 * repeated here.
 */
import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import { bytesToHex, hexToBytes, BufferWriter } from "./encoding.js";
import { Opcodes, pushData } from "./script.js";
import {
  serializeTransaction,
  deserializeTransaction,
  derEncodeSignature,
  type Transaction,
  SIGHASH_ALL,
} from "./transaction.js";

/**
 * Compute the SIGHASH_ALL sighash for a P2SH multisig input: identical to
 * `signInput`'s algorithm, except the scriptCode substituted into the input
 * being signed is the REDEEM SCRIPT, per BIP16.
 */
export function computeMultisigSigHash(
  tx: Transaction,
  inputIndex: number,
  redeemScript: Uint8Array,
  hashType: number = SIGHASH_ALL,
): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(
      `Input index ${inputIndex} out of range [0, ${tx.inputs.length})`,
    );
  }

  const sigTx: Transaction = {
    version: tx.version,
    inputs: tx.inputs.map((input, idx) => ({
      txid: input.txid,
      vout: input.vout,
      scriptSig: idx === inputIndex ? redeemScript : new Uint8Array(0),
      sequence: input.sequence,
    })),
    outputs: tx.outputs.map((output) => ({
      value: output.value,
      scriptPubKey: output.scriptPubKey,
    })),
    lockTime: tx.lockTime,
  };

  const writer = new BufferWriter();
  writer.writeBytes(serializeTransaction(sigTx));
  writer.writeUInt32LE(hashType);

  return sha256(sha256(writer.toBytes()));
}

/**
 * Sign a P2SH multisig input with ONE private key. Returns a BARE DER
 * signature + SIGHASH_ALL byte -- NOT a finished scriptSig. The private key
 * never leaves this function's stack frame and is never part of the return
 * value; combine the returned signatures from `m` different cosigners with
 * `assembleMultisigScriptSig` (Task 3) to produce the final, broadcastable
 * scriptSig.
 */
export function signMultisigInput(
  tx: Transaction,
  inputIndex: number,
  redeemScript: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array {
  const sigHash = computeMultisigSigHash(tx, inputIndex, redeemScript, SIGHASH_ALL);

  const signature = secp256k1.sign(sigHash, privateKey);
  const normalizedSig = signature.hasHighS() ? signature.normalizeS() : signature;
  const derSig = derEncodeSignature(normalizedSig.r, normalizedSig.s);

  const sigWithHashType = new Uint8Array(derSig.length + 1);
  sigWithHashType.set(derSig, 0);
  sigWithHashType[derSig.length] = SIGHASH_ALL;

  return sigWithHashType;
}

/**
 * Parse the pubkeys (in order) out of a redeem script built by
 * `createMultisigRedeemScript`. Used by `assembleMultisigScriptSig` to order
 * signatures correctly -- OP_CHECKMULTISIG requires signatures in the SAME
 * relative order as their pubkeys appear in the script, even when signing a
 * strict subset (m < n).
 */
function extractPubkeysFromMultisigRedeemScript(redeemScript: Uint8Array): Uint8Array[] {
  if (redeemScript.length < 3) {
    throw new Error("Redeem script too short to be a multisig script");
  }
  const mOpcode = redeemScript[0];
  if (mOpcode < Opcodes.OP_1 || mOpcode > Opcodes.OP_16) {
    throw new Error("Redeem script does not start with a valid OP_m");
  }

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
      return pubkeys;
    }

    const len = next;
    if (len === 0 || len >= Opcodes.OP_PUSHDATA1) {
      throw new Error("Malformed multisig redeem script: expected a pubkey push");
    }
    if (offset + 1 + len > redeemScript.length) {
      throw new Error("Malformed multisig redeem script: truncated pubkey push");
    }
    pubkeys.push(redeemScript.slice(offset + 1, offset + 1 + len));
    offset += 1 + len;
  }

  throw new Error("Malformed multisig redeem script: missing OP_n OP_CHECKMULTISIG tail");
}

/** One cosigner's signature for a specific input, paired with their pubkey. */
export interface PartialSignature {
  pubkey: Uint8Array;
  /** Output of `signMultisigInput`: a bare DER signature + SIGHASH byte. */
  signature: Uint8Array;
}

/**
 * Assemble the final P2SH multisig scriptSig from `m` (or more) partial
 * signatures: `OP_0 <sig>...<sig> <redeemScript>`. Signatures are reordered
 * to match their pubkeys' order in the redeem script -- callers do not need
 * to track cosigning order themselves.
 *
 * The leading OP_0 is MANDATORY: it is a dummy stack element that works
 * around a bug in Bitcoin's original OP_CHECKMULTISIG implementation (it
 * pops one extra stack value it never uses). Omitting it makes the script
 * fail EVERY time, permanently locking the funds.
 */
export function assembleMultisigScriptSig(
  signatures: PartialSignature[],
  redeemScript: Uint8Array,
): Uint8Array {
  const pubkeyOrder = extractPubkeysFromMultisigRedeemScript(redeemScript).map(bytesToHex);

  // Resolve each signature's position via a `.map()` pass (which always
  // visits every element) rather than inside the `.sort()` comparator --
  // `Array.prototype.sort` never invokes its comparator for arrays of
  // length 0 or 1, so a membership check placed there would silently skip
  // validating a single foreign signature.
  const indexed = signatures.map((sig) => {
    const index = pubkeyOrder.indexOf(bytesToHex(sig.pubkey));
    if (index === -1) {
      throw new Error("A signature's pubkey is not part of this redeem script");
    }
    return { index, signature: sig.signature };
  });
  const ordered = indexed.sort((a, b) => a.index - b.index);

  const parts: Uint8Array[] = [new Uint8Array([Opcodes.OP_0])];
  for (const { signature } of ordered) {
    parts.push(pushData(signature));
  }
  parts.push(pushData(redeemScript));

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * A signing request for ONE input of an unsigned multisig transaction: what
 * a coordinator device sends to a cosigner device so it can produce its
 * `PartialSignature` without ever needing the other cosigners' keys.
 */
export interface MultisigSigningRequest {
  tx: Transaction;
  inputIndex: number;
  redeemScript: Uint8Array;
}

/** Wire-friendly (JSON-serializable) form of {@link MultisigSigningRequest}. */
export interface SerializedMultisigSigningRequest {
  txHex: string;
  inputIndex: number;
  redeemScriptHex: string;
}

/**
 * Serialize a signing request for transport between cosigner devices (e.g.
 * QR code, file export, relay server). Carries no private key material --
 * only the unsigned transaction, which input to sign, and the redeem script.
 */
export function serializeMultisigSigningRequest(
  request: MultisigSigningRequest,
): SerializedMultisigSigningRequest {
  return {
    txHex: bytesToHex(serializeTransaction(request.tx)),
    inputIndex: request.inputIndex,
    redeemScriptHex: bytesToHex(request.redeemScript),
  };
}

/** Inverse of {@link serializeMultisigSigningRequest}. */
export function deserializeMultisigSigningRequest(
  serialized: SerializedMultisigSigningRequest,
): MultisigSigningRequest {
  return {
    tx: deserializeTransaction(hexToBytes(serialized.txHex)),
    inputIndex: serialized.inputIndex,
    redeemScript: hexToBytes(serialized.redeemScriptHex),
  };
}
