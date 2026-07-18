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
import { BufferWriter } from "./encoding.js";
import {
  serializeTransaction,
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
