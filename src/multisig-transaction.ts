/**
 * Transaction building for spending FROM a P2SH multisig UTXO. All UTXOs
 * passed to `buildMultisigSpend` must share the SAME redeem script (a
 * single multisig wallet/Pocket). Spending a mix of P2PKH and P2SH-multisig
 * inputs in one transaction, or inputs with DIFFERENT redeem scripts, is
 * out of scope for Layer 1.
 */
import { hash160 } from "./address.js";
import { bytesEqual } from "./encoding.js";
import { readMultisigThreshold } from "./multisig-script.js";
import type { NetworkConfig } from "./network.js";
import { createP2SHScript, scriptForAddress } from "./script.js";
import { SMALLEST_UNIT_NAME } from "./branding.js";
import type { Transaction, TxInput, TxOutput, UTXO } from "./transaction.js";

const TX_OVERHEAD = 10; // version(4) + vin count(~1) + vout count(~1) + locktime(4)
const P2PKH_OUTPUT_SIZE = 34; // value(8) + scriptLen(1) + scriptPubKey(25)
const DEFAULT_SEQUENCE = 0xffffffff;

/**
 * Max DER-encoded ECDSA signature length (72 bytes) plus the 1-byte SIGHASH
 * suffix, per Bitcoin Core's own conservative fee-estimation convention.
 * Real signatures are usually 1-2 bytes shorter, so sizing against this
 * bound never underpays a multisig spend's fee.
 */
const MAX_DER_SIG_WITH_HASHTYPE = 73;

/**
 * Size of a script push for `dataLength` bytes: a 1-byte length prefix for
 * data under 76 bytes, an OP_PUSHDATA1 + 1-byte length for up to 255 bytes
 * (the practical ceiling for a standard, relay-eligible multisig redeem
 * script).
 */
function pushSize(dataLength: number): number {
  if (dataLength < 0x4c) return 1 + dataLength;
  if (dataLength <= 0xff) return 2 + dataLength;
  return 3 + dataLength;
}

/** Size of the varint prefix a transaction's scriptSig-length field takes. */
function varIntSize(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  return 5;
}

/**
 * Estimate the byte size of ONE P2SH multisig input: outpoint(36) +
 * scriptSig-length varint + scriptSig + sequence(4). The scriptSig is
 * `OP_0 <sig>...<sig> <redeemScript>` (see `assembleMultisigScriptSig`).
 *
 * The threshold `m` is derived from `redeemScript` itself -- it is exactly
 * `redeemScript[0] - OP_1 + 1` -- so a caller cannot pass a wrong `m` and
 * under-fee (and thereby strand) the transaction.
 */
export function estimateMultisigInputSize(redeemScript: Uint8Array): number {
  const m = readMultisigThreshold(redeemScript);
  const sigPushSize = pushSize(MAX_DER_SIG_WITH_HASHTYPE);
  const redeemPushSize = pushSize(redeemScript.length);
  const scriptSigSize = 1 /* OP_0 dummy element */ + m * sigPushSize + redeemPushSize;
  return 36 + varIntSize(scriptSigSize) + scriptSigSize + 4;
}

/**
 * Estimate the byte size of a transaction whose inputs are ALL P2SH
 * multisig inputs locked by the same redeem script.
 */
export function estimateMultisigTxSize(
  numInputs: number,
  numOutputs: number,
  redeemScript: Uint8Array,
): number {
  return (
    TX_OVERHEAD +
    numInputs * estimateMultisigInputSize(redeemScript) +
    numOutputs * P2PKH_OUTPUT_SIZE
  );
}

export interface BuildMultisigSpendParams {
  /** UTXOs to spend, all locked by the SAME redeem script. */
  utxos: UTXO[];
  /** The shared redeem script that locks every UTXO above. */
  redeemScript: Uint8Array;
  recipients: Array<{ address: string; value: bigint }>;
  /** Where any change goes -- typically the same multisig address. */
  changeAddress: string;
  feePerByte: bigint;
  network: NetworkConfig;
}

/**
 * Build an unsigned transaction spending one or more P2SH multisig UTXOs.
 * Mirrors `buildTransaction`'s coin-accounting shape (spend everything
 * given, compute a change output if it clears the dust threshold) but sizes
 * the fee for multisig scriptSigs and pays recipients/change through
 * `scriptForAddress` so a P2SH destination (e.g. change back to the same
 * multisig address) is encoded correctly.
 *
 * Returns an UNSIGNED transaction: each input's `scriptSig` must still be
 * produced via `signMultisigInput` (per cosigner) + `assembleMultisigScriptSig`.
 */
export function buildMultisigSpend(params: BuildMultisigSpendParams): Transaction {
  const { utxos, redeemScript, recipients, changeAddress, feePerByte, network } = params;

  if (utxos.length === 0) {
    throw new Error("No UTXOs provided");
  }
  if (recipients.length === 0) {
    throw new Error("No recipients provided");
  }

  // Every UTXO must be locked by THIS redeem script's P2SH address. Signing
  // against a UTXO whose scriptPubKey belongs to some other script silently
  // builds an unspendable transaction -- the redeem script we later reveal
  // won't hash to the output being spent, so CHECKMULTISIG never runs. Reject
  // any mismatch up front, before signing work begins.
  const expectedScriptPubKey = createP2SHScript(hash160(redeemScript));
  for (const utxo of utxos) {
    if (!bytesEqual(utxo.scriptPubKey, expectedScriptPubKey)) {
      throw new Error("UTXO scriptPubKey does not match redeemScript's P2SH address");
    }
  }

  let totalIn = 0n;
  for (const utxo of utxos) {
    totalIn += utxo.value;
  }

  let totalOut = 0n;
  for (const recipient of recipients) {
    if (recipient.value <= 0n) {
      throw new Error("Recipient value must be positive");
    }
    totalOut += recipient.value;
  }

  const sizeWithChange = estimateMultisigTxSize(
    utxos.length,
    recipients.length + 1,
    redeemScript,
  );
  const feeWithChange = feePerByte * BigInt(sizeWithChange);

  const sizeWithoutChange = estimateMultisigTxSize(
    utxos.length,
    recipients.length,
    redeemScript,
  );
  const feeWithoutChange = feePerByte * BigInt(sizeWithoutChange);

  if (totalIn < totalOut + feeWithoutChange) {
    throw new Error(
      `Insufficient funds: have ${totalIn} ${SMALLEST_UNIT_NAME}, need ${totalOut + feeWithoutChange} (${totalOut} + ${feeWithoutChange} fee)`,
    );
  }

  const outputs: TxOutput[] = recipients.map((recipient) => ({
    value: recipient.value,
    scriptPubKey: scriptForAddress(recipient.address, network),
  }));

  const changeAmount = totalIn - totalOut - feeWithChange;
  if (changeAmount > network.minRelayFee) {
    outputs.push({
      value: changeAmount,
      scriptPubKey: scriptForAddress(changeAddress, network),
    });
  }

  const inputs: TxInput[] = utxos.map((utxo) => ({
    txid: utxo.txid,
    vout: utxo.vout,
    scriptSig: new Uint8Array(0),
    sequence: DEFAULT_SEQUENCE,
  }));

  return {
    version: 1,
    inputs,
    outputs,
    lockTime: 0,
  };
}
