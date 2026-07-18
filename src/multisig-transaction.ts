/**
 * Transaction building for spending FROM a P2SH multisig UTXO. All UTXOs
 * passed to `buildMultisigSpend` must share the SAME redeem script (a
 * single multisig wallet/Pocket). Spending a mix of P2PKH and P2SH-multisig
 * inputs in one transaction, or inputs with DIFFERENT redeem scripts, is
 * out of scope for Layer 1.
 */
import type { NetworkConfig } from "./network.js";
import { scriptForAddress } from "./script.js";
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
 */
export function estimateMultisigInputSize(m: number, redeemScriptLength: number): number {
  if (!Number.isInteger(m) || m < 1) {
    throw new Error(`Invalid multisig threshold m=${m}: must be a positive integer`);
  }
  const sigPushSize = pushSize(MAX_DER_SIG_WITH_HASHTYPE);
  const redeemPushSize = pushSize(redeemScriptLength);
  const scriptSigSize = 1 /* OP_0 dummy element */ + m * sigPushSize + redeemPushSize;
  return 36 + varIntSize(scriptSigSize) + scriptSigSize + 4;
}

/**
 * Estimate the byte size of a transaction whose inputs are ALL P2SH
 * multisig inputs sharing the same (m, redeem script length).
 */
export function estimateMultisigTxSize(
  numInputs: number,
  numOutputs: number,
  m: number,
  redeemScriptLength: number,
): number {
  return (
    TX_OVERHEAD +
    numInputs * estimateMultisigInputSize(m, redeemScriptLength) +
    numOutputs * P2PKH_OUTPUT_SIZE
  );
}

export interface BuildMultisigSpendParams {
  /** UTXOs to spend, all locked by the SAME redeem script. */
  utxos: UTXO[];
  /** The shared redeem script that locks every UTXO above. */
  redeemScript: Uint8Array;
  /** Required signature count (for fee estimation only; not enforced here). */
  m: number;
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
  const { utxos, redeemScript, m, recipients, changeAddress, feePerByte, network } = params;

  if (utxos.length === 0) {
    throw new Error("No UTXOs provided");
  }
  if (recipients.length === 0) {
    throw new Error("No recipients provided");
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
    m,
    redeemScript.length,
  );
  const feeWithChange = feePerByte * BigInt(sizeWithChange);

  const sizeWithoutChange = estimateMultisigTxSize(
    utxos.length,
    recipients.length,
    m,
    redeemScript.length,
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
