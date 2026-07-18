/**
 * FairCoin transaction construction, serialization, and signing.
 * Follows Bitcoin's pre-SegWit transaction format (version 1).
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import * as secp256k1 from "@noble/secp256k1";
import {
  BufferWriter,
  BufferReader,
  bytesToHex,
  hexToBytes,
} from "./encoding.js";
import type { NetworkConfig } from "./network.js";
import { createP2PKHScriptSig, scriptForAddress } from "./script.js";
import { SMALLEST_UNIT_NAME } from "./branding.js";

// Configure @noble/secp256k1 v2 HMAC for synchronous signing
secp256k1.etc.hmacSha256Sync = (
  key: Uint8Array,
  ...messages: Uint8Array[]
): Uint8Array => hmac(sha256, key, secp256k1.etc.concatBytes(...messages));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const SIGHASH_ALL = 0x01;
const DEFAULT_SEQUENCE = 0xffffffff;

/** Estimated byte sizes for P2PKH transactions. */
const TX_OVERHEAD = 10; // version(4) + vin count(~1) + vout count(~1) + locktime(4)
const P2PKH_INPUT_SIZE = 148; // outpoint(36) + scriptLen(1) + scriptSig(~107) + sequence(4)
const P2PKH_OUTPUT_SIZE = 34; // value(8) + scriptLen(1) + scriptPubKey(25)

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface TxInput {
  /** Previous transaction hash as hex (64 characters, display order). */
  txid: string;
  /** Output index in the previous transaction. */
  vout: number;
  /** Unlocking script (empty before signing). */
  scriptSig: Uint8Array;
  /** Sequence number, default 0xffffffff. */
  sequence: number;
}

export interface TxOutput {
  /** Value in satoshis. */
  value: bigint;
  /** Locking script (scriptPubKey). */
  scriptPubKey: Uint8Array;
}

export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  lockTime: number;
}

export interface UTXO {
  txid: string;
  vout: number;
  value: bigint;
  scriptPubKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a transaction to raw bytes (Bitcoin pre-SegWit format).
 */
export function serializeTransaction(tx: Transaction): Uint8Array {
  const writer = new BufferWriter();

  // Version (int32 LE)
  writer.writeInt32LE(tx.version);

  // Inputs
  writer.writeVarInt(tx.inputs.length);
  for (const input of tx.inputs) {
    writer.writeHash(input.txid);
    writer.writeUInt32LE(input.vout);
    writer.writeVarInt(input.scriptSig.length);
    writer.writeBytes(input.scriptSig);
    writer.writeUInt32LE(input.sequence);
  }

  // Outputs
  writer.writeVarInt(tx.outputs.length);
  for (const output of tx.outputs) {
    writer.writeUInt64LE(output.value);
    writer.writeVarInt(output.scriptPubKey.length);
    writer.writeBytes(output.scriptPubKey);
  }

  // Lock time
  writer.writeUInt32LE(tx.lockTime);

  return writer.toBytes();
}

/**
 * Deserialize a transaction from raw bytes.
 */
export function deserializeTransaction(raw: Uint8Array): Transaction {
  const reader = new BufferReader(raw);

  const version = reader.readInt32LE();

  const inputCount = reader.readVarInt();
  const inputs: TxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = reader.readHash();
    const vout = reader.readUInt32LE();
    const scriptLen = reader.readVarInt();
    const scriptSig = reader.readBytes(scriptLen);
    const sequence = reader.readUInt32LE();
    inputs.push({ txid, vout, scriptSig, sequence });
  }

  const outputCount = reader.readVarInt();
  const outputs: TxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    const value = reader.readUInt64LE();
    const scriptLen = reader.readVarInt();
    const scriptPubKey = reader.readBytes(scriptLen);
    outputs.push({ value, scriptPubKey });
  }

  const lockTime = reader.readUInt32LE();

  return { version, inputs, outputs, lockTime };
}

/**
 * Compute the transaction ID (double SHA-256 of the serialized tx, byte-reversed).
 */
export function hashTransaction(tx: Transaction): string {
  const raw = serializeTransaction(tx);
  const hash = sha256(sha256(raw));
  // txid is displayed in reversed byte order
  const reversed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    reversed[i] = hash[31 - i];
  }
  return bytesToHex(reversed);
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Compute the sighash for signing an input (SIGHASH_ALL).
 *
 * For SIGHASH_ALL:
 * 1. Copy the transaction
 * 2. Clear all input scripts
 * 3. Set the script for the input being signed to prevScriptPubKey
 * 4. Append the hash type as a uint32 LE
 * 5. Double SHA-256
 */
function computeSigHash(
  tx: Transaction,
  inputIndex: number,
  prevScriptPubKey: Uint8Array,
  hashType: number,
): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(
      `Input index ${inputIndex} out of range [0, ${tx.inputs.length})`,
    );
  }

  // Build the signing serialization
  const sigTx: Transaction = {
    version: tx.version,
    inputs: tx.inputs.map((input, idx) => ({
      txid: input.txid,
      vout: input.vout,
      scriptSig:
        idx === inputIndex ? prevScriptPubKey : new Uint8Array(0),
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
 * Encode a bigint as a DER integer (minimal, positive).
 */
function derEncodeInteger(n: bigint): Uint8Array {
  // Convert bigint to big-endian byte array
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  // If high bit is set, prepend 0x00 to keep it positive
  if (bytes[0] >= 0x80) {
    bytes.unshift(0x00);
  }
  return new Uint8Array([0x02, bytes.length, ...bytes]);
}

/**
 * DER-encode an ECDSA signature from r and s bigints.
 * Format: 0x30 <total len> 0x02 <r len> <r> 0x02 <s len> <s>
 */
export function derEncodeSignature(r: bigint, s: bigint): Uint8Array {
  const rEnc = derEncodeInteger(r);
  const sEnc = derEncodeInteger(s);
  const totalLen = rEnc.length + sEnc.length;
  const result = new Uint8Array(2 + totalLen);
  result[0] = 0x30;
  result[1] = totalLen;
  result.set(rEnc, 2);
  result.set(sEnc, 2 + rEnc.length);
  return result;
}

/**
 * Sign a transaction input using a private key with SIGHASH_ALL.
 * Returns the complete scriptSig (DER signature + hash type + public key push).
 */
export function signInput(
  tx: Transaction,
  inputIndex: number,
  prevScriptPubKey: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array {
  const sigHash = computeSigHash(tx, inputIndex, prevScriptPubKey, SIGHASH_ALL);

  // Sign with secp256k1 v2 (returns Signature with r, s bigints)
  const signature = secp256k1.sign(sigHash, privateKey);

  // Normalize to low-S per BIP-62
  const normalizedSig = signature.hasHighS() ? signature.normalizeS() : signature;

  // DER-encode the signature
  const derSig = derEncodeSignature(normalizedSig.r, normalizedSig.s);

  // Append SIGHASH_ALL byte to the DER signature
  const sigWithHashType = new Uint8Array(derSig.length + 1);
  sigWithHashType.set(derSig, 0);
  sigWithHashType[derSig.length] = SIGHASH_ALL;

  // Get compressed public key
  const publicKey = secp256k1.getPublicKey(privateKey, true);

  return createP2PKHScriptSig(sigWithHashType, publicKey);
}

// ---------------------------------------------------------------------------
// Transaction building
// ---------------------------------------------------------------------------

/**
 * Estimate the byte size of a P2PKH transaction.
 */
export function estimateTxSize(
  numInputs: number,
  numOutputs: number,
): number {
  return TX_OVERHEAD + numInputs * P2PKH_INPUT_SIZE + numOutputs * P2PKH_OUTPUT_SIZE;
}

export interface BuildTransactionParams {
  utxos: UTXO[];
  recipients: Array<{ address: string; value: bigint }>;
  changeAddress: string;
  feePerByte: bigint;
  network: NetworkConfig;
}

/**
 * Build an unsigned transaction with coin selection and change output.
 *
 * Uses a simple "use all provided UTXOs" strategy. The caller is expected
 * to pre-select UTXOs. Returns the unsigned transaction; inputs will have
 * empty scriptSig fields that must be signed before broadcast.
 */
export function buildTransaction(
  params: BuildTransactionParams,
): Transaction {
  const { utxos, recipients, changeAddress, feePerByte, network } = params;

  if (utxos.length === 0) {
    throw new Error("No UTXOs provided");
  }
  if (recipients.length === 0) {
    throw new Error("No recipients provided");
  }

  // Calculate total input value
  let totalIn = 0n;
  for (const utxo of utxos) {
    totalIn += utxo.value;
  }

  // Calculate total output value
  let totalOut = 0n;
  for (const recipient of recipients) {
    if (recipient.value <= 0n) {
      throw new Error("Recipient value must be positive");
    }
    totalOut += recipient.value;
  }

  // Estimate fee with a potential change output
  const estimatedSizeWithChange = estimateTxSize(
    utxos.length,
    recipients.length + 1,
  );
  const feeWithChange = feePerByte * BigInt(estimatedSizeWithChange);

  const estimatedSizeWithoutChange = estimateTxSize(
    utxos.length,
    recipients.length,
  );
  const feeWithoutChange = feePerByte * BigInt(estimatedSizeWithoutChange);

  if (totalIn < totalOut + feeWithoutChange) {
    throw new Error(
      `Insufficient funds: have ${totalIn} ${SMALLEST_UNIT_NAME}, need ${totalOut + feeWithoutChange} (${totalOut} + ${feeWithoutChange} fee)`,
    );
  }

  // Build outputs for recipients
  const outputs: TxOutput[] = recipients.map((recipient) => ({
    value: recipient.value,
    scriptPubKey: scriptForAddress(recipient.address, network),
  }));

  // Determine if we need a change output
  const changeAmount = totalIn - totalOut - feeWithChange;
  const dustThreshold = network.minRelayFee;

  if (changeAmount > dustThreshold) {
    outputs.push({
      value: changeAmount,
      scriptPubKey: scriptForAddress(changeAddress, network),
    });
  }

  // Build inputs (empty scriptSig, to be signed later)
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
