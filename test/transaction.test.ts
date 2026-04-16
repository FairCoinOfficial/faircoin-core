/**
 * Tests for transaction serialisation, parsing, signing, and building.
 *
 * Uses the BIP39 trial mnemonic and a synthetic UTXO as a deterministic
 * source of test data. Signatures are verified for round-trip-ability
 * and txid stability.
 */

import { describe, test, expect } from "bun:test";

import { hexToBytes, bytesToHex, decodeAddress } from "../src/encoding.js";
import { deriveAddress, mnemonicToSeed } from "../src/hd-wallet.js";
import { MAINNET } from "../src/network.js";
import { createP2PKHScript } from "../src/script.js";
import {
  buildTransaction,
  deserializeTransaction,
  estimateTxSize,
  hashTransaction,
  serializeTransaction,
  signInput,
  type Transaction,
  type TxInput,
  type TxOutput,
  type UTXO,
} from "../src/transaction.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TRIAL_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function getFixtures(): {
  utxo: UTXO;
  senderPrivKey: Uint8Array;
  senderAddr: string;
  recipientAddr: string;
} {
  const seed = mnemonicToSeed(TRIAL_MNEMONIC);
  const sender = deriveAddress(seed, 0, 0, 0, MAINNET);
  const recipient = deriveAddress(seed, 0, 0, 1, MAINNET);

  const scriptPubKey = createP2PKHScript(decodeAddress(sender.address).hash);
  const utxo: UTXO = {
    txid: "0000000000000000000000000000000000000000000000000000000000000001",
    vout: 0,
    value: 1_000_000_000n,
    scriptPubKey,
  };

  return {
    utxo,
    senderPrivKey: sender.privateKey,
    senderAddr: sender.address,
    recipientAddr: recipient.address,
  };
}

// ---------------------------------------------------------------------------
// serializeTransaction / deserializeTransaction
// ---------------------------------------------------------------------------

describe("serializeTransaction / deserializeTransaction", () => {
  test("round trip minimum tx", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [],
      outputs: [],
      lockTime: 0,
    };
    const raw = serializeTransaction(tx);
    const parsed = deserializeTransaction(raw);
    expect(parsed.version).toBe(1);
    expect(parsed.inputs.length).toBe(0);
    expect(parsed.outputs.length).toBe(0);
    expect(parsed.lockTime).toBe(0);
  });

  test("parses a known Bitcoin-format tx (1 in, 1 out, empty scriptSig)", () => {
    const hex =
      "0100000001" + // version
      "0000000000000000000000000000000000000000000000000000000000000000" + // prev txid
      "ffffffff" + // vout
      "00" + // scriptSig len (empty)
      "ffffffff" + // sequence
      "01" + // 1 output
      "00e1f50500000000" + // value 100_000_000 LE
      "1976a914751e76e8199196d454941c45d1b3a323f1433bd688ac" + // scriptPubKey
      "00000000"; // locktime

    const parsed = deserializeTransaction(hexToBytes(hex));
    expect(parsed.version).toBe(1);
    expect(parsed.inputs.length).toBe(1);
    expect(parsed.outputs.length).toBe(1);
    expect(parsed.inputs[0].vout).toBe(0xffffffff);
    expect(parsed.inputs[0].scriptSig.length).toBe(0);
    expect(parsed.inputs[0].sequence).toBe(0xffffffff);
    expect(parsed.outputs[0].value).toBe(100_000_000n);
    expect(bytesToHex(parsed.outputs[0].scriptPubKey)).toBe(
      "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    );
    expect(parsed.lockTime).toBe(0);
  });

  test("serialise → deserialise is an identity for a populated tx", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          txid: "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f",
          vout: 7,
          scriptSig: hexToBytes("4830450201"),
          sequence: 0xfffffffe,
        } satisfies TxInput,
      ],
      outputs: [
        {
          value: 54_321n,
          scriptPubKey: hexToBytes(
            "76a9140102030405060708090a0b0c0d0e0f101112131488ac",
          ),
        } satisfies TxOutput,
      ],
      lockTime: 42,
    };
    const raw = serializeTransaction(tx);
    const parsed = deserializeTransaction(raw);
    expect(parsed.version).toBe(tx.version);
    expect(parsed.inputs.length).toBe(1);
    expect(parsed.inputs[0].txid).toBe(tx.inputs[0].txid);
    expect(parsed.inputs[0].vout).toBe(tx.inputs[0].vout);
    expect(bytesToHex(parsed.inputs[0].scriptSig)).toBe(
      bytesToHex(tx.inputs[0].scriptSig),
    );
    expect(parsed.inputs[0].sequence).toBe(tx.inputs[0].sequence);
    expect(parsed.outputs.length).toBe(1);
    expect(parsed.outputs[0].value).toBe(tx.outputs[0].value);
    expect(bytesToHex(parsed.outputs[0].scriptPubKey)).toBe(
      bytesToHex(tx.outputs[0].scriptPubKey),
    );
    expect(parsed.lockTime).toBe(tx.lockTime);
  });
});

// ---------------------------------------------------------------------------
// hashTransaction
// ---------------------------------------------------------------------------

describe("hashTransaction", () => {
  test("is deterministic for the same tx", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [],
      outputs: [],
      lockTime: 0,
    };
    expect(hashTransaction(tx)).toBe(hashTransaction(tx));
  });

  test("changes when inputs change", () => {
    const base: Transaction = {
      version: 1,
      inputs: [
        {
          txid: "00".repeat(32),
          vout: 0,
          scriptSig: new Uint8Array(0),
          sequence: 0xffffffff,
        },
      ],
      outputs: [],
      lockTime: 0,
    };
    const mutated: Transaction = {
      ...base,
      inputs: [{ ...base.inputs[0], vout: 1 }],
    };
    expect(hashTransaction(base)).not.toBe(hashTransaction(mutated));
  });

  test("returns 64 hex characters", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [],
      outputs: [],
      lockTime: 0,
    };
    expect(hashTransaction(tx).length).toBe(64);
    expect(/^[0-9a-f]{64}$/.test(hashTransaction(tx))).toBe(true);
  });

  test("is stable across serialise/deserialise round trips", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          txid: "11".repeat(32),
          vout: 2,
          scriptSig: hexToBytes("aabbcc"),
          sequence: 0xffffffff,
        },
      ],
      outputs: [
        {
          value: 5000n,
          scriptPubKey: hexToBytes("76a9140102030405060708090a0b0c0d0e0f101112131488ac"),
        },
      ],
      lockTime: 0,
    };
    const raw = serializeTransaction(tx);
    const parsed = deserializeTransaction(raw);
    expect(hashTransaction(parsed)).toBe(hashTransaction(tx));
  });
});

// ---------------------------------------------------------------------------
// buildTransaction
// ---------------------------------------------------------------------------

describe("buildTransaction", () => {
  test("creates a tx with a change output when funds exceed target + fee", () => {
    const f = getFixtures();
    const tx = buildTransaction({
      utxos: [f.utxo],
      recipients: [{ address: f.recipientAddr, value: 100_000_000n }],
      changeAddress: f.senderAddr,
      feePerByte: 1n,
      network: MAINNET,
    });
    expect(tx.inputs.length).toBe(1);
    expect(tx.outputs.length).toBe(2); // recipient + change
    expect(tx.version).toBe(1);
    expect(tx.lockTime).toBe(0);
    expect(tx.inputs[0].scriptSig.length).toBe(0); // unsigned
  });

  test("omits change output when change is below dust threshold", () => {
    const f = getFixtures();
    // Pick a target that leaves only a tiny change
    const totalIn = f.utxo.value;
    // Estimate size-1 output tx
    const expectedSize = estimateTxSize(1, 1);
    const fee = BigInt(expectedSize);
    const tx = buildTransaction({
      utxos: [f.utxo],
      recipients: [{ address: f.recipientAddr, value: totalIn - fee }],
      changeAddress: f.senderAddr,
      feePerByte: 1n,
      network: MAINNET,
    });
    expect(tx.outputs.length).toBe(1); // no change
  });

  test("throws when no UTXOs provided", () => {
    const f = getFixtures();
    expect(() =>
      buildTransaction({
        utxos: [],
        recipients: [{ address: f.recipientAddr, value: 1n }],
        changeAddress: f.senderAddr,
        feePerByte: 1n,
        network: MAINNET,
      }),
    ).toThrow();
  });

  test("throws when no recipients provided", () => {
    const f = getFixtures();
    expect(() =>
      buildTransaction({
        utxos: [f.utxo],
        recipients: [],
        changeAddress: f.senderAddr,
        feePerByte: 1n,
        network: MAINNET,
      }),
    ).toThrow();
  });

  test("throws when recipient value is non-positive", () => {
    const f = getFixtures();
    expect(() =>
      buildTransaction({
        utxos: [f.utxo],
        recipients: [{ address: f.recipientAddr, value: 0n }],
        changeAddress: f.senderAddr,
        feePerByte: 1n,
        network: MAINNET,
      }),
    ).toThrow();
  });

  test("throws when funds are insufficient", () => {
    const f = getFixtures();
    expect(() =>
      buildTransaction({
        utxos: [f.utxo],
        recipients: [{ address: f.recipientAddr, value: f.utxo.value + 1n }],
        changeAddress: f.senderAddr,
        feePerByte: 1n,
        network: MAINNET,
      }),
    ).toThrow(/insufficient/i);
  });
});

// ---------------------------------------------------------------------------
// signInput
// ---------------------------------------------------------------------------

describe("signInput", () => {
  test("produces a scriptSig that parses as DER sig + pubkey push", () => {
    const f = getFixtures();
    const tx = buildTransaction({
      utxos: [f.utxo],
      recipients: [{ address: f.recipientAddr, value: 100_000_000n }],
      changeAddress: f.senderAddr,
      feePerByte: 1n,
      network: MAINNET,
    });

    const scriptSig = signInput(tx, 0, f.utxo.scriptPubKey, f.senderPrivKey);
    expect(scriptSig.length).toBeGreaterThan(0);

    // scriptSig format: <sigLen> <DER sig + sighash byte> <pubkeyLen> <pubkey>
    // First byte is the push length for the signature
    const sigLen = scriptSig[0];
    expect(sigLen).toBeGreaterThanOrEqual(1);
    expect(sigLen).toBeLessThanOrEqual(74); // max DER sig size
    // DER sig starts with 0x30
    expect(scriptSig[1]).toBe(0x30);
    // SIGHASH byte at the end of the sig
    expect(scriptSig[1 + sigLen - 1]).toBe(0x01);
    // Pubkey push follows: 0x21 (33) for compressed
    const pubkeyPushIndex = 1 + sigLen;
    expect(scriptSig[pubkeyPushIndex]).toBe(0x21);
    // Pubkey starts with 0x02 or 0x03 (compressed)
    const firstPubkeyByte = scriptSig[pubkeyPushIndex + 1];
    expect(firstPubkeyByte === 0x02 || firstPubkeyByte === 0x03).toBe(true);
  });

  test("signed tx serialises and round-trips deterministically", () => {
    const f = getFixtures();
    const tx = buildTransaction({
      utxos: [f.utxo],
      recipients: [{ address: f.recipientAddr, value: 100_000_000n }],
      changeAddress: f.senderAddr,
      feePerByte: 1n,
      network: MAINNET,
    });

    tx.inputs[0] = {
      ...tx.inputs[0],
      scriptSig: signInput(tx, 0, f.utxo.scriptPubKey, f.senderPrivKey),
    };

    const raw = serializeTransaction(tx);
    const parsed = deserializeTransaction(raw);
    expect(parsed.inputs.length).toBe(1);
    expect(bytesToHex(parsed.inputs[0].scriptSig)).toBe(
      bytesToHex(tx.inputs[0].scriptSig),
    );
    expect(hashTransaction(parsed)).toBe(hashTransaction(tx));
  });

  test("signatures are deterministic (RFC6979)", () => {
    const f = getFixtures();
    const tx = buildTransaction({
      utxos: [f.utxo],
      recipients: [{ address: f.recipientAddr, value: 100_000_000n }],
      changeAddress: f.senderAddr,
      feePerByte: 1n,
      network: MAINNET,
    });

    const a = signInput(tx, 0, f.utxo.scriptPubKey, f.senderPrivKey);
    const b = signInput(tx, 0, f.utxo.scriptPubKey, f.senderPrivKey);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("rejects an out-of-range input index", () => {
    const f = getFixtures();
    const tx: Transaction = {
      version: 1,
      inputs: [
        {
          txid: "00".repeat(32),
          vout: 0,
          scriptSig: new Uint8Array(0),
          sequence: 0xffffffff,
        },
      ],
      outputs: [],
      lockTime: 0,
    };
    expect(() => signInput(tx, 1, f.utxo.scriptPubKey, f.senderPrivKey)).toThrow();
    expect(() => signInput(tx, -1, f.utxo.scriptPubKey, f.senderPrivKey)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// estimateTxSize
// ---------------------------------------------------------------------------

describe("estimateTxSize", () => {
  test("1 in / 1 out is around 192 bytes", () => {
    // 10 + 1*148 + 1*34 = 192
    expect(estimateTxSize(1, 1)).toBe(192);
  });

  test("1 in / 2 out is around 226 bytes", () => {
    // 10 + 1*148 + 2*34 = 226
    expect(estimateTxSize(1, 2)).toBe(226);
  });

  test("scales linearly with input/output counts", () => {
    const a = estimateTxSize(1, 1);
    const b = estimateTxSize(3, 3);
    // 2 extra inputs + 2 extra outputs = 2*148 + 2*34 = 364 bytes
    expect(b - a).toBe(2 * 148 + 2 * 34);
  });
});
