import { describe, test, expect } from "bun:test";

import { hexToBytes, bytesToHex } from "../src/encoding.js";
import { hash160 } from "../src/address.js";
import { createP2PKHScript } from "../src/script.js";
import { serializeTransaction, type Transaction } from "../src/transaction.js";
import { createMultisigRedeemScript } from "../src/multisig-script.js";
import {
  computeMultisigSigHash,
  signMultisigInput,
  verifyPartialSignature,
  assembleMultisigScriptSig,
  serializeMultisigSigningRequest,
  deserializeMultisigSigningRequest,
  type PartialSignature,
  type MultisigSigningRequest,
} from "../src/multisig-sign.js";

// Same fixed keys as multisig-script.test.ts.
const PUB1 = hexToBytes("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
const PUB2 = hexToBytes("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
const PUB3 = hexToBytes("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337");
const PRIV1 = hexToBytes("01".repeat(32));
const PRIV3 = hexToBytes("03".repeat(32));

export const REDEEM_SCRIPT = createMultisigRedeemScript(2, [PUB1, PUB2, PUB3]);

/** A synthetic 1-input, 1-output unsigned tx spending a fake P2SH UTXO. */
export function fixtureTx(): Transaction {
  return {
    version: 1,
    inputs: [
      {
        txid: "aa".repeat(32),
        vout: 0,
        scriptSig: new Uint8Array(0),
        sequence: 0xffffffff,
      },
    ],
    outputs: [
      {
        value: 4_900_000n,
        scriptPubKey: createP2PKHScript(hash160(PUB1)),
      },
    ],
    lockTime: 0,
  };
}

describe("computeMultisigSigHash", () => {
  test("matches the real, independently-reproducible sighash", () => {
    const sigHash = computeMultisigSigHash(fixtureTx(), 0, REDEEM_SCRIPT);
    expect(bytesToHex(sigHash)).toBe(
      "2c9a73c1356725b2cf6e3a49110767eeb75eb35016f3fe8c07d3f932231597b7",
    );
  });

  test("throws for an out-of-range input index", () => {
    expect(() => computeMultisigSigHash(fixtureTx(), 5, REDEEM_SCRIPT)).toThrow();
  });
});

describe("signMultisigInput", () => {
  test("signer 1 produces the real, deterministic (RFC6979) DER signature", () => {
    const sig = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    expect(bytesToHex(sig)).toBe(
      "3045022100a75e0470f26695564c7d7532dad3aeac6845280a5a10f135b32525752c7bbbc4022045a7fd3af5b2776c6e23f13b30cdec93504942e00ee23e2dd2a2eff8497d629d01",
    );
    expect(sig[sig.length - 1]).toBe(0x01);
  });

  test("signer 3 produces a different, also-deterministic signature", () => {
    const sig = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV3);
    expect(bytesToHex(sig)).toBe(
      "3044022050837cdb7dafab46d59dc1385ae2716aedf2d0ff29ebfeebcfec4552da173ed002200fc8187898f3cc9fbde73fd781f93824820f21d4b30cc8859581788824175e7501",
    );
  });

  test("signing is deterministic: the same key + tx always produces the same signature", () => {
    const a = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    const b = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("never returns anything resembling the private key (key-leak guard)", () => {
    const sig = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    expect(bytesToHex(sig)).not.toContain(bytesToHex(PRIV1));
  });
});

describe("assembleMultisigScriptSig", () => {
  test("produces the exact real finalized scriptSig (signers 1 and 3, in order)", () => {
    const sig1: PartialSignature = {
      pubkey: PUB1,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    const sig3: PartialSignature = {
      pubkey: PUB3,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV3),
    };
    const scriptSig = assembleMultisigScriptSig([sig1, sig3], REDEEM_SCRIPT);
    expect(bytesToHex(scriptSig)).toBe(
      "00483045022100a75e0470f26695564c7d7532dad3aeac6845280a5a10f135b32525752c7bbbc4022045a7fd3af5b2776c6e23f13b30cdec93504942e00ee23e2dd2a2eff8497d629d01473044022050837cdb7dafab46d59dc1385ae2716aedf2d0ff29ebfeebcfec4552da173ed002200fc8187898f3cc9fbde73fd781f93824820f21d4b30cc8859581788824175e75014c695221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33753ae",
    );
    expect(scriptSig.length).toBe(253);
    expect(scriptSig[0]).toBe(0x00); // mandatory OP_0 CHECKMULTISIG dummy element
  });

  test("reorders signatures given in the WRONG order to match the redeem script's pubkey order", () => {
    const sig1: PartialSignature = {
      pubkey: PUB1,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    const sig3: PartialSignature = {
      pubkey: PUB3,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV3),
    };
    // Signer 3's signature passed FIRST -- the result must still put signer
    // 1 first, since PUB1 appears before PUB3 in the redeem script.
    const reversedOrder = assembleMultisigScriptSig([sig3, sig1], REDEEM_SCRIPT);
    const naturalOrder = assembleMultisigScriptSig([sig1, sig3], REDEEM_SCRIPT);
    expect(bytesToHex(reversedOrder)).toBe(bytesToHex(naturalOrder));
  });

  test("rejects a signature whose pubkey is not part of the redeem script", () => {
    const foreignSig: PartialSignature = {
      pubkey: hexToBytes("02".repeat(33)),
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    expect(() => assembleMultisigScriptSig([foreignSig], REDEEM_SCRIPT)).toThrow(
      /not part of this redeem script/,
    );
  });

  test("rejects an under-signed set: 1 signature for a 2-of-3", () => {
    // OP_CHECKMULTISIG needs exactly m=2 signatures; a single one assembles
    // into a scriptSig that looks spendable but is rejected at broadcast.
    const sig1: PartialSignature = {
      pubkey: PUB1,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    expect(() => assembleMultisigScriptSig([sig1], REDEEM_SCRIPT)).toThrow(/Expected exactly 2/);
  });

  test("rejects two signatures from the SAME cosigner for a 2-of-3", () => {
    // Two distinct-looking entries that both resolve to PUB1 -- CHECKMULTISIG
    // requires m=2 DISTINCT in-script signers, so this must not assemble.
    const sig1a: PartialSignature = {
      pubkey: PUB1,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    const sig1b: PartialSignature = {
      pubkey: PUB1,
      signature: signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1),
    };
    expect(() => assembleMultisigScriptSig([sig1a, sig1b], REDEEM_SCRIPT)).toThrow(/Duplicate/);
  });
});

describe("serializeMultisigSigningRequest / deserializeMultisigSigningRequest", () => {
  test("round-trips through the real unsigned tx and matches the known wire hex", () => {
    const request: MultisigSigningRequest = {
      tx: fixtureTx(),
      inputIndex: 0,
      redeemScript: REDEEM_SCRIPT,
    };
    const serialized = serializeMultisigSigningRequest(request);
    expect(serialized.txHex).toBe(
      "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff01a0c44a00000000001976a91479b000887626b294a914501a4cd226b58b23598388ac00000000",
    );
    expect(serialized.inputIndex).toBe(0);
    expect(serialized.redeemScriptHex).toBe(bytesToHex(REDEEM_SCRIPT));

    const deserialized = deserializeMultisigSigningRequest(serialized);
    expect(bytesToHex(serializeTransaction(deserialized.tx))).toBe(
      bytesToHex(serializeTransaction(request.tx)),
    );
    expect(deserialized.inputIndex).toBe(0);
    expect(bytesToHex(deserialized.redeemScript)).toBe(bytesToHex(REDEEM_SCRIPT));
  });

  test("signing from a DESERIALIZED request matches signing the original directly", () => {
    const request: MultisigSigningRequest = {
      tx: fixtureTx(),
      inputIndex: 0,
      redeemScript: REDEEM_SCRIPT,
    };
    const roundTripped = deserializeMultisigSigningRequest(serializeMultisigSigningRequest(request));
    const sigFromOriginal = signMultisigInput(request.tx, request.inputIndex, request.redeemScript, PRIV1);
    const sigFromRoundTrip = signMultisigInput(
      roundTripped.tx,
      roundTripped.inputIndex,
      roundTripped.redeemScript,
      PRIV1,
    );
    expect(bytesToHex(sigFromRoundTrip)).toBe(bytesToHex(sigFromOriginal));
  });
});

describe("verifyPartialSignature", () => {
  test("a real signMultisigInput signature verifies TRUE against its matching pubkey", () => {
    // The sighash signMultisigInput signs internally is the multisig sighash
    // over this input -- verify against that exact digest.
    const sighash = computeMultisigSigHash(fixtureTx(), 0, REDEEM_SCRIPT);
    const sig1 = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    expect(verifyPartialSignature(sig1, PUB1, sighash)).toBe(true);
  });

  test("that same signature verifies FALSE against a different cosigner's pubkey", () => {
    // PUB1's genuine signature is not PUB2's signature, even though PUB2 is a
    // real cosigner in this redeem script -- this is exactly the bad/mislabeled
    // contribution a coordinator must reject at partial-sig collection.
    const sighash = computeMultisigSigHash(fixtureTx(), 0, REDEEM_SCRIPT);
    const sig1 = signMultisigInput(fixtureTx(), 0, REDEEM_SCRIPT, PRIV1);
    expect(verifyPartialSignature(sig1, PUB2, sighash)).toBe(false);
  });

  test("random/garbage bytes verify FALSE without throwing", () => {
    const sighash = computeMultisigSigHash(fixtureTx(), 0, REDEEM_SCRIPT);
    // Non-DER noise (no 0x30 header), a truncated buffer, an empty buffer, and
    // a structurally-valid DER whose r=s=1 is not a real signature -- every one
    // must return false, and none may throw.
    const nonDer = hexToBytes("de".repeat(72));
    const truncated = hexToBytes("3006020101");
    const empty = new Uint8Array(0);
    const wellFormedButInvalid = hexToBytes("3006020101020101");
    expect(verifyPartialSignature(nonDer, PUB1, sighash)).toBe(false);
    expect(verifyPartialSignature(truncated, PUB1, sighash)).toBe(false);
    expect(verifyPartialSignature(empty, PUB1, sighash)).toBe(false);
    expect(verifyPartialSignature(wellFormedButInvalid, PUB1, sighash)).toBe(false);
  });
});
