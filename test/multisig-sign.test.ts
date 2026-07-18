import { describe, test, expect } from "bun:test";

import { hexToBytes, bytesToHex } from "../src/encoding.js";
import { hash160 } from "../src/address.js";
import { createP2PKHScript } from "../src/script.js";
import type { Transaction } from "../src/transaction.js";
import { createMultisigRedeemScript } from "../src/multisig-script.js";
import { computeMultisigSigHash, signMultisigInput } from "../src/multisig-sign.js";

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
    expect(sig[sig.length - 1]).toBe(0x01); // trailing SIGHASH_ALL byte
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
