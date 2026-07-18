import { describe, test, expect } from "bun:test";

import { hexToBytes, bytesToHex, encodeAddress } from "../src/encoding.js";
import { hash160 } from "../src/address.js";
import { createP2SHScript } from "../src/script.js";
import { MAINNET } from "../src/network.js";
import { createMultisigRedeemScript, multisigAddress } from "../src/multisig-script.js";
import {
  estimateMultisigInputSize,
  estimateMultisigTxSize,
  buildMultisigSpend,
  type BuildMultisigSpendParams,
} from "../src/multisig-transaction.js";

const PUB1 = hexToBytes("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
const PUB2 = hexToBytes("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
const PUB3 = hexToBytes("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337");
const REDEEM_SCRIPT = createMultisigRedeemScript(2, [PUB1, PUB2, PUB3]);
const MULTISIG_ADDRESS = multisigAddress(REDEEM_SCRIPT, MAINNET);
const PUB2_ADDRESS = encodeAddress(hash160(PUB2), MAINNET.pubKeyHash);

describe("estimateMultisigInputSize / estimateMultisigTxSize", () => {
  test("matches the real assembled scriptSig size for a 2-of-3 spend (conservative upper bound)", () => {
    // multisig-sign.test.ts's real 2-of-3 scriptSig is 253 bytes (36 outpoint
    // + 3 varint + 253 scriptSig + 4 sequence = 296-byte input); the estimate
    // sizes against the 72-byte DER max (not the actual 71/72-byte real
    // signatures), so it must be >= the real input size.
    expect(estimateMultisigInputSize(2, REDEEM_SCRIPT.length)).toBe(299);
    expect(estimateMultisigInputSize(2, REDEEM_SCRIPT.length)).toBeGreaterThanOrEqual(
      36 + 3 + 253 + 4,
    );
  });

  test("full tx size estimate for 1 input, 2 outputs", () => {
    expect(estimateMultisigTxSize(1, 2, 2, REDEEM_SCRIPT.length)).toBe(377);
  });

  test("rejects a non-positive threshold", () => {
    expect(() => estimateMultisigInputSize(0, REDEEM_SCRIPT.length)).toThrow();
  });
});

describe("buildMultisigSpend", () => {
  const baseParams: BuildMultisigSpendParams = {
    utxos: [
      {
        txid: "bb".repeat(32),
        vout: 0,
        value: 10_000_000n,
        scriptPubKey: createP2SHScript(hash160(REDEEM_SCRIPT)),
      },
    ],
    redeemScript: REDEEM_SCRIPT,
    m: 2,
    recipients: [{ address: PUB2_ADDRESS, value: 4_000_000n }],
    changeAddress: MULTISIG_ADDRESS,
    feePerByte: 10n,
    network: MAINNET,
  };

  test("produces the exact real unsigned transaction bytes", () => {
    const tx = buildMultisigSpend(baseParams);
    expect(tx.outputs[0].value).toBe(4_000_000n);
    expect(bytesToHex(tx.outputs[0].scriptPubKey)).toBe(
      "76a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac",
    );
    expect(tx.outputs[1].value).toBe(5_996_230n);
    expect(bytesToHex(tx.outputs[1].scriptPubKey)).toBe(
      "a914ae79902ae33900b679c76ced8576362e4abb15e887",
    );
    expect(tx.inputs[0].scriptSig.length).toBe(0);
  });

  test("throws when funds are insufficient", () => {
    expect(() =>
      buildMultisigSpend({
        ...baseParams,
        recipients: [{ address: PUB2_ADDRESS, value: 50_000_000n }],
      }),
    ).toThrow(/Insufficient funds/);
  });

  test("rejects an empty UTXO list", () => {
    expect(() => buildMultisigSpend({ ...baseParams, utxos: [] })).toThrow("No UTXOs provided");
  });
});
