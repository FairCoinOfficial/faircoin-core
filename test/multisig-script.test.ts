import { describe, test, expect } from "bun:test";

import { hexToBytes, bytesToHex } from "../src/encoding.js";
import { MAINNET, TESTNET } from "../src/network.js";
import { createMultisigRedeemScript, multisigAddress } from "../src/multisig-script.js";

// Fixed, reproducible secp256k1 compressed public keys, derived from private
// keys 0x01/0x02/0x03 repeated to 32 bytes via @noble/secp256k1 (this
// package's own pinned signing library). Reused across multisig-sign.test.ts
// and multisig-transaction.test.ts so every test in this plan is internally
// consistent.
const PUB1 = hexToBytes("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
const PUB2 = hexToBytes("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
const PUB3 = hexToBytes("02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337");

describe("createMultisigRedeemScript", () => {
  test("2-of-3 produces the exact real redeem script bytes", () => {
    const script = createMultisigRedeemScript(2, [PUB1, PUB2, PUB3]);
    expect(bytesToHex(script)).toBe(
      "5221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33753ae",
    );
    expect(script.length).toBe(105);
  });

  test("1-of-1 (smallest multisig)", () => {
    const script = createMultisigRedeemScript(1, [PUB1]);
    expect(bytesToHex(script)).toBe(
      "5121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f51ae",
    );
  });

  test("rejects m > n", () => {
    expect(() => createMultisigRedeemScript(3, [PUB1, PUB2])).toThrow(/cannot exceed n/);
  });

  test("rejects m < 1", () => {
    expect(() => createMultisigRedeemScript(0, [PUB1])).toThrow(/positive integer/);
  });

  test("rejects more than 16 pubkeys (OP_1..OP_16 opcode ceiling)", () => {
    const seventeen = Array.from({ length: 17 }, () => PUB1);
    expect(() => createMultisigRedeemScript(1, seventeen)).toThrow(/between 1 and 16/);
  });

  test("rejects a redeem script over the 520-byte standard relay limit", () => {
    const sixteen = Array.from({ length: 16 }, () => PUB1);
    expect(() => createMultisigRedeemScript(16, sixteen)).toThrow(/520-byte/);
  });

  test("rejects an invalid public key length", () => {
    expect(() => createMultisigRedeemScript(1, [new Uint8Array(20)])).toThrow(
      /Invalid public key length/,
    );
  });
});

describe("multisigAddress", () => {
  test("produces the real mainnet 2-of-3 P2SH address", () => {
    const script = createMultisigRedeemScript(2, [PUB1, PUB2, PUB3]);
    expect(multisigAddress(script, MAINNET)).toBe("7iKBxUNbBbTa8n1Q32oLucmvmKL7c572P2");
  });

  test("produces the real testnet 2-of-3 P2SH address", () => {
    const script = createMultisigRedeemScript(2, [PUB1, PUB2, PUB3]);
    expect(multisigAddress(script, TESTNET)).toBe("66xn23BSLsc4s3T3wMU4y7gnFJJLmXkhhT");
  });
});
