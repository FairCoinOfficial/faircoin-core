/**
 * Tests for BIP32/BIP39/BIP44 HD wallet helpers.
 *
 * Uses the canonical BIP39 trial mnemonic ("abandon ... about") as a
 * source of deterministic test vectors. The seed derived from that
 * mnemonic is a well-known reference value in the BIP39 spec.
 *
 * The FairCoin-specific addresses derived from that seed are pinned
 * as regression guards — if anyone changes FairCoin's BIP44 coin type
 * (119), BIP32 version bytes, or pubKeyHash version byte, these tests
 * will fail.
 */

import { describe, test, expect } from "bun:test";

import {
  deriveAddress,
  deriveKeyFromSeed,
  generateMnemonic,
  getDerivationPath,
  mnemonicToSeed,
  validateMnemonic,
} from "../src/hd-wallet.js";
import { bytesToHex } from "../src/encoding.js";
import { MAINNET, TESTNET } from "../src/network.js";

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

const TRIAL_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Canonical BIP39 reference seed (no passphrase) from the BIP39 spec
// appendix. If this ever changes, the BIP39 implementation is broken.
const TRIAL_SEED_HEX =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

// Pinned FairCoin mainnet / testnet outputs for the trial mnemonic at
// BIP44 path m/44'/coinType'/0'/0/0. These act as regression guards.
const MAINNET_0_0_0_ADDRESS = "FQVANvQqVsLwkwBnAJ5oPDYrqcfXLak7Bf";
const MAINNET_0_0_0_PUBKEY =
  "0399d319ee6de45a113e1084b79ade7609616f608049916b7dff2a8cef8497903a";
const MAINNET_0_0_0_PRIVKEY =
  "571f3331e168b2499e884a6d11978fe9f425138692731c1855ffaf0111e893d7";
const MAINNET_0_0_1_ADDRESS = "F8Xe2DS7EwmU7CdyNokYmMYq6DqKnEEyRf";
const TESTNET_0_0_0_ADDRESS = "TFGpQZB4EjXpVNT4gvPqzTFCwSAyjGe1MX";

// ---------------------------------------------------------------------------
// generateMnemonic / validateMnemonic
// ---------------------------------------------------------------------------

describe("generateMnemonic / validateMnemonic", () => {
  test("generated mnemonic validates and has 24 words", () => {
    const m = generateMnemonic();
    const words = m.split(/\s+/);
    expect(words.length).toBe(24);
    expect(validateMnemonic(m)).toBe(true);
  });

  test("generates different mnemonics across calls", () => {
    const a = generateMnemonic();
    const b = generateMnemonic();
    expect(a).not.toBe(b);
  });

  test("rejects the empty string", () => {
    expect(validateMnemonic("")).toBe(false);
  });

  test("rejects a single word", () => {
    expect(validateMnemonic("abandon")).toBe(false);
  });

  test("rejects an invalid checksum", () => {
    // Valid words but incorrect BIP39 checksum (last word changed).
    const bad =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    expect(validateMnemonic(bad)).toBe(false);
  });

  test("accepts the canonical trial mnemonic", () => {
    expect(validateMnemonic(TRIAL_MNEMONIC)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// mnemonicToSeed (BIP39)
// ---------------------------------------------------------------------------

describe("mnemonicToSeed", () => {
  test("trial mnemonic produces the canonical BIP39 seed", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    expect(bytesToHex(seed)).toBe(TRIAL_SEED_HEX);
  });

  test("seed length is 64 bytes", () => {
    expect(mnemonicToSeed(TRIAL_MNEMONIC).length).toBe(64);
  });

  test("passphrase changes the seed", () => {
    const a = mnemonicToSeed(TRIAL_MNEMONIC, "");
    const b = mnemonicToSeed(TRIAL_MNEMONIC, "passphrase");
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

// ---------------------------------------------------------------------------
// deriveKeyFromSeed (BIP32 master)
// ---------------------------------------------------------------------------

describe("deriveKeyFromSeed", () => {
  test("master node is at depth 0 with index 0", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const root = deriveKeyFromSeed(seed, MAINNET);
    expect(root.depth).toBe(0);
    expect(root.index).toBe(0);
  });

  test("master node has private and public keys", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const root = deriveKeyFromSeed(seed, MAINNET);
    expect(root.privateKey).not.toBeNull();
    expect(root.publicKey).not.toBeNull();
    expect(root.privateKey?.length).toBe(32);
    expect(root.publicKey?.length).toBe(33);
  });

  test("mainnet and testnet use different BIP32 version bytes", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const mainRoot = deriveKeyFromSeed(seed, MAINNET);
    const testRoot = deriveKeyFromSeed(seed, TESTNET);
    // Extended-key serialisation embeds the version bytes, so the xpriv
    // strings must differ even though the underlying private key material
    // is the same.
    expect(mainRoot.hdKey.privateExtendedKey).not.toBe(
      testRoot.hdKey.privateExtendedKey,
    );
  });

  test("derive(path) returns a deeper node", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const root = deriveKeyFromSeed(seed, MAINNET);
    const child = root.derive("m/44'/119'/0'/0/0");
    expect(child.depth).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// getDerivationPath
// ---------------------------------------------------------------------------

describe("getDerivationPath", () => {
  test("FairCoin mainnet path uses coin type 119", () => {
    expect(getDerivationPath(0, 0, 0, MAINNET)).toBe("m/44'/119'/0'/0/0");
  });

  test("testnet path uses coin type 1", () => {
    expect(getDerivationPath(0, 0, 0, TESTNET)).toBe("m/44'/1'/0'/0/0");
  });

  test("account, change, and index are rendered in order", () => {
    expect(getDerivationPath(3, 1, 7, MAINNET)).toBe("m/44'/119'/3'/1/7");
  });
});

// ---------------------------------------------------------------------------
// deriveAddress
// ---------------------------------------------------------------------------

describe("deriveAddress (BIP44 end-to-end)", () => {
  test("mainnet m/44'/119'/0'/0/0 matches pinned address", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const d = deriveAddress(seed, 0, 0, 0, MAINNET);
    expect(d.address).toBe(MAINNET_0_0_0_ADDRESS);
    expect(bytesToHex(d.publicKey)).toBe(MAINNET_0_0_0_PUBKEY);
    expect(bytesToHex(d.privateKey)).toBe(MAINNET_0_0_0_PRIVKEY);
    expect(d.path).toBe("m/44'/119'/0'/0/0");
  });

  test("mainnet m/44'/119'/0'/0/1 produces a different address", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const d0 = deriveAddress(seed, 0, 0, 0, MAINNET);
    const d1 = deriveAddress(seed, 0, 0, 1, MAINNET);
    expect(d1.address).toBe(MAINNET_0_0_1_ADDRESS);
    expect(d1.address).not.toBe(d0.address);
    expect(bytesToHex(d1.privateKey)).not.toBe(bytesToHex(d0.privateKey));
  });

  test("testnet m/44'/1'/0'/0/0 matches pinned address", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const d = deriveAddress(seed, 0, 0, 0, TESTNET);
    expect(d.address).toBe(TESTNET_0_0_0_ADDRESS);
    expect(d.path).toBe("m/44'/1'/0'/0/0");
  });

  test("mainnet and testnet differ for the same leaf", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const main = deriveAddress(seed, 0, 0, 0, MAINNET);
    const test = deriveAddress(seed, 0, 0, 0, TESTNET);
    expect(main.address).not.toBe(test.address);
  });

  test("different account paths derive different keys", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const acct0 = deriveAddress(seed, 0, 0, 0, MAINNET);
    const acct1 = deriveAddress(seed, 1, 0, 0, MAINNET);
    expect(acct0.address).not.toBe(acct1.address);
    expect(acct0.path).toBe("m/44'/119'/0'/0/0");
    expect(acct1.path).toBe("m/44'/119'/1'/0/0");
  });

  test("external and change chains produce different addresses", () => {
    const seed = mnemonicToSeed(TRIAL_MNEMONIC);
    const external = deriveAddress(seed, 0, 0, 0, MAINNET);
    const change = deriveAddress(seed, 0, 1, 0, MAINNET);
    expect(external.address).not.toBe(change.address);
  });
});
