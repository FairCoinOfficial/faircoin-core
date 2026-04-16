/**
 * BIP32/BIP39/BIP44 HD wallet support for FairCoin.
 * Generates 24-word mnemonics (256 bits entropy) and derives
 * keys using the FairCoin BIP44 coin type.
 */

import { HDKey } from "@scure/bip32";
import {
  generateMnemonic as bip39Generate,
  validateMnemonic as bip39Validate,
  mnemonicToSeedSync,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

import { publicKeyToAddress } from "./address.js";
import type { NetworkConfig } from "./network.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HDNode {
  /** Derive a child node at the given path segment. */
  derive(path: string): HDNode;
  /** Derive a hardened child at the given index. */
  deriveChild(index: number): HDNode;
  /** 33-byte compressed public key, or null if neutered. */
  readonly publicKey: Uint8Array | null;
  /** 32-byte private key, or null if this is a public-only (neutered) node. */
  readonly privateKey: Uint8Array | null;
  /** Depth of this node in the HD tree. */
  readonly depth: number;
  /** Child index of this node. */
  readonly index: number;
  /** The underlying HDKey instance. */
  readonly hdKey: HDKey;
}

export interface DerivedAddress {
  address: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  path: string;
}

// ---------------------------------------------------------------------------
// Mnemonic functions
// ---------------------------------------------------------------------------

/**
 * Generate a new 24-word BIP39 mnemonic (256 bits of entropy).
 */
export function generateMnemonic(): string {
  return bip39Generate(wordlist, 256);
}

/**
 * Validate a BIP39 mnemonic phrase against the English wordlist.
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39Validate(mnemonic, wordlist);
}

/**
 * Convert a mnemonic to a 64-byte seed.
 * Uses synchronous derivation (PBKDF2 with 2048 rounds of HMAC-SHA512).
 */
export function mnemonicToSeed(
  mnemonic: string,
  passphrase: string = "",
): Uint8Array {
  return mnemonicToSeedSync(mnemonic, passphrase);
}

// ---------------------------------------------------------------------------
// HD key derivation
// ---------------------------------------------------------------------------

function wrapHDKey(key: HDKey): HDNode {
  return {
    get publicKey(): Uint8Array | null {
      return key.publicKey ?? null;
    },
    get privateKey(): Uint8Array | null {
      return key.privateKey ?? null;
    },
    get depth(): number {
      return key.depth;
    },
    get index(): number {
      return key.index;
    },
    get hdKey(): HDKey {
      return key;
    },
    derive(path: string): HDNode {
      return wrapHDKey(key.derive(path));
    },
    deriveChild(index: number): HDNode {
      return wrapHDKey(key.deriveChild(index));
    },
  };
}

/**
 * Create an HD root node from a BIP39 seed.
 * Applies the FairCoin BIP32 version bytes from the network config.
 */
export function deriveKeyFromSeed(
  seed: Uint8Array,
  network: NetworkConfig,
): HDNode {
  const versions = {
    public: network.bip32.public,
    private: network.bip32.private,
  };
  const master = HDKey.fromMasterSeed(seed, versions);
  return wrapHDKey(master);
}

/**
 * Build a BIP44 derivation path:
 * m/44'/{coinType}'/account'/change/index
 */
export function getDerivationPath(
  account: number,
  change: number,
  index: number,
  network: NetworkConfig,
): string {
  return `m/44'/${network.bip44CoinType}'/${account}'/${change}/${index}`;
}

/**
 * Derive a full address (with keys) from seed at a BIP44 path.
 */
export function deriveAddress(
  seed: Uint8Array,
  account: number,
  change: number,
  index: number,
  network: NetworkConfig,
): DerivedAddress {
  const root = deriveKeyFromSeed(seed, network);
  const path = getDerivationPath(account, change, index, network);
  const child = root.derive(path);

  const publicKey = child.publicKey;
  const privateKey = child.privateKey;

  if (publicKey === null || privateKey === null) {
    throw new Error(
      "Failed to derive keys: HD node returned null keys at path " + path,
    );
  }

  const address = publicKeyToAddress(publicKey, network);

  return {
    address,
    publicKey,
    privateKey,
    path,
  };
}
