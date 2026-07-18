/**
 * Identity-key social-receive address scheme.
 *
 * A generic secp256k1 identity-key-derived FairCoin address scheme: given
 * ONLY a public key, anyone can compute a deterministic sequence of FairCoin
 * addresses (`addr(0)`, `addr(1)`, …); given the matching private key, the
 * key holder can derive the spending key for any of those addresses. This
 * lets a payer compute a receive address for a recipient's identity key
 * without any interaction, while only the recipient can ever spend from it.
 *
 * No dependency on Oxy, DID, or `@oxyhq/core` — inputs are generic secp256k1
 * public/private key bytes. Oxy Pay's usage happens to source the public key
 * from an Oxy DID (`resolveDid()`'s `verificationMethod[].publicKeyHex`) and
 * the private key from `@oxyhq/core`'s `KeyManager.getPrivateKey()`/
 * `getSharedPrivateKey()`, but this module has no knowledge of that — it is
 * exactly as generic as `multisig-script.ts`'s multisig scheme.
 *
 * Scheme (both sides compute the SAME deterministic chain code, so a payer
 * and the key holder always agree on `addr(i)`):
 *   IK_pub      = the identity's public key, NORMALIZED to compressed form
 *   IK_priv     = the identity's private key (key holder only)
 *   cc          = HMAC-SHA256(key = SOCIAL_RECEIVE_CHAIN_CODE_KEY, msg = IK_pub)
 *   xpub_social = HDKey({ publicKey: IK_pub,  chainCode: cc, depth: 0 })   // public path
 *   xprv_social = HDKey({ privateKey: IK_priv, chainCode: cc, depth: 0 })  // private path
 *   addr(i)     = publicKeyToAddress(xpub_social.deriveChild(i).publicKey, network)
 *
 * Normalization is load-bearing: a caller may pass either a compressed
 * (33-byte) or uncompressed (65-byte) public key encoding — hashing the raw,
 * un-normalized bytes into the chain code would make the two paths derive
 * DIFFERENT addresses for the SAME key. Every public key entering this
 * module is routed through `@scure/bip32`'s own point-normalization first.
 *
 * Non-hardened derivation only (`index < HARDENED_OFFSET`) — a hardened
 * index would require the private key on the public path, so it is rejected
 * up front with a clear error instead of failing deep inside `@scure/bip32`.
 */
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";
import { HDKey, HARDENED_OFFSET } from "@scure/bip32";
import { publicKeyToAddress } from "./address.js";
import type { NetworkConfig } from "./network.js";

/**
 * HMAC key domain-separating this chain code from every other derivation.
 * Versioned so a future scheme change is a new, non-colliding tag.
 */
const SOCIAL_RECEIVE_CHAIN_CODE_KEY = utf8ToBytes("oxypay/faircoin/social/v1");

/** Highest legal `index` — `@scure/bip32` treats `>= HARDENED_OFFSET` as a hardened child. */
export const MAX_SOCIAL_RECEIVE_INDEX = HARDENED_OFFSET - 1;

function assertValidIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index > MAX_SOCIAL_RECEIVE_INDEX) {
    throw new Error(
      `social-receive: index must be an integer in [0, ${MAX_SOCIAL_RECEIVE_INDEX}], got ${index}`,
    );
  }
}

/**
 * Normalize a public key to `@scure/bip32`'s canonical (compressed, 33-byte)
 * representation, regardless of whether the caller passed a compressed or
 * uncompressed encoding. MUST be called before this key is hashed into a
 * chain code or used to construct the branch's `HDKey` — see the module
 * doc-comment's normalization note.
 */
function normalizePublicKey(publicKey: Uint8Array): Uint8Array {
  const probe = new HDKey({ publicKey, depth: 0 });
  if (!probe.publicKey) {
    throw new Error("social-receive: failed to normalize public key");
  }
  return probe.publicKey;
}

/**
 * The deterministic, PUBLIC chain code for a key's social-receive branch.
 * `normalizedPublicKey` MUST already be normalized (compressed) — callers in
 * this module always pass it through {@link normalizePublicKey} or an
 * equivalently-normalized source (a private-key-derived probe) first.
 */
function buildSocialReceiveChainCode(normalizedPublicKey: Uint8Array): Uint8Array {
  return hmac(sha256, SOCIAL_RECEIVE_CHAIN_CODE_KEY, normalizedPublicKey);
}

/**
 * Derive a secp256k1 keypair's own public key (always compressed, 33 bytes)
 * from its private key. Lets the key holder compute its OWN social-receive
 * watch addresses via {@link deriveSocialReceiveAddress} from a SINGLE input
 * (the private key it already holds) instead of separately fetching a public
 * key that could theoretically get out of sync with it.
 */
export function publicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
  const probe = new HDKey({ privateKey, depth: 0 });
  if (!probe.publicKey) {
    throw new Error("social-receive: failed to derive public key from private key");
  }
  return probe.publicKey;
}

/**
 * PAYER / BACKEND path — public-only. Compute the FairCoin address a payer
 * would send social-receive child `index` to, from ONLY the recipient's
 * PUBLIC key. Never touches a private key.
 */
export function deriveSocialReceiveAddress(
  identityPublicKey: Uint8Array,
  index: number,
  network: NetworkConfig,
): string {
  assertValidIndex(index);
  const normalized = normalizePublicKey(identityPublicKey);
  const chainCode = buildSocialReceiveChainCode(normalized);
  const xpubSocial = new HDKey({ publicKey: normalized, chainCode, depth: 0 });
  const child = xpubSocial.deriveChild(index);
  if (!child.publicKey) {
    throw new Error("social-receive: failed to derive child public key");
  }
  return publicKeyToAddress(child.publicKey, network);
}

/**
 * RECIPIENT path — holds the PRIVATE key. Derive the spending private key
 * for social-receive child `index`. `publicKeyToAddress` of the matching
 * public key equals what {@link deriveSocialReceiveAddress} computes for the
 * SAME key + index — pinned down by the crypto unit tests.
 */
export function deriveSocialReceiveSpendingKey(
  identityPrivateKey: Uint8Array,
  index: number,
): Uint8Array {
  assertValidIndex(index);
  // The private-key branch's own public key is ALREADY compressed
  // (`@scure/bip32` derives it via `secp.getPublicKey(priv, true)`), so no
  // extra normalization call is needed here.
  const normalized = publicKeyFromPrivateKey(identityPrivateKey);
  const chainCode = buildSocialReceiveChainCode(normalized);
  const xprvSocial = new HDKey({ privateKey: identityPrivateKey, chainCode, depth: 0 });
  const child = xprvSocial.deriveChild(index);
  if (!child.privateKey) {
    throw new Error("social-receive: failed to derive child private key");
  }
  return child.privateKey;
}
