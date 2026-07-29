/**
 * Proof-of-work primitives, mirroring FairCoin's `pow.cpp` / `uint256`.
 *
 * These live here rather than in a consumer because they are consensus rules:
 * the SPV wallet gates headers on them, and this package's own mainnet vector
 * tests assert against them. Two implementations would have to stay
 * bit-identical forever, and nothing would catch it if they drifted.
 *
 * FairCoin is hybrid PoW/PoS. `main.cpp` calls `CheckBlockHeader` with
 * `block.IsProofOfWork()`, and `IsProofOfStake()` reads `vtx[1]` — which a
 * header-only client never has. But a proof-of-stake block is rejected at or
 * below `NetworkConfig.lastPowBlock`, so every header in that range is
 * provably proof-of-work and can be checked; above it, there is no work.
 */

const U256_MASK = (1n << 256n) - 1n;

export interface CompactTarget {
  /** The decoded 256-bit target value. */
  readonly target: bigint;
  /** True if the compact encoding had its sign bit set (an invalid target). */
  readonly negative: boolean;
  /** True if the mantissa/exponent combination overflows 256 bits. */
  readonly overflow: boolean;
}

/**
 * Decode a compact difficulty target ("nBits"), faithfully reproducing
 * FairCoin's `uint256::SetCompact` including its sign/overflow flags.
 */
export function compactToTarget(bits: number): CompactTarget {
  const nSize = (bits >>> 24) & 0xff;
  const nWord = bits & 0x007fffff;

  let target: bigint;
  if (nSize <= 3) {
    target = BigInt(nWord >>> (8 * (3 - nSize)));
  } else {
    target = (BigInt(nWord) << BigInt(8 * (nSize - 3))) & U256_MASK;
  }

  const negative = nWord !== 0 && (bits & 0x00800000) !== 0;
  const overflow =
    nWord !== 0 &&
    (nSize > 34 ||
      (nWord > 0xff && nSize > 33) ||
      (nWord > 0xffff && nSize > 32));

  return { target, negative, overflow };
}

/**
 * Whether `nBits` encodes a valid, in-range target — the range half of
 * `CheckProofOfWork`: reject negative, zero, overflowing or above-limit.
 */
export function isValidTargetBits(bits: number, powLimit: bigint): boolean {
  const { target, negative, overflow } = compactToTarget(bits);
  if (negative || overflow) return false;
  if (target === 0n) return false;
  if (target > powLimit) return false;
  return true;
}

/**
 * Read a block hash as the 256-bit number the target is compared against.
 *
 * `hashBlockHeader` returns bytes in internal (`uint256` serialisation) order,
 * which is little-endian: byte 0 is the least significant.
 */
export function hashToUint256(hash: Uint8Array): bigint {
  let value = 0n;
  for (let i = hash.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(hash[i]);
  }
  return value;
}

/**
 * The work half of `CheckProofOfWork`: `hash > bnTarget` fails, so equality
 * passes. Only meaningful at or below `NetworkConfig.lastPowBlock`.
 */
export function meetsProofOfWork(hash: Uint8Array, bits: number): boolean {
  const { target, negative, overflow } = compactToTarget(bits);
  if (negative || overflow || target === 0n) return false;
  return hashToUint256(hash) <= target;
}
