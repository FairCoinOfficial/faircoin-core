/**
 * Shared FAIR amount formatting utilities.
 *
 * All amounts in FAIRWallet are stored as `bigint` base units in m⊜
 * (1 FAIR = 100,000,000 m⊜, the same smallest-unit convention that
 * Bitcoin uses for satoshis). These helpers convert between the raw
 * base-unit representation and human-readable FAIR strings.
 *
 * Use `formatUnits` when full precision matters (copy, confirmation
 * dialogs, verification rows). Use `formatFair` for display-oriented
 * UI where trailing zeros would be visual noise.
 */

import { UNITS_PER_COIN } from "./branding.js";

const DECIMALS = 8;

/**
 * Insert thousands separators into a non-negative integer digit string.
 * Implemented manually because `Intl.NumberFormat.format(bigint)` throws
 * "Cannot convert BigInt to number" on Hermes (React Native's JS engine).
 */
function withThousandsSeparators(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Format smallest units (m⊜) as a FAIR decimal string with full
 * 8-decimal precision. Used for precise displays, copy-to-clipboard,
 * and confirmation dialogs.
 *
 * Example: 150000000n -> "1.50000000"
 */
export function formatUnits(value: bigint): string {
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const whole = abs / UNITS_PER_COIN;
  const frac = abs % UNITS_PER_COIN;
  const result = `${whole.toString()}.${frac.toString().padStart(DECIMALS, "0")}`;
  return negative ? `-${result}` : result;
}

/**
 * Format smallest units (m⊜) as a trimmed, human-readable FAIR string
 * with thousands separators. Trailing zeros in the decimal are stripped;
 * integer values render with no decimal point.
 *
 * Examples:
 *   100000000n      -> "1"
 *   150000000n      -> "1.5"
 *   123456780000n   -> "1,234.5678"
 *   1n              -> "0.00000001"
 *   0n              -> "0"
 */
export function formatFair(value: bigint): string {
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const whole = abs / UNITS_PER_COIN;
  const frac = abs % UNITS_PER_COIN;

  const wholeStr = withThousandsSeparators(whole.toString());
  const fracStr = frac.toString().padStart(DECIMALS, "0").replace(/0+$/, "");

  const result = fracStr.length > 0 ? `${wholeStr}.${fracStr}` : wholeStr;
  return negative ? `-${result}` : result;
}

/**
 * Parse a FAIR decimal string to smallest units (m⊜) using string-based
 * arithmetic to avoid floating-point precision issues.
 *
 * Returns `null` for empty, malformed, or negative input.
 *
 * Example: "1.5" -> 150000000n
 */
export function parseFairToUnits(input: string): bigint | null {
  const trimmed = input.trim();
  if (trimmed === "" || trimmed === ".") return null;

  const parts = trimmed.split(".");
  if (parts.length > 2) return null;

  const wholePart = parts[0] ?? "0";
  const fracPart = (parts[1] ?? "").padEnd(DECIMALS, "0").slice(0, DECIMALS);

  if (!/^\d*$/.test(wholePart) || !/^\d*$/.test(fracPart)) return null;

  try {
    const wholeNum = BigInt(wholePart === "" ? "0" : wholePart);
    const fracNum = BigInt(fracPart === "" ? "0" : fracPart);
    return wholeNum * UNITS_PER_COIN + fracNum;
  } catch {
    return null;
  }
}
