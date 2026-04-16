/**
 * Tests for FAIR amount formatting utilities.
 *
 * Covers every helper exported from format-amount.ts plus the edge
 * cases called out in the module docstring (trailing zeros, thousands
 * separators, precision, malformed inputs, over-precision inputs).
 */

import { describe, test, expect } from "bun:test";

import { formatFair, formatUnits, parseFairToUnits } from "../src/format-amount.js";

// ---------------------------------------------------------------------------
// formatUnits (full precision)
// ---------------------------------------------------------------------------

describe("formatUnits", () => {
  test("zero", () => {
    expect(formatUnits(0n)).toBe("0.00000000");
  });

  test("one base unit", () => {
    expect(formatUnits(1n)).toBe("0.00000001");
  });

  test("one whole coin", () => {
    expect(formatUnits(100_000_000n)).toBe("1.00000000");
  });

  test("1.5 FAIR", () => {
    expect(formatUnits(150_000_000n)).toBe("1.50000000");
  });

  test("large value preserves precision", () => {
    expect(formatUnits(123_456_789_012_345n)).toBe("1234567.89012345");
  });

  test("negative values", () => {
    expect(formatUnits(-150_000_000n)).toBe("-1.50000000");
    expect(formatUnits(-1n)).toBe("-0.00000001");
  });
});

// ---------------------------------------------------------------------------
// formatFair (trimmed, display)
// ---------------------------------------------------------------------------

describe("formatFair", () => {
  test("zero renders as plain 0", () => {
    expect(formatFair(0n)).toBe("0");
  });

  test("integer values drop the decimal point", () => {
    expect(formatFair(100_000_000n)).toBe("1");
    expect(formatFair(1_000_000_000n)).toBe("10");
    expect(formatFair(100_000_000_000n)).toBe("1,000");
  });

  test("trailing zeros are stripped", () => {
    expect(formatFair(150_000_000n)).toBe("1.5");
    expect(formatFair(125_000_000n)).toBe("1.25");
    expect(formatFair(123_400_000n)).toBe("1.234");
  });

  test("small fractional values keep precision", () => {
    expect(formatFair(1n)).toBe("0.00000001");
    expect(formatFair(10n)).toBe("0.0000001");
    expect(formatFair(100n)).toBe("0.000001");
  });

  test("thousands separator on large values", () => {
    expect(formatFair(123_456_780_000n)).toBe("1,234.5678");
    expect(formatFair(1_000_000_000_000n)).toBe("10,000");
    expect(formatFair(1_234_567_890_123_456n)).toBe("12,345,678.90123456");
  });

  test("negative values keep the sign", () => {
    expect(formatFair(-150_000_000n)).toBe("-1.5");
    expect(formatFair(-1n)).toBe("-0.00000001");
  });
});

// ---------------------------------------------------------------------------
// parseFairToUnits
// ---------------------------------------------------------------------------

describe("parseFairToUnits", () => {
  test("parses integer FAIR", () => {
    expect(parseFairToUnits("1")).toBe(100_000_000n);
    expect(parseFairToUnits("10")).toBe(1_000_000_000n);
    expect(parseFairToUnits("0")).toBe(0n);
  });

  test("parses fractional FAIR", () => {
    expect(parseFairToUnits("1.5")).toBe(150_000_000n);
    expect(parseFairToUnits("0.00000001")).toBe(1n);
    expect(parseFairToUnits("0.5")).toBe(50_000_000n);
  });

  test("parses values with no integer part", () => {
    expect(parseFairToUnits(".5")).toBe(50_000_000n);
  });

  test("parses values with trailing dot", () => {
    expect(parseFairToUnits("1.")).toBe(100_000_000n);
  });

  test("trims whitespace", () => {
    expect(parseFairToUnits("  1.5  ")).toBe(150_000_000n);
  });

  test("handles more than 8 decimals by truncating", () => {
    // The implementation trims excess decimals rather than rejecting.
    // 0.123456789 -> 0.12345678 -> 12345678 base units.
    expect(parseFairToUnits("0.123456789")).toBe(12_345_678n);
  });

  test("rejects empty input", () => {
    expect(parseFairToUnits("")).toBeNull();
  });

  test("rejects lone dot", () => {
    expect(parseFairToUnits(".")).toBeNull();
  });

  test("rejects more than one dot", () => {
    expect(parseFairToUnits("1.2.3")).toBeNull();
  });

  test("rejects non-numeric input", () => {
    expect(parseFairToUnits("abc")).toBeNull();
    expect(parseFairToUnits("1a")).toBeNull();
    expect(parseFairToUnits("not a number")).toBeNull();
  });

  test("rejects explicit sign", () => {
    // Parser only accepts plain digits — negative and explicit + are rejected
    // because non-digit characters fail the regex test.
    expect(parseFairToUnits("-1")).toBeNull();
    expect(parseFairToUnits("+1")).toBeNull();
  });

  test("round trip with formatFair", () => {
    // Each pair is (input, expected formatFair output). The expected value
    // adds thousands separators to the integer part only; the fractional
    // part is left untouched.
    const cases: Array<[string, string]> = [
      ["1", "1"],
      ["1.5", "1.5"],
      ["10", "10"],
      ["1234.5678", "1,234.5678"],
      ["0.00000001", "0.00000001"],
      ["0", "0"],
    ];
    for (const [input, expected] of cases) {
      const parsed = parseFairToUnits(input);
      expect(parsed).not.toBeNull();
      if (parsed !== null) {
        expect(formatFair(parsed)).toBe(expected);
      }
    }
  });
});
