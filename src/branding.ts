/**
 * FAIRWallet branding constants.
 *
 * Centralizes coin name, symbols, units, and explorer URLs so they are not
 * duplicated as magic strings across the codebase. Update these values here
 * to rebrand the entire app.
 */

/** Full coin name. */
export const COIN_NAME = "FairCoin";

/** Short ticker / display name. */
export const COIN_TICKER = "FAIR";

/** App / wallet name. */
export const APP_NAME = "FAIRWallet";

/** Coin symbol glyph (Unicode U+229C). */
export const COIN_SYMBOL = "\u229C"; // ⊜

/** Smallest unit display name (m⊜ — analogous to "satoshi" in Bitcoin). */
export const SMALLEST_UNIT_NAME = "m\u229C"; // m⊜

/** Smallest units per whole coin. 1 FAIR = 100,000,000 m⊜ */
export const UNITS_PER_COIN = 100_000_000n;

/** Block explorer base URL. Append the txid to get a tx URL. */
export const EXPLORER_BASE_URL = "https://explorer.fairco.in";

/** Build a transaction explorer URL for the given txid. */
export function explorerTxUrl(txid: string): string {
  return `${EXPLORER_BASE_URL}/tx/${txid}`;
}

/** Build an address explorer URL. */
export function explorerAddressUrl(address: string): string {
  return `${EXPLORER_BASE_URL}/address/${address}`;
}

/** Buy page URL — the in-app browser flow. */
export const BUY_BASE_URL = "https://buy.fairco.in";

/** Default community/website link. */
export const COMMUNITY_URL = "https://fairco.in";
