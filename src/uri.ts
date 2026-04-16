/**
 * Deep link parsing utilities for faircoin: URI scheme.
 *
 * Format: faircoin:<address>?amount=<amount>&label=<label>&message=<message>
 * Follows BIP21 conventions adapted for FairCoin.
 *
 * Examples:
 *   faircoin:FxxxxAddress
 *   faircoin:FxxxxAddress?amount=10.5
 *   faircoin:FxxxxAddress?amount=10.5&label=Donation&message=Thanks
 */

export interface FairCoinURI {
  address: string;
  amount: string | null;
  label: string | null;
  message: string | null;
}

/**
 * Parse a faircoin: URI into its components.
 * Returns null if the URI is invalid.
 */
export function parseFairCoinURI(uri: string): FairCoinURI | null {
  const trimmed = uri.trim();

  // Must start with faircoin:
  if (!trimmed.toLowerCase().startsWith("faircoin:")) {
    return null;
  }

  const withoutScheme = trimmed.slice("faircoin:".length);
  const [addressPart, queryString] = withoutScheme.split("?");

  if (!addressPart || addressPart.length < 25) {
    return null;
  }

  const result: FairCoinURI = {
    address: addressPart,
    amount: null,
    label: null,
    message: null,
  };

  if (queryString) {
    const params = new URLSearchParams(queryString);
    const amount = params.get("amount");
    const label = params.get("label");
    const message = params.get("message");

    if (amount) {
      result.amount = amount;
    }
    if (label) {
      result.label = decodeURIComponent(label);
    }
    if (message) {
      result.message = decodeURIComponent(message);
    }
  }

  return result;
}

/**
 * Build a faircoin: URI from components.
 */
export function buildFairCoinURI(
  address: string,
  amount?: string,
  label?: string,
  message?: string,
): string {
  let uri = `faircoin:${address}`;
  const params: string[] = [];

  if (amount) {
    params.push(`amount=${amount}`);
  }
  if (label) {
    params.push(`label=${encodeURIComponent(label)}`);
  }
  if (message) {
    params.push(`message=${encodeURIComponent(message)}`);
  }

  if (params.length > 0) {
    uri += `?${params.join("&")}`;
  }

  return uri;
}
