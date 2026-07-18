/**
 * @fairco.in/core — FairCoin protocol primitives.
 *
 * Public API surface. All exports are pure TypeScript with no React Native,
 * Expo, or browser-specific dependencies. Consumers include the FAIRWallet
 * app, the WFAIR bridge service, and future ecosystem tooling.
 */

export {
  type NetworkType,
  type NetworkConfig,
  MAINNET,
  TESTNET,
  getNetwork,
} from "./network.js";

export {
  hexToBytes,
  bytesToHex,
  bytesEqual,
  base58CheckEncode,
  base58CheckDecode,
  encodeAddress,
  decodeAddress,
  type DecodedAddress,
  encodeWIF,
  decodeWIF,
  type DecodedWIF,
  writeVarInt,
  readVarInt,
  type VarIntResult,
  writeUInt32LE,
  readUInt32LE,
  writeUInt64LE,
  readUInt64LE,
  writeInt32LE,
  readInt32LE,
  BufferWriter,
  BufferReader,
} from "./encoding.js";

export {
  hash160,
  publicKeyToAddress,
  addressToScriptHash,
  validateAddress,
  isP2PKH,
  isP2SH,
  reverseHex,
} from "./address.js";

export {
  Opcodes,
  pushData,
  createP2PKHScript,
  createP2SHScript,
  createP2PKHScriptSig,
  isP2PKHScript,
  isP2SHScript,
  extractAddressFromScript,
} from "./script.js";

export {
  createMultisigRedeemScript,
  type ParsedMultisigRedeemScript,
  parseMultisigRedeemScript,
  readMultisigThreshold,
  multisigAddress,
} from "./multisig-script.js";

export {
  type HDNode,
  type DerivedAddress,
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  deriveKeyFromSeed,
  getDerivationPath,
  deriveAddress,
} from "./hd-wallet.js";

export {
  SIGHASH_ALL,
  type TxInput,
  type TxOutput,
  type Transaction,
  type UTXO,
  type BuildTransactionParams,
  serializeTransaction,
  deserializeTransaction,
  hashTransaction,
  signInput,
  estimateTxSize,
  buildTransaction,
} from "./transaction.js";

export {
  type BlockHeader,
  serializeBlockHeader,
  quarkHash,
  hashBlockHeader,
  doubleSha256,
} from "./quark-hash.js";

export {
  type BIP38DecryptResult,
  encryptBIP38,
  decryptBIP38,
} from "./bip38.js";

export {
  type Checkpoint,
  MAINNET_CHECKPOINTS,
  TESTNET_CHECKPOINTS,
  getCheckpoints,
  getLatestCheckpoint,
  isCheckpointHeight,
  getCheckpointHash,
} from "./checkpoints.js";

export {
  type FairCoinURI,
  parseFairCoinURI,
  buildFairCoinURI,
} from "./uri.js";

export {
  COIN_NAME,
  COIN_TICKER,
  APP_NAME,
  COIN_SYMBOL,
  SMALLEST_UNIT_NAME,
  UNITS_PER_COIN,
  EXPLORER_BASE_URL,
  explorerTxUrl,
  explorerAddressUrl,
  BUY_BASE_URL,
  COMMUNITY_URL,
} from "./branding.js";

export {
  formatUnits,
  formatFair,
  parseFairToUnits,
} from "./format-amount.js";
