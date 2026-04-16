# @fairco.in/core

FairCoin protocol primitives. Pure TypeScript, no React Native. BIP32/BIP39/BIP44
HD wallets, transaction building/signing, P2PKH scripts, address encoding,
network constants, Quark block-hash, BIP38 encrypted keys, and BIP21 URIs.

Used by the FAIRWallet app and the WFAIR bridge.

## Install

```sh
bun add @fairco.in/core
```

## Usage

```ts
import {
  MAINNET,
  generateMnemonic,
  mnemonicToSeed,
  deriveAddress,
} from "@fairco.in/core";

const mnemonic = generateMnemonic();
const seed = mnemonicToSeed(mnemonic);
const account = deriveAddress(seed, MAINNET, 0, 0, 0);
// account.address, account.privateKey, account.publicKey
```

## License

MIT
