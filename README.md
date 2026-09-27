<p align="center">
  <a href="https://strica.io/" target="_blank">
    <img src="https://docs.strica.io/images/logo.png" width="200">
  </a>
</p>

# @stricahq/cip08

[![npm](https://img.shields.io/npm/v/@stricahq/cip08.svg)](https://www.npmjs.com/package/@stricahq/cip08)
[![downloads](https://img.shields.io/npm/dm/@stricahq/cip08.svg)](https://www.npmjs.com/package/@stricahq/cip08)
[![node](https://img.shields.io/node/v/@stricahq/cip08.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/@stricahq/cip08.svg)](./LICENSE)

[CIP-8](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008) message signing for JavaScript. Use it to verify what a CIP-30 wallet's `signData` returns, or to build and sign COSE_Sign1 messages yourself. COSE_Sign and encryption aren't supported.

## v2 is a breaking change

v2 is ESM-only, needs Node 22.12 or later, and uses `Uint8Array` instead of `Buffer`. It also handles hashed and detached payloads the way CIP-8 specifies, which v1 didn't.

### Migrating from v1

| v1 | v2 |
|---|---|
| `Buffer` in and out | `Uint8Array` out; `Buffer` still accepted as input |
| `bytes.toString("hex")` | `Buffer.from(bytes).toString("hex")` |
| `fromCbor` and `getPublicKeyFromCoseKey` take hex | hex or bytes |
| `hashPayload()` hashes to 24 bytes | Blake2b-224, 28 bytes |
| a `null` payload is signed as CBOR `null` | the payload itself is signed, so pass it to `createSigStructure` and `verifySignature` |
| `verifySignature` throws on some malformed signatures | returns `false` |
| CommonJS package | ESM only, `require(esm)` on Node >= 22.12 |

A few of these won't show up as errors:

- `toString("hex")` on a `Uint8Array` returns comma-separated numbers instead of throwing, so code that turned a v1 result into hex keeps running with the wrong value.
- If you sign with `@stricahq/bip32ed25519`, move it to 2.x as well. 1.x expects a `Buffer` and signs the wrong bytes when you give it a `Uint8Array`.

## Installation

### yarn/npm

```sh
yarn add @stricahq/cip08
```

The package is ESM-only. On Node 22.12 or later you can still `require()` it from CommonJS:

```js
const { CoseSign1 } = require("@stricahq/cip08");
```

If you compile TypeScript to CommonJS, that needs TypeScript 5.8 or later with `"module": "nodenext"`.

### Browser

```html
<script src="https://cdn.jsdelivr.net/npm/@stricahq/cip08/dist/index.min.js"></script>
<script>
  const { CoseSign1, getPublicKeyFromCoseKey } = cip08;
</script>
```

If you use a bundler instead, you won't need polyfills or aliases. Nothing in the package or its dependencies uses Node.js builtins.

## Verifying a signature

A CIP-30 wallet's `signData(address, payload)` gives you back two hex strings: `signature`, the COSE_Sign1 message, and `key`, a COSE_Key holding the public key.

```js
import { CoseSign1, getPublicKeyFromCoseKey } from "@stricahq/cip08";

const { signature, key } = await api.signData(addressHex, payloadHex);

const coseSign1 = CoseSign1.fromCbor(signature);
const publicKeyBuffer = getPublicKeyFromCoseKey(key);
const verified = coseSign1.verifySignature({ publicKeyBuffer });
```

Always pass the key from `key`. Without one, `verifySignature()` reads the public key from label 4 of the protected header, which only works if the signer put it there. Label 4 is `kid`, a key identifier, and CIP-30 recommends setting it to the address, so with wallet output that call usually throws.

A valid signature only proves that the key signed the message. You still need to check that it's the message you asked for:

```js
coseSign1.getPayload(); // what was signed
coseSign1.isHashed(); // whether that's the message's Blake2b-224 hash
coseSign1.getAddress(); // the address in the protected header
```

Or pass the payload you expect, and the signature gets checked against it instead of the payload in the message:

```js
coseSign1.verifySignature({ publicKeyBuffer, payload: expectedPayload });
```

Keep in mind that the address is whatever the signer put there. To tie it to the key, check that the key's Blake2b-224 hash is the address's payment or stake credential.

## Signing

```js
import { CoseSign1 } from "@stricahq/cip08";

const protectedMap = new Map();
protectedMap.set(1, -8); // alg: EdDSA
protectedMap.set("address", addressBytes);

const coseSign1 = new CoseSign1({
  protectedMap,
  unProtectedMap: new Map(),
  payload: new TextEncoder().encode("sign in to example.com"),
});

// any Ed25519 key works, here a @stricahq/bip32ed25519 PrivateKey
const signature = privateKey.sign(coseSign1.createSigStructure());

const message = coseSign1.buildMessage(signature); // the COSE_Sign1 bytes
```

If the signature should also cover data that isn't in the message, the external AAD, pass it to both `createSigStructure(externalAad)` and `verifySignature({ externalAad })`.

### Hashed payload

Hardware wallets can't display a large payload, so CIP-8 lets you sign its Blake2b-224 hash instead. `hashPayload()` replaces the payload with the hash and sets `hashed` in the unprotected header:

```js
coseSign1.hashPayload();
const signature = privateKey.sign(coseSign1.createSigStructure()); // signs the hash
```

On the verifying side, `isHashed()` returns true, `getPayload()` returns the hash, and a payload you pass to `verifySignature` has to be the hash too.

### Detached payload

If both sides already have the payload, you can leave it out of the message with `payload: null`. The signature still covers it, so hand it over when you sign and when you verify:

```js
const coseSign1 = new CoseSign1({ protectedMap, unProtectedMap: new Map(), payload: null });
const signature = privateKey.sign(coseSign1.createSigStructure(undefined, payload));
const message = coseSign1.buildMessage(signature);

CoseSign1.fromCbor(message).verifySignature({ publicKeyBuffer, payload });
```

## Bytes and hex

Everything cip08 returns is a plain `Uint8Array`, and anywhere it takes bytes, any `Uint8Array` works, a Node.js `Buffer` included. `CoseSign1.fromCbor` and `getPublicKeyFromCoseKey` also take hex, and throw if it's malformed.

There are no hex helpers. On Node, use `Buffer.from(bytes).toString("hex")`. Newer runtimes have `bytes.toHex()`. Or use whatever your project already has.

## API docs

The full API reference is at [docs.strica.io/lib/cip08](https://docs.strica.io/lib/cip08).

# License

Copyright 2022 Strica

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
