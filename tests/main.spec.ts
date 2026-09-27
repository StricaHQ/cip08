import { beforeAll, describe, expect, it } from "vitest";
import { runInNewContext } from "node:vm";
import { decode, encode } from "@stricahq/cbors";
import { Bip32PrivateKey, PrivateKey } from "@stricahq/bip32ed25519";

import { CoseSign1, getPublicKeyFromCoseKey } from "../src/index";

const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const ADDRESS = hex(
  "006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bc"
);

const MESSAGE =
  "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a617061746958404a50d474e5d5e49ecd9f62bab0e246c1f6f700ab6d11d4c9378e891669c46edd2411aadfe35577addce00148036fe3b36de2e1ac4013404d1ef3e3850e58120d";

const MESSAGE_WITHOUT_KEY =
  "845846a201276761646472657373583900c7a814c30663312017fb7f26de3c45ee66f018a787bda06975bd3ad857e3e14dcee6ba8f48b97044ca868b4ee017d04ecc792de386beab74a166686173686564f45054686973206973206120737472696e675840ccfb786d2a48e04056bd7eee05a42cc55f01c94de0e5a55e99ef64b799610502af1611f4585f4178546b04c7f7211393328321ce23058c29f101cb30e408a109";
const COSE_KEY =
  "a40101032720062158203ec69aff937ffd1b1348ca83b423794554114be400926a805b27db92df814d79";

// made with Emurgo's cardano-message-signing, the reference implementation
const REFERENCE_PUBLIC_KEY = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const REFERENCE_HASHED =
  "845869a30127045820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f5581c47c7d6f36f3ec09aa99785b789241921fd82b37005c764d5bbb7cf7a584023eb07f7088e47eecb0af07c28a94b6125551698ae37a274631bdd3b801f8f819fbcc801cd23303f78ab329c5abcf15f206e7da89ad02384a4bae959ea5afe0f";
const REFERENCE_DETACHED =
  "845846a2012767616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f4f65840fbaeda7f1b6e1ef339b3e7df4aad2b1404d7daa7b982778613d2aa17e0a40ed2b01cf2397822047045e5f4eb7537b6bee21fd5126451542b214475b098ddf401";

let privateKey: PrivateKey;
let publicKey: Uint8Array;

const sign = (sigStructure: Uint8Array): Uint8Array => privateKey.sign(sigStructure);

const protectedHeaders = (): Map<any, any> =>
  new Map<any, any>([
    [1, -8],
    [4, publicKey],
    ["address", ADDRESS],
  ]);

beforeAll(async () => {
  const rootKey = await Bip32PrivateKey.fromEntropy(new Uint8Array(32).fill(1));
  privateKey = rootKey.derivePath("m/1852'/1815'/0'/0/0").toPrivateKey();
  publicKey = privateKey.toPublicKey().toBytes();
});

describe("CoseSign1", (): void => {
  it(`Create CoseSign1 message`, () => {
    const data = {
      addressBuffer: ADDRESS,
      publicKeyBuffer: hex("C60060BA8A101B84BCAA1169D358C6C23B3F602F2E2EA9430ECFE2A4D9E19DEA"),
      signature: hex(
        "4A50D474E5D5E49ECD9F62BAB0E246C1F6F700AB6D11D4C9378E891669C46EDD2411AADFE35577ADDCE00148036FE3B36DE2E1AC4013404D1EF3E3850E58120D"
      ),
    };

    const protectedMap = new Map();
    protectedMap.set(1, -8);
    protectedMap.set(4, data.publicKeyBuffer);
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });

    const coseSign1 = coseSign1Builder.buildMessage(data.signature);

    expect(toHex(coseSign1)).eq(MESSAGE);
  });

  it(`Create SigStructure`, () => {
    const expectedSigStructure =
      "846a5369676e6174757265315869a30127045820bbf06f180eda23ad804b93a99d24a979922169324f848a4ef6ac2c6d377ae5c567616464726573735839002cf23b5423fe2f4d5ad654ecfe1c234339199be5922a612eed14c065de39e719a0a9328f0875548639d694cdbb373923c34d6aae93c9cccb40506f6d6568756c207072616a6170617469";

    const data = {
      addressBuffer: hex(
        "002CF23B5423FE2F4D5AD654ECFE1C234339199BE5922A612EED14C065DE39E719A0A9328F0875548639D694CDBB373923C34D6AAE93C9CCCB"
      ),
      publicKeyBuffer: hex("BBF06F180EDA23AD804B93A99D24A979922169324F848A4EF6AC2C6D377AE5C5"),
      payloadBuffer: hex("6f6d6568756c207072616a6170617469"),
    };

    const protectedMap = new Map();
    protectedMap.set(1, -8);
    protectedMap.set(4, data.publicKeyBuffer);
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: data.payloadBuffer,
    });

    const sigStructure = coseSign1Builder.createSigStructure();

    expect(toHex(sigStructure)).eq(expectedSigStructure);
  });

  it(`Create SigStructure with External Aad`, () => {
    const expectedSigStructure =
      "846a5369676e6174757265315869a30127045820bbf06f180eda23ad804b93a99d24a979922169324f848a4ef6ac2c6d377ae5c567616464726573735839002cf23b5423fe2f4d5ad654ecfe1c234339199be5922a612eed14c065de39e719a0a9328f0875548639d694cdbb373923c34d6aae93c9cccb4865787465726e616c506f6d6568756c207072616a6170617469";

    const data = {
      addressBuffer: hex(
        "002CF23B5423FE2F4D5AD654ECFE1C234339199BE5922A612EED14C065DE39E719A0A9328F0875548639D694CDBB373923C34D6AAE93C9CCCB"
      ),
      publicKeyBuffer: hex("BBF06F180EDA23AD804B93A99D24A979922169324F848A4EF6AC2C6D377AE5C5"),
      payloadBuffer: hex("6f6d6568756c207072616a6170617469"),
    };

    const protectedMap = new Map();
    protectedMap.set(1, -8);
    protectedMap.set(4, data.publicKeyBuffer);
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: data.payloadBuffer,
    });

    const sigStructure = coseSign1Builder.createSigStructure(utf8("external"));

    expect(toHex(sigStructure)).eq(expectedSigStructure);
  });

  it("Verify", () => {
    const builder = CoseSign1.fromCbor(MESSAGE);

    const verified = builder.verifySignature();

    expect(verified).eq(true);
  });

  it("Verify External Aad", () => {
    const messageCBOR =
      "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a61706174695840beddb835fb9e82e9132417491437d197b7ca1765c70526484fc3b0fdc6821897696c83a398db88266f99c5665eb184cd106528bfc2251b3d6e7f0dbbc32a730f";
    const builder = CoseSign1.fromCbor(messageCBOR);

    const verified = builder.verifySignature({ externalAad: utf8("external aad") });

    expect(verified).eq(true);
  });

  it("Verify with missing PublicKey in CoseSign1", () => {
    const builder = CoseSign1.fromCbor(MESSAGE_WITHOUT_KEY);

    const pkBuffer = getPublicKeyFromCoseKey(COSE_KEY);

    const verified = builder.verifySignature({
      publicKeyBuffer: pkBuffer,
    });
    expect(verified).eq(true);
  });

  it("Signs and verifies a message", () => {
    const payload = utf8("sign in to example.com");
    const coseSign1 = new CoseSign1({
      protectedMap: protectedHeaders(),
      unProtectedMap: new Map(),
      payload,
    });
    const message = coseSign1.buildMessage(sign(coseSign1.createSigStructure()));

    const parsed = CoseSign1.fromCbor(message);
    expect(parsed.verifySignature()).eq(true);
    expect(toHex(parsed.getPayload()!)).eq(toHex(payload));
    expect(toHex(parsed.getAddress()!)).eq(toHex(ADDRESS));
    expect(toHex(parsed.getPublicKey()!)).eq(toHex(publicKey));

    expect(parsed.verifySignature({ externalAad: utf8("external aad") })).eq(false);
    expect(parsed.verifySignature({ payload: utf8("sign in to example.org") })).eq(false);
    expect(parsed.verifySignature({ publicKeyBuffer: hex(REFERENCE_PUBLIC_KEY) })).eq(false);
  });

  it("Returns false for a signature that does not verify", () => {
    const tampered = `${MESSAGE.slice(0, -2)}0e`;
    expect(CoseSign1.fromCbor(tampered).verifySignature()).eq(false);

    const withSignature = (signature: Uint8Array) =>
      CoseSign1.fromCbor(CoseSign1.fromCbor(MESSAGE).buildMessage(signature));

    expect(withSignature(new Uint8Array(63)).verifySignature()).eq(false);

    const offCurve = new Uint8Array(64);
    offCurve[0] = 2;
    expect(withSignature(offCurve).verifySignature()).eq(false);

    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const signature = CoseSign1.fromCbor(MESSAGE).getSignature()!;
    const S = BigInt(`0x${toHex(signature.slice(32).reverse())}`);
    const unreduced = hex((S + L).toString(16).padStart(64, "0")).reverse();
    expect(
      withSignature(Uint8Array.of(...signature.slice(0, 32), ...unreduced)).verifySignature()
    ).eq(false);
  });

  it("Throws on a missing or malformed public key or signature", () => {
    const withoutKey = CoseSign1.fromCbor(MESSAGE_WITHOUT_KEY);
    expect(() => withoutKey.verifySignature()).toThrow("Public key not found");
    expect(() => withoutKey.verifySignature({ publicKeyBuffer: new Uint8Array(31) })).toThrow(
      "Invalid public key"
    );
    expect(() => withoutKey.verifySignature({ publicKeyBuffer: new Uint8Array(64) })).toThrow(
      "Invalid public key"
    );

    const unsigned = new CoseSign1({
      protectedMap: protectedHeaders(),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });
    expect(() => unsigned.verifySignature()).toThrow("Signature not found");
  });

  it("Throws on inputs that would make an invalid message", () => {
    const headers = () => ({ protectedMap: new Map([[1, -8]]), unProtectedMap: new Map() });

    expect(() => new CoseSign1({ ...headers(), payload: "mehul prajapati" as any })).toThrow(
      "Invalid payload"
    );
    expect(() => new CoseSign1({ ...headers() } as any)).toThrow("Invalid payload");

    const coseSign1 = new CoseSign1({ ...headers(), payload: utf8("mehul prajapati") });
    expect(() => coseSign1.createSigStructure("external" as any)).toThrow("Invalid externalAad");
    expect(() => coseSign1.createSigStructure(undefined, "payload" as any)).toThrow(
      "Invalid payload"
    );
    expect(() => coseSign1.buildMessage(toHex(new Uint8Array(64)) as any)).toThrow(
      "Invalid signature"
    );
  });

  it("Returns plain Uint8Arrays, and takes Node.js buffers", () => {
    const withBuffers = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: Buffer.from("mehul prajapati"),
    });
    const withBytes = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });

    const sigStructure = withBuffers.createSigStructure(Buffer.from("external"));
    expect(toHex(sigStructure)).eq(toHex(withBytes.createSigStructure(utf8("external"))));

    const message = withBuffers.buildMessage(Buffer.alloc(64, 1));
    const parsed = CoseSign1.fromCbor(Buffer.from(message));
    for (const bytes of [
      sigStructure,
      message,
      withBuffers.getPayload()!,
      withBuffers.getSignature()!,
      parsed.getPayload()!,
      parsed.getSignature()!,
    ]) {
      expect(bytes.constructor).eq(Uint8Array);
    }
  });

  it("Takes Uint8Arrays from another realm", () => {
    const foreign = runInNewContext("new Uint8Array([1, 2, 3])");
    expect(foreign instanceof Uint8Array).eq(false);

    const coseSign1 = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: foreign,
    });
    expect(toHex(decode(coseSign1.createSigStructure(foreign))[2])).eq("010203");
    coseSign1.hashPayload();
    expect(coseSign1.getPayload()!.length).eq(28);

    const message = runInNewContext(`new Uint8Array([${hex(MESSAGE).join(",")}])`);
    expect(CoseSign1.fromCbor(message).verifySignature()).eq(true);
  });
});

describe("fromCbor", (): void => {
  it("Takes bytes as well as hex", () => {
    expect(CoseSign1.fromCbor(hex(MESSAGE)).verifySignature()).eq(true);
    expect(CoseSign1.fromCbor(MESSAGE.toUpperCase()).verifySignature()).eq(true);
  });

  it("Throws on malformed hex", () => {
    expect(() => CoseSign1.fromCbor(MESSAGE.slice(0, -1))).toThrow("Invalid hex string");
    expect(() => CoseSign1.fromCbor(`${MESSAGE.slice(0, -2)}zz`)).toThrow("Invalid hex string");
    expect(() => CoseSign1.fromCbor(12 as any)).toThrow("Expected a hex string or a Uint8Array");
  });

  it("Throws on anything but a COSE_Sign1", () => {
    const items = decode(hex(MESSAGE));
    const withItem = (index: number, value: any): Uint8Array => {
      const replaced = [...items];
      replaced[index] = value;
      return encode(replaced);
    };

    expect(() => CoseSign1.fromCbor(encode(new Map()))).toThrow("Invalid CBOR");
    expect(() => CoseSign1.fromCbor(encode(items.slice(0, 3)))).toThrow("Invalid COSE_SIGN1");
    expect(() => CoseSign1.fromCbor(withItem(0, "a1"))).toThrow("Invalid protected");
    expect(() => CoseSign1.fromCbor(withItem(0, encode([1, -8])))).toThrow("Invalid protected");
    expect(() => CoseSign1.fromCbor(withItem(0, hex("a201")))).toThrow("Invalid protected");
    expect(() => CoseSign1.fromCbor(withItem(1, []))).toThrow("Invalid unprotected");
    expect(() => CoseSign1.fromCbor(withItem(2, "mehul prajapati"))).toThrow("Invalid payload");
    expect(() => CoseSign1.fromCbor(withItem(3, null))).toThrow("Invalid signature");
  });
});

describe("Protected header", (): void => {
  it("Writes and reads an empty protected header as a zero-length byte string", () => {
    const coseSign1 = new CoseSign1({
      protectedMap: new Map(),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });
    const sigStructure = coseSign1.createSigStructure();
    const message = coseSign1.buildMessage(sign(sigStructure));

    expect(decode(sigStructure)[1]).toEqual(new Uint8Array(0));
    expect(decode(message)[0]).toEqual(new Uint8Array(0));
    expect(CoseSign1.fromCbor(message).verifySignature({ publicKeyBuffer: publicKey })).eq(true);
  });

  it("Verifies against the protected header as written, not as encoded again", () => {
    // {1: -8, "address": ...}, with the label 1 written in two bytes (18 01) where one would do
    const protectedSerialized = hex(`a218012767616464726573735839${toHex(ADDRESS)}`);
    expect(toHex(encode(decode(protectedSerialized)))).not.eq(toHex(protectedSerialized));

    const payload = utf8("mehul prajapati");
    const signature = sign(encode(["Signature1", protectedSerialized, new Uint8Array(0), payload]));
    const message = encode([protectedSerialized, new Map([["hashed", false]]), payload, signature]);

    const coseSign1 = CoseSign1.fromCbor(message);
    expect(coseSign1.verifySignature({ publicKeyBuffer: publicKey })).eq(true);
    expect(toHex(coseSign1.buildMessage(signature))).eq(toHex(message));
  });
});

describe("Hashed payload", (): void => {
  it("Builds the reference implementation's hashed message", () => {
    const reference = CoseSign1.fromCbor(REFERENCE_HASHED);
    expect(reference.verifySignature()).eq(true);

    const coseSign1 = new CoseSign1({
      protectedMap: new Map<any, any>([
        [1, -8],
        [4, hex(REFERENCE_PUBLIC_KEY)],
        ["address", ADDRESS],
      ]),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });
    coseSign1.hashPayload();

    expect(toHex(coseSign1.createSigStructure())).eq(toHex(reference.createSigStructure()));
    expect(toHex(coseSign1.buildMessage(reference.getSignature()!))).eq(REFERENCE_HASHED);
  });

  it("Reads the hashed header", () => {
    expect(CoseSign1.fromCbor(REFERENCE_HASHED).isHashed()).eq(true);
    expect(CoseSign1.fromCbor(REFERENCE_DETACHED).isHashed()).eq(false);

    const coseSign1 = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });
    expect(coseSign1.isHashed()).eq(false);
    coseSign1.hashPayload();
    expect(coseSign1.isHashed()).eq(true);
  });

  it("Hashes a payload only once", () => {
    const coseSign1 = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: utf8("mehul prajapati"),
    });
    coseSign1.hashPayload();
    expect(() => coseSign1.hashPayload()).toThrow("Payload already hashed");

    const detached = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map(),
      payload: null,
    });
    expect(() => detached.hashPayload()).toThrow("Invalid payload");

    const invalidHeader = new CoseSign1({
      protectedMap: new Map([[1, -8]]),
      unProtectedMap: new Map([["hashed", 0]]),
      payload: utf8("mehul prajapati"),
    });
    expect(() => invalidHeader.hashPayload()).toThrow("Invalid unprotected map");
  });
});

describe("Detached payload", (): void => {
  it("Verifies the reference implementation's detached message against the payload", () => {
    const coseSign1 = CoseSign1.fromCbor(REFERENCE_DETACHED);
    const publicKeyBuffer = hex(REFERENCE_PUBLIC_KEY);

    expect(coseSign1.getPayload()).eq(null);
    expect(coseSign1.verifySignature({ publicKeyBuffer, payload: utf8("mehul prajapati") })).eq(
      true
    );
    expect(coseSign1.verifySignature({ publicKeyBuffer, payload: utf8("someone else") })).eq(false);
    expect(() => coseSign1.verifySignature({ publicKeyBuffer })).toThrow("Payload is detached");
  });

  it("Signs the payload and leaves it out of the message", () => {
    const payload = utf8("mehul prajapati");
    const detached = new CoseSign1({
      protectedMap: protectedHeaders(),
      unProtectedMap: new Map(),
      payload: null,
    });
    const attached = new CoseSign1({
      protectedMap: protectedHeaders(),
      unProtectedMap: new Map(),
      payload,
    });

    expect(() => detached.createSigStructure()).toThrow("Payload is detached");
    const sigStructure = detached.createSigStructure(undefined, payload);
    expect(toHex(sigStructure)).eq(toHex(attached.createSigStructure()));

    const message = detached.buildMessage(sign(sigStructure));
    expect(decode(message)[2]).eq(null);
    expect(CoseSign1.fromCbor(message).verifySignature({ payload })).eq(true);
  });
});

describe("getPublicKeyFromCoseKey", (): void => {
  it("Reads the public key from hex or bytes", () => {
    const expected = "3ec69aff937ffd1b1348ca83b423794554114be400926a805b27db92df814d79";

    expect(toHex(getPublicKeyFromCoseKey(COSE_KEY))).eq(expected);
    expect(toHex(getPublicKeyFromCoseKey(hex(COSE_KEY)))).eq(expected);
  });

  it("Throws on anything but a COSE_Key with a public key", () => {
    expect(() => getPublicKeyFromCoseKey(toHex(encode([1, 6])))).toThrow("Invalid COSE_Key");
    expect(() => getPublicKeyFromCoseKey(toHex(encode(new Map([[1, 1]]))))).toThrow(
      "Public key not found"
    );
    expect(() => getPublicKeyFromCoseKey(toHex(encode(new Map([[-2, "key"]]))))).toThrow(
      "Public key not found"
    );
  });
});
