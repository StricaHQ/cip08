import { expect } from "chai";

import { CoseSign1, getPublicKeyFromCoseKey } from "../src/index";

describe("CoseSign1", (): void => {
  before(async () => {});

  it(`Create CoseSign1 message`, () => {
    const expectedCoseSign1CBOR =
      "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a617061746958404a50d474e5d5e49ecd9f62bab0e246c1f6f700ab6d11d4c9378e891669c46edd2411aadfe35577addce00148036fe3b36de2e1ac4013404d1ef3e3850e58120d";

    const data = {
      addressBuffer: Buffer.from(
        "006807B8AA9C7F462BF43125D9C071FD01D0720E8133FA9532FFD24C19DB5E8ECE0982ACC4883DE67C2E3411CC26BD56686A162074998C02BC",
        "hex"
      ),
      publicKeyBuffer: Buffer.from(
        "C60060BA8A101B84BCAA1169D358C6C23B3F602F2E2EA9430ECFE2A4D9E19DEA",
        "hex"
      ),
      signature: Buffer.from(
        "4A50D474E5D5E49ECD9F62BAB0E246C1F6F700AB6D11D4C9378E891669C46EDD2411AADFE35577ADDCE00148036FE3B36DE2E1AC4013404D1EF3E3850E58120D",
        "hex"
      ),
    };

    const protectedMap = new Map();
    // Set protected headers as per CIP08
    // Set Algorthm used by Cardano keys
    protectedMap.set(1, -8);
    // Set PublicKey
    protectedMap.set(4, data.publicKeyBuffer);
    // Set Address
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: Buffer.from("mehul prajapati"),
      hashPayload: false,
    });

    const coseSign1 = coseSign1Builder.buildMessage(data.signature);

    expect(coseSign1.toString("hex")).eq(expectedCoseSign1CBOR);
  });

  it(`Create SigStructure`, () => {
    const expectedSigStructure =
      "846a5369676e6174757265315869a30127045820bbf06f180eda23ad804b93a99d24a979922169324f848a4ef6ac2c6d377ae5c567616464726573735839002cf23b5423fe2f4d5ad654ecfe1c234339199be5922a612eed14c065de39e719a0a9328f0875548639d694cdbb373923c34d6aae93c9cccb40506f6d6568756c207072616a6170617469";

    const data = {
      addressBuffer: Buffer.from(
        "002CF23B5423FE2F4D5AD654ECFE1C234339199BE5922A612EED14C065DE39E719A0A9328F0875548639D694CDBB373923C34D6AAE93C9CCCB",
        "hex"
      ),
      publicKeyBuffer: Buffer.from(
        "BBF06F180EDA23AD804B93A99D24A979922169324F848A4EF6AC2C6D377AE5C5",
        "hex"
      ),
      payloadBuffer: Buffer.from("6f6d6568756c207072616a6170617469", "hex"),
    };

    const protectedMap = new Map();
    // Set protected headers as per CIP08
    // Set Algorthm used by Cardano keys
    protectedMap.set(1, -8);
    // Set PublicKey
    protectedMap.set(4, data.publicKeyBuffer);
    // Set Address
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: data.payloadBuffer,
      hashPayload: false,
    });

    const sigStucture = coseSign1Builder.createSigStructure();

    expect(sigStucture.toString("hex")).eq(expectedSigStructure);
  });

  it(`Create SigStructure with Extranal Aad`, () => {
    const expectedSigStructure =
      "846a5369676e6174757265315869a30127045820bbf06f180eda23ad804b93a99d24a979922169324f848a4ef6ac2c6d377ae5c567616464726573735839002cf23b5423fe2f4d5ad654ecfe1c234339199be5922a612eed14c065de39e719a0a9328f0875548639d694cdbb373923c34d6aae93c9cccb4865787465726e616c506f6d6568756c207072616a6170617469";

    const data = {
      addressBuffer: Buffer.from(
        "002CF23B5423FE2F4D5AD654ECFE1C234339199BE5922A612EED14C065DE39E719A0A9328F0875548639D694CDBB373923C34D6AAE93C9CCCB",
        "hex"
      ),
      publicKeyBuffer: Buffer.from(
        "BBF06F180EDA23AD804B93A99D24A979922169324F848A4EF6AC2C6D377AE5C5",
        "hex"
      ),
      payloadBuffer: Buffer.from("6f6d6568756c207072616a6170617469", "hex"),
    };

    const protectedMap = new Map();
    // Set protected headers as per CIP08
    // Set Algorthm used by Cardano keys
    protectedMap.set(1, -8);
    // Set PublicKey
    protectedMap.set(4, data.publicKeyBuffer);
    // Set Address
    protectedMap.set("address", data.addressBuffer);

    const coseSign1Builder = new CoseSign1({
      protectedMap,
      unProtectedMap: new Map(),
      payload: data.payloadBuffer,
      hashPayload: false,
    });

    const sigStucture = coseSign1Builder.createSigStructure(Buffer.from("external"));

    expect(sigStucture.toString("hex")).eq(expectedSigStructure);
  });

  it("Verify", () => {
    const messageCBOR =
      "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a617061746958404a50d474e5d5e49ecd9f62bab0e246c1f6f700ab6d11d4c9378e891669c46edd2411aadfe35577addce00148036fe3b36de2e1ac4013404d1ef3e3850e58120d";
    const builder = CoseSign1.fromCbor(messageCBOR);

    const verified = builder.verifySignature();

    expect(verified).eq(true);
  });

  it("Verify External Aad", () => {
    const messageCBOR =
      "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a61706174695840beddb835fb9e82e9132417491437d197b7ca1765c70526484fc3b0fdc6821897696c83a398db88266f99c5665eb184cd106528bfc2251b3d6e7f0dbbc32a730f";
    const builder = CoseSign1.fromCbor(messageCBOR);

    const verified = builder.verifySignature({ externalAad: Buffer.from("external aad") });

    expect(verified).eq(true);
  });

  it("Verify with missing PublicKey in CoseSign1", () => {
    const messageCBOR =
      "845846a201276761646472657373583900c7a814c30663312017fb7f26de3c45ee66f018a787bda06975bd3ad857e3e14dcee6ba8f48b97044ca868b4ee017d04ecc792de386beab74a166686173686564f45054686973206973206120737472696e675840ccfb786d2a48e04056bd7eee05a42cc55f01c94de0e5a55e99ef64b799610502af1611f4585f4178546b04c7f7211393328321ce23058c29f101cb30e408a109";
    const builder = CoseSign1.fromCbor(messageCBOR);

    const pkBuffer = getPublicKeyFromCoseKey(
      "a40101032720062158203ec69aff937ffd1b1348ca83b423794554114be400926a805b27db92df814d79"
    );

    const verified = builder.verifySignature({
      publicKeyBuffer: pkBuffer,
    });
    expect(verified).eq(true);
  });
});
