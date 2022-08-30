import { Decoder } from "@stricahq/cbors";

export const getPublicKeyFromCoseKey = (cbor: string): Buffer => {
  const decodedCoseKey = Decoder.decode(Buffer.from(cbor, "hex"));
  const publicKeyBuffer = decodedCoseKey.value.get(-2);

  if (publicKeyBuffer) {
    return publicKeyBuffer;
  }

  throw Error("Public key not found");
};
