import { decode } from "@stricahq/cbors";
import { isBytes, toBytes } from "./internal/bytes";

/**
 * The public key (label -2) of a COSE_Key, such as the `key` a CIP-30 wallet returns from
 * signData.
 *
 * @param cbor - the COSE_Key, as hex or bytes
 */
export const getPublicKeyFromCoseKey = (cbor: string | Uint8Array): Uint8Array => {
  const decodedCoseKey = decode(toBytes(cbor));
  if (!(decodedCoseKey instanceof Map)) throw Error("Invalid COSE_Key");

  const publicKeyBuffer = decodedCoseKey.get(-2);

  if (isBytes(publicKeyBuffer)) {
    return publicKeyBuffer;
  }

  throw Error("Public key not found");
};
