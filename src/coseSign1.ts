import { blake2b } from "@noble/hashes/blake2.js";
import { PublicKey } from "@stricahq/bip32ed25519";
import { type CborNode, decodeAnnotated, encode } from "@stricahq/cbors";
import { isBytes, plainView, toBytes } from "./internal/bytes";

const EMPTY = new Uint8Array(0);

// a Map keeps only the last value of a repeated label, but another reader may take the first,
// and the signature covers both
const hasDuplicateLabel = (header: CborNode, map: Map<any, any>): boolean =>
  map.size !== header.entries!.length;

class CoseSign1 {
  private protectedMap: Map<any, any>;

  private unProtectedMap: Map<any, any>;

  private payload: Uint8Array | null;

  private signature: Uint8Array | undefined;

  // the protected header of a parsed message as written: the signature covers these exact
  // bytes, and encoding the map again may not give them back
  private protectedSerialized: Uint8Array | undefined;

  constructor(options: {
    protectedMap: Map<any, any>;
    unProtectedMap: Map<any, any>;
    /** null for a detached payload */
    payload: Uint8Array | null;
    signature?: Uint8Array;
  }) {
    const { payload, signature } = options;
    if (payload !== null && !isBytes(payload)) throw TypeError("Invalid payload");
    if (signature !== undefined && !isBytes(signature)) throw TypeError("Invalid signature");

    this.protectedMap = options.protectedMap;
    this.unProtectedMap = options.unProtectedMap;
    this.payload = payload && plainView(payload);

    if (this.unProtectedMap.get("hashed") == null) {
      this.unProtectedMap.set("hashed", false);
    }

    this.signature = signature && plainView(signature);
  }

  /**
   * Parses a COSE_Sign1 message, given as hex or bytes. Throws if a header has the same label
   * twice.
   */
  static fromCbor(cbor: string | Uint8Array): CoseSign1 {
    const message = decodeAnnotated(toBytes(cbor));
    const decoded = message.toJS();

    if (!Array.isArray(decoded)) throw Error("Invalid CBOR");
    if (decoded.length !== 4) throw Error("Invalid COSE_SIGN1");

    const protectedSerialized = decoded[0];
    if (!isBytes(protectedSerialized)) throw Error("Invalid protected");

    let protectedMap = new Map();
    if (protectedSerialized.length !== 0) {
      let header: CborNode;
      try {
        header = decodeAnnotated(protectedSerialized);
        protectedMap = header.toJS();
      } catch {
        throw Error("Invalid protected");
      }
      if (!(protectedMap instanceof Map)) throw Error("Invalid protected");
      if (hasDuplicateLabel(header, protectedMap)) throw Error("Duplicate label in protected");
    }

    const unProtectedMap = decoded[1];
    if (!(unProtectedMap instanceof Map)) throw Error("Invalid unprotected");
    if (hasDuplicateLabel(message.items![1], unProtectedMap)) {
      throw Error("Duplicate label in unprotected");
    }

    const payload = decoded[2];
    if (payload !== null && !isBytes(payload)) throw Error("Invalid payload");

    const signature = decoded[3];
    if (!isBytes(signature)) throw Error("Invalid signature");

    const coseSign1 = new CoseSign1({
      protectedMap,
      unProtectedMap,
      payload,
      signature,
    });
    coseSign1.protectedSerialized = protectedSerialized;

    return coseSign1;
  }

  /**
   * The Sig_structure, the bytes to sign.
   *
   * @param payload - the payload to sign in place of the message's own, needed when it is
   * detached
   */
  createSigStructure(externalAad: Uint8Array = EMPTY, payload?: Uint8Array): Uint8Array {
    if (!isBytes(externalAad)) throw TypeError("Invalid externalAad");
    if (payload !== undefined && !isBytes(payload)) throw TypeError("Invalid payload");

    const signedPayload = payload ?? this.payload;
    if (!signedPayload) throw Error("Payload is detached, pass the payload");

    const structure = ["Signature1", this.getProtectedSerialized(), externalAad, signedPayload];

    return encode(structure);
  }

  buildMessage(signature: Uint8Array): Uint8Array {
    if (!isBytes(signature)) throw TypeError("Invalid signature");

    this.signature = plainView(signature);

    const coseSign1 = [
      this.getProtectedSerialized(),
      this.unProtectedMap,
      this.payload,
      this.signature,
    ];

    return encode(coseSign1);
  }

  /**
   * Whether the signature verifies. Throws if the protected header's `alg` isn't EdDSA (-8).
   */
  verifySignature({
    externalAad = EMPTY,
    publicKeyBuffer,
    payload,
  }: {
    externalAad?: Uint8Array;
    /** the 32-byte Ed25519 public key, if the protected header doesn't carry it (label 4) */
    publicKeyBuffer?: Uint8Array;
    /**
     * the payload to verify in place of the message's own, needed when it is detached. For a
     * hashed message, pass the hash
     */
    payload?: Uint8Array;
  } = {}): boolean {
    if (this.protectedMap.get(1) !== -8) throw Error("Unsupported alg, expected EdDSA (-8)");

    if (!publicKeyBuffer) {
      publicKeyBuffer = this.getPublicKey();
    }

    if (!publicKeyBuffer) throw Error("Public key not found");
    if (!this.signature) throw Error("Signature not found");
    if (!isBytes(publicKeyBuffer) || publicKeyBuffer.length !== 32) {
      throw Error("Invalid public key");
    }

    return new PublicKey(publicKeyBuffer).verify(
      this.signature,
      this.createSigStructure(externalAad, payload)
    );
  }

  /**
   * Replaces the payload with its Blake2b-224 hash and sets `hashed` in the unprotected header.
   */
  hashPayload(): void {
    if (!this.payload) throw Error("Invalid payload");

    const hashed = this.unProtectedMap.get("hashed");
    if (hashed === true) throw Error("Payload already hashed");
    if (hashed !== false) throw Error("Invalid unprotected map");

    this.unProtectedMap.set("hashed", true);

    this.payload = blake2b(this.payload, { dkLen: 28 });
  }

  getAddress(): Uint8Array | undefined {
    return this.protectedMap.get("address");
  }

  getPublicKey(): Uint8Array | undefined {
    return this.protectedMap.get(4);
  }

  /**
   * The payload, null if it is detached, or its hash if it was hashed.
   */
  getPayload(): Uint8Array | null {
    return this.payload;
  }

  /**
   * Whether the payload is the message's Blake2b-224 hash, as the `hashed` unprotected header
   * says.
   */
  isHashed(): boolean {
    return this.unProtectedMap.get("hashed") === true;
  }

  getSignature(): Uint8Array | undefined {
    return this.signature;
  }

  private getProtectedSerialized(): Uint8Array {
    if (this.protectedSerialized) return this.protectedSerialized;

    if (this.protectedMap.size === 0) return EMPTY;

    return encode(this.protectedMap);
  }
}

export default CoseSign1;
