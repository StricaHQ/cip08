// reads the type name from the typed array's internal slot, so unlike instanceof it also
// recognises a Uint8Array from another realm
const typedArrayName = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag
)!.get!;

export const isBytes = (value: unknown): value is Uint8Array =>
  value instanceof Uint8Array || typedArrayName.call(value) === "Uint8Array";

export const plainView = (bytes: Uint8Array): Uint8Array =>
  bytes.constructor === Uint8Array
    ? bytes
    : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const HEX = /^(?:[0-9a-fA-F]{2})*$/;

export const fromHex = (hex: string): Uint8Array => {
  if (!HEX.test(hex)) throw TypeError("Invalid hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return bytes;
};

// always a copy, so nothing decoded from it shares memory with the caller's buffer
export const toBytes = (input: string | Uint8Array): Uint8Array => {
  if (typeof input === "string") return fromHex(input);
  if (isBytes(input)) return new Uint8Array(input);
  throw TypeError("Expected a hex string or a Uint8Array");
};
