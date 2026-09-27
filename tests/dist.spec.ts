import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createContext, runInContext } from "node:vm";

// Runs the build outside vitest, whose module loader is more lenient than Node's or a browser's.
// Skipped until `yarn build`.
const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const esm = `${dist}index.js`;
const iife = `${dist}index.min.js`;

const MESSAGE =
  "845869a30127045820c60060ba8a101b84bcaa1169d358c6c23b3f602f2e2ea9430ecfe2a4d9e19dea67616464726573735839006807b8aa9c7f462bf43125d9c071fd01d0720e8133fa9532ffd24c19db5e8ece0982acc4883de67c2e3411cc26bd56686a162074998c02bca166686173686564f44f6d6568756c207072616a617061746958404a50d474e5d5e49ecd9f62bab0e246c1f6f700ab6d11d4c9378e891669c46edd2411aadfe35577addce00148036fe3b36de2e1ac4013404d1ef3e3850e58120d";
const MESSAGE_WITHOUT_KEY =
  "845846a201276761646472657373583900c7a814c30663312017fb7f26de3c45ee66f018a787bda06975bd3ad857e3e14dcee6ba8f48b97044ca868b4ee017d04ecc792de386beab74a166686173686564f45054686973206973206120737472696e675840ccfb786d2a48e04056bd7eee05a42cc55f01c94de0e5a55e99ef64b799610502af1611f4585f4178546b04c7f7211393328321ce23058c29f101cb30e408a109";
const COSE_KEY =
  "a40101032720062158203ec69aff937ffd1b1348ca83b423794554114be400926a805b27db92df814d79";

const checks = `[
  CoseSign1.fromCbor(${JSON.stringify(MESSAGE)}).verifySignature(),
  CoseSign1.fromCbor(${JSON.stringify(`${MESSAGE.slice(0, -2)}0e`)}).verifySignature(),
  CoseSign1.fromCbor(${JSON.stringify(MESSAGE_WITHOUT_KEY)}).verifySignature({
    publicKeyBuffer: getPublicKeyFromCoseKey(${JSON.stringify(COSE_KEY)}),
  }),
]`;

describe("dist", (): void => {
  it.skipIf(!existsSync(esm))("Loads and verifies with Node.js' ESM loader", () => {
    const script = `
      import { CoseSign1, getPublicKeyFromCoseKey } from ${JSON.stringify(pathToFileURL(esm).href)};
      console.log(JSON.stringify(${checks}));
    `;
    const output = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
    });

    expect(JSON.parse(output)).toEqual([true, false, true]);
  });

  it.skipIf(!existsSync(iife))("Browser bundle runs without Node.js globals", () => {
    const context: Record<string, any> = { TextEncoder, TextDecoder, crypto: globalThis.crypto };
    context.self = context;
    context.window = context;
    createContext(context);
    runInContext(readFileSync(iife, "utf8"), context);

    expect(
      runInContext(`const { CoseSign1, getPublicKeyFromCoseKey } = cip08; ${checks}`, context)
    ).toEqual([true, false, true]);
  });
});
