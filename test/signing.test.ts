import { test, expect } from "bun:test";
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import {
  DOMAIN_SEPARATOR_REGISTRY,
  buildSignedBytes,
  verifyArtifactSignature,
  isRegisteredSeparator,
} from "../src/signing.ts";

function rawPub(publicKey: KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

function signAs(kind: keyof typeof DOMAIN_SEPARATOR_REGISTRY, doc: Record<string, unknown>) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const hash = sha256Hex(canonicalize(withoutSignature(doc)));
  const signedBytes = buildSignedBytes(DOMAIN_SEPARATOR_REGISTRY[kind], hash);
  const signatureRaw = new Uint8Array(nodeSign(null, signedBytes, privateKey));
  return { publicKeyRaw: rawPub(publicKey), signatureRaw };
}

test("§7.7 Ed25519 round-trip via the domain-separated path", () => {
  const doc = { listingId: "abc", listingVersion: 1, signature: "placeholder" };
  const { publicKeyRaw, signatureRaw } = signAs("dacs-1-listing", doc);
  const res = verifyArtifactSignature({ kind: "dacs-1-listing", doc, publicKeyRaw, signatureRaw });
  expect(res.ok).toBe(true);
  expect(res.separator).toBe("dacs-listing:v1:");
});

test("tampering with the signed scope breaks verification", () => {
  const doc = { listingId: "abc", listingVersion: 1, signature: "placeholder" };
  const { publicKeyRaw, signatureRaw } = signAs("dacs-1-listing", doc);
  const tampered = { ...doc, listingVersion: 2 };
  const res = verifyArtifactSignature({ kind: "dacs-1-listing", doc: tampered, publicKeyRaw, signatureRaw });
  expect(res.ok).toBe(false);
});

test("SIG-2 domain separation: a listing signature does not verify as a bundle signature", () => {
  const doc = { listingId: "abc", listingVersion: 1, signature: "placeholder" };
  const { publicKeyRaw, signatureRaw } = signAs("dacs-1-listing", doc);
  // Same bytes, different artifact kind → different separator → must fail.
  const res = verifyArtifactSignature({ kind: "dacs-5-bundle", doc, publicKeyRaw, signatureRaw });
  expect(res.ok).toBe(false);
});

test("the §7.7 registry is the closed set (17 separators)", () => {
  expect(Object.keys(DOMAIN_SEPARATOR_REGISTRY)).toHaveLength(17);
  expect(isRegisteredSeparator("dacs-listing:v1:")).toBe(true);
  expect(isRegisteredSeparator("dacs-bundle:v1:")).toBe(true);
});

test("FINDING: separators used in the spec body are absent from the §7.7 closed registry", () => {
  // §8.4.1 "dacs-auto-accept-commitment:v1:" / "dacs-auto-accept-instance:v1:",
  // §6.3.2 "dacs-session-binding:v1:", §8.4.3 "dacs-sealed-bid:v1:" are all used
  // normatively but are NOT in the §7.7 registry and are NOT x-prefixed (SIG-4).
  for (const s of [
    "dacs-auto-accept-commitment:v1:",
    "dacs-auto-accept-instance:v1:",
    "dacs-session-binding:v1:",
    "dacs-sealed-bid:v1:",
  ]) {
    expect(isRegisteredSeparator(s)).toBe(false); // → finding DACS-VERIFY-0002
  }
});

test("buildSignedBytes rejects a non-sha256 artifact hash", () => {
  expect(() => buildSignedBytes("dacs-listing:v1:", "deadbeef")).toThrow();
});
