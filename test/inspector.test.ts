import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "bun:test";

import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import { inspectEvidence, type EvidenceInspectionInput } from "../src/inspector.ts";
import {
  BUNDLE_SIGNED_SCOPE_OMIT,
  bundleHash,
  type AttestationBundle,
  type BundleSignature,
} from "../src/dacs5/index.ts";
import { keypairFromSeed, signArtifact, type Keypair } from "../examples/issuer-kit.ts";

const fixturePath = join(import.meta.dir, "..", "conformance", "fixtures", "attestation-bundle-0004.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as AttestationBundle;
const buyer = keypairFromSeed("a1".repeat(32));
const seller = keypairFromSeed("c3".repeat(32));

const baseInput = (): EvidenceInspectionInput => ({
  artifactType: "dacs-5-attestation-bundle",
  source: {
    kind: "fixture",
    label: "DACS-VERIFY-0004 bundle fixture",
    url: "conformance/fixtures/attestation-bundle-0004.json",
  },
  artifact: fixture,
  expectations: {
    jobId: "DACS-VERIFY-0004",
    expectedDecision: "pass",
    expectedBundleHash: bundleHash(fixture),
  },
  publicKeys: {
    "did:demos:buyer": Buffer.from(buyer.publicKeyRaw).toString("hex"),
    "did:demos:seller": Buffer.from(seller.publicKeyRaw).toString("hex"),
  },
});

function signBundle(base: Omit<AttestationBundle, "signatures">, signers: [string, Keypair][]): AttestationBundle {
  const signingDoc = { ...base, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const signatures: BundleSignature[] = signers.map(([party, kp]) => ({
    party,
    algorithm: "ed25519",
    value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, kp.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
  }));
  return { ...base, signatures };
}

test("Evidence Inspector verifies the DACS-VERIFY-0004 bundle fixture", () => {
  const result = inspectEvidence(baseInput());
  expect(result.result.status).toBe("verified");
  expect(result.result.decision).toBe("pass");
  expect(result.generatedAt).not.toBe(new Date(0).toISOString());
  expect(result.input.artifactHash).toBe(bundleHash(fixture));
  expect(result.limitations).toContain("no live payment");
  expect(result.limitations).toContain("verifies supplied bytes and signatures, not source truth");
  expect(result.provenance.conformanceVectorIds).toEqual(["DACS-VERIFY-0004"]);
  expect(result.checks.every((entry) => entry.status === "pass")).toBe(true);
});

test("Evidence Inspector rejects a tampered bundle signature", () => {
  const input = baseInput();
  const tampered = structuredClone(fixture);
  tampered.signatures[0] = {
    ...tampered.signatures[0]!,
    value: (tampered.signatures[0]!.value[0] === "A" ? "B" : "A") + tampered.signatures[0]!.value.slice(1),
  };
  input.artifact = tampered;
  input.expectations = {
    ...input.expectations,
    expectedBundleHash: bundleHash(tampered),
    expectedDecision: "fail",
  };
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.decision).toBe("fail");
  expect(result.provenance.conformanceVectorIds).toBeUndefined();
  expect(result.checks.find((entry) => entry.id === "bundle.verify")?.status).toBe("fail");
});

test("Evidence Inspector rejects a wrong expected bundle hash", () => {
  const input = baseInput();
  input.expectations = {
    ...input.expectations,
    expectedBundleHash: "0".repeat(64),
  };
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.decision).toBe("pass");
  expect(result.checks.find((entry) => entry.id === "bundle.expected-hash")?.status).toBe("fail");
});

test("Evidence Inspector rejects a wrong expected jobId", () => {
  const input = baseInput();
  input.expectations = {
    ...input.expectations,
    jobId: "other-job",
  };
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.decision).toBe("pass");
  expect(result.checks.find((entry) => entry.id === "bundle.job-id")?.status).toBe("fail");
});

test("Evidence Inspector reports malformed numeric artifacts instead of throwing", () => {
  const input = baseInput();
  input.artifact = {
    ...fixture,
    finalisedAt: 1.5,
  };
  expect(() => inspectEvidence(input)).not.toThrow();
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("error");
});

test("Evidence Inspector reports non-JSON artifacts instead of throwing", () => {
  const input = baseInput();
  input.artifact = {
    ...fixture,
    finalisedAt: 1n,
  } as never;
  expect(() => inspectEvidence(input)).not.toThrow();
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("error");
});

test("Evidence Inspector blocks malformed top-level envelopes", () => {
  expect(() => inspectEvidence(null as never)).not.toThrow();
  const result = inspectEvidence({ artifactType: "dacs-5-attestation-bundle", artifact: fixture } as never);
  expect(result.result.status).toBe("blocked");
  expect(result.result.blockedReason).toBe("invalid-envelope");
});

test("Evidence Inspector blocks unsupported artifact types", () => {
  const input = {
    ...baseInput(),
    artifactType: "directory-artifact-ref",
  };
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("blocked");
  expect(result.result.blockedReason).toBe("unsupported-artifact-type");
});

test("Evidence Inspector returns indeterminate when public keys are unavailable", () => {
  const input = baseInput();
  delete input.publicKeys;
  delete input.expectations!.expectedDecision;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("indeterminate");
  expect(result.result.decision).toBe("indeterminate");
  expect(result.checks.find((entry) => entry.id === "bundle.verify")?.status).toBe("indeterminate");
});

test("Evidence Inspector does not derive verifier keys from non-key claims ending in hex", () => {
  const buyerHex = Buffer.from(buyer.publicKeyRaw).toString("hex");
  const sellerHex = Buffer.from(seller.publicKeyRaw).toString("hex");
  const { signatures: _signatures, ...base } = structuredClone(fixture);
  const didKeyLikeBundle = signBundle({
    ...base,
    parties: [
      { ...base.parties[0]!, primaryClaim: `did:demos:agent:${buyerHex}` },
      { ...base.parties[1]!, primaryClaim: `did:demos:agent:${sellerHex}` },
    ],
  }, [
    [`did:demos:agent:${buyerHex}`, buyer],
    [`did:demos:agent:${sellerHex}`, seller],
  ]);
  const input = baseInput();
  input.artifact = didKeyLikeBundle;
  input.expectations = {
    jobId: "DACS-VERIFY-0004",
    expectedBundleHash: bundleHash(didKeyLikeBundle),
  };
  delete input.publicKeys;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("indeterminate");
  expect(result.result.decision).toBe("indeterminate");
});

test("Evidence Inspector derives verifier keys from key base64url claims", () => {
  const buyerClaim = `key:${Buffer.from(buyer.publicKeyRaw).toString("base64url")}`;
  const sellerClaim = `key:${Buffer.from(seller.publicKeyRaw).toString("base64url")}`;
  const { signatures: _signatures, ...base } = structuredClone(fixture);
  const keyClaimBundle = signBundle({
    ...base,
    parties: [
      { ...base.parties[0]!, primaryClaim: buyerClaim },
      { ...base.parties[1]!, primaryClaim: sellerClaim },
    ],
  }, [
    [buyerClaim, buyer],
    [sellerClaim, seller],
  ]);
  const input = baseInput();
  input.artifact = keyClaimBundle;
  input.expectations = {
    jobId: "DACS-VERIFY-0004",
    expectedDecision: "pass",
    expectedBundleHash: bundleHash(keyClaimBundle),
  };
  delete input.publicKeys;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("verified");
  expect(result.result.decision).toBe("pass");
});
