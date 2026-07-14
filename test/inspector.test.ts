import { readFileSync } from "node:fs";
import { sign as nodeSign } from "node:crypto";
import { join } from "node:path";
import { expect, test } from "bun:test";

import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { buildSignedBytes, DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
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
const directorySigner = keypairFromSeed("d4".repeat(32));
const directorySignerClaim = "did:demos:agent:directory-sample-demo";
const DIRECTORY_SAMPLE_SEPARATOR = "dacs-x-directory-sample-receipt:v0.1:";

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

function directorySamplePayload() {
  const inputDescriptor = {
    package: "@example/api-client",
    fromVersion: "1.4.2",
    toVersion: "1.4.5",
    advisoryRefs: ["GHSA-fixture-0001"],
  };
  const workProductDescriptor = {
    summary: "Fixture dependency upgrade plan",
    beforeLockHash: "1".repeat(64),
    afterLockHash: "2".repeat(64),
    changedFiles: ["package.json", "bun.lock"],
    limitation: "sample plan only",
  };
  return {
    receiptKind: "dependency-upgrade-sample-receipt",
    receiptVersion: "0.1",
    listingRef: {
      listingId: "dep-upgrade-plan",
      version: 1,
      seller: directorySignerClaim,
    },
    sampleProfile: {
      maturity: "sample-backed",
      noLivePayment: true,
      noSourceTruthClaim: true,
      noLegalOrPerformanceClaim: true,
    },
    input: {
      presetId: "dependency-upgrade-fixture",
      inputHash: sha256Hex(canonicalize(inputDescriptor)),
      descriptor: inputDescriptor,
    },
    workProduct: {
      kind: "dependency-upgrade-plan",
      contentHash: sha256Hex(canonicalize(workProductDescriptor)),
      descriptor: workProductDescriptor,
    },
    generatedAt: "2026-07-14T00:00:00Z",
    limitations: [
      "sample-backed receipt",
      "no live payment",
      "not source truth",
      "not reputation evidence",
    ],
  };
}

function makeDirectorySampleReceipt() {
  const payload = directorySamplePayload();
  const signedPayloadHash = sha256Hex(canonicalize(payload));
  const signature = nodeSign(
    null,
    buildSignedBytes(DIRECTORY_SAMPLE_SEPARATOR, signedPayloadHash),
    directorySigner.privateKey,
  ).toString("base64url");
  const receipt = {
    ...payload,
    authorship: {
      signer: directorySignerClaim,
      algorithm: "ed25519",
      signature,
      signedPayloadHash,
    },
  };
  return {
    ...receipt,
    receiptHash: sha256Hex(canonicalize(receipt)),
  };
}

const directorySampleInput = (): EvidenceInspectionInput => {
  const receipt = makeDirectorySampleReceipt();
  return {
    artifactType: "directory-sample-receipt",
    source: {
      kind: "fixture",
      label: "Directory sample receipt fixture",
      url: "examples/inspect-directory-sample.ts",
    },
    artifact: receipt,
    expectations: {
      listingId: "dep-upgrade-plan",
      expectedMaturity: "sample-backed",
      expectedReceiptHash: receipt.receiptHash,
    },
    publicKeys: {
      [directorySignerClaim]: Buffer.from(directorySigner.publicKeyRaw).toString("hex"),
    },
  };
};

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

test("Evidence Inspector verifies a Directory sample receipt", () => {
  const result = inspectEvidence(directorySampleInput());
  expect(result.result.status).toBe("verified");
  expect(result.input.artifactHash).toBe((directorySampleInput().artifact as { receiptHash: string }).receiptHash);
  expect(result.checks.every((entry) => entry.status === "pass")).toBe(true);
});

test("Evidence Inspector rejects a Directory sample receipt with tampered input", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.input.descriptor.toVersion = "9.9.9";
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.input-hash")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt with tampered work product", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.workProduct.descriptor.changedFiles.push("src/hidden.ts");
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.work-product-hash")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt with a tampered signature", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.authorship.signature = (receipt.authorship.signature[0] === "A" ? "B" : "A") + receipt.authorship.signature.slice(1);
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.signature")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt without limitation profile", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.limitations = ["sample-backed receipt"];
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.limitations")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt with false limitation flags", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.sampleProfile.noSourceTruthClaim = false;
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.sample-profile")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt with spoofed listing seller", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  receipt.listingRef.seller = "did:demos:agent:other-seller";
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.signer-binding")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory sample receipt with missing signature", () => {
  const input = directorySampleInput();
  const receipt = structuredClone(input.artifact) as ReturnType<typeof makeDirectorySampleReceipt>;
  delete (receipt.authorship as Partial<typeof receipt.authorship>).signature;
  input.artifact = receipt;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.signature")?.status).toBe("fail");
});

test("Evidence Inspector returns indeterminate for a Directory sample receipt without signer key", () => {
  const input = directorySampleInput();
  delete input.publicKeys;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("indeterminate");
  expect(result.checks.find((entry) => entry.id === "directory.receipt.signature")?.status).toBe("indeterminate");
});
