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
  bundleAddress,
  bundleHash,
  type AttestationBundle,
  type BundleSignature,
} from "../src/dacs5/index.ts";
import {
  buildSessionBundleFixtures,
  VERIFY_BUYER_CLAIM,
  VERIFY_DIVERGENT_JOB_ID,
  VERIFY_ONE_SIDED_JOB_ID,
  VERIFY_SELLER_CLAIM,
} from "../examples/session-bundles.ts";
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

function directoryServiceProfile(maturity = "listed", sampleReceipt?: ReturnType<typeof makeDirectorySampleReceipt>) {
  return {
    profileKind: "directory-service-profile",
    profileVersion: "0.1",
    listing: {
      listingId: "dep-upgrade-plan",
      version: 1,
      seller: directorySignerClaim,
      artifactProfile: "fixture-listing",
      contentHash: "3".repeat(64),
    },
    maturityProfile: {
      maturity,
      noReputationClaim: true,
      noLivePaymentClaim: maturity !== "live-paid",
    },
    ...(sampleReceipt !== undefined ? { sampleReceipt } : {}),
    limitations: [
      "roster maturity hint",
      "not reputation evidence",
      "not source truth",
    ],
  };
}

const directoryServiceProfileInput = (maturity = "listed", sampleReceipt?: ReturnType<typeof makeDirectorySampleReceipt>): EvidenceInspectionInput => ({
  artifactType: "directory-service-profile",
  source: {
    kind: "fixture",
    label: "Directory service profile fixture",
    url: "examples/inspect-directory-service-profile.ts",
  },
  artifact: directoryServiceProfile(maturity, sampleReceipt),
  expectations: {
    listingId: "dep-upgrade-plan",
    listingVersion: 1,
    expectedMaturity: maturity,
  },
  publicKeys: {
    [directorySignerClaim]: Buffer.from(directorySigner.publicKeyRaw).toString("hex"),
  },
});

function directoryDealInput(input: {
  jobId: string;
  buyerBundle?: AttestationBundle;
  sellerBundle?: AttestationBundle;
  publicKeys: Record<string, string>;
}): EvidenceInspectionInput {
  return {
    artifactType: "directory-deal",
    source: {
      kind: "fixture",
      label: "Directory deal fixture",
      url: "examples/session-bundles.ts",
    },
    artifact: {
      dealKind: "directory-deal",
      dealVersion: "0.1",
      jobId: input.jobId,
      owners: {
        buyer: VERIFY_BUYER_CLAIM,
        seller: VERIFY_SELLER_CLAIM,
      },
      ...(input.buyerBundle !== undefined ? { buyerBundle: input.buyerBundle } : {}),
      ...(input.sellerBundle !== undefined ? { sellerBundle: input.sellerBundle } : {}),
    },
    expectations: {
      jobId: input.jobId,
    },
    publicKeys: input.publicKeys,
  };
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

test("Evidence Inspector verifies a unified Directory deal", () => {
  const fixtures = buildSessionBundleFixtures();
  const buyerBundle = fixtures.fetchUnified(bundleAddress(VERIFY_DIVERGENT_JOB_ID, "buyer"));
  const sellerBundle = fixtures.fetchUnified(bundleAddress(VERIFY_DIVERGENT_JOB_ID, "seller"));
  const input = directoryDealInput({
    jobId: VERIFY_DIVERGENT_JOB_ID,
    buyerBundle: buyerBundle!,
    sellerBundle: sellerBundle!,
    publicKeys: fixtures.publicKeys,
  });
  input.expectations!.expectedVerdict = "unified";
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("verified");
  expect(result.result.verdict).toBe("unified");
  expect(result.result.reputation?.buyer.bundleCount).toBe(1);
  expect(result.result.reputation?.seller.bundleCount).toBe(1);
  expect(result.result.reputation?.buyer.completionRate).toBe(1);
  expect(result.checks.find((entry) => entry.id === "directory.deal.no-fetch")?.status).toBe("pass");
});

test("Evidence Inspector reports a one-sided Directory deal without treating it as unified evidence", () => {
  const fixtures = buildSessionBundleFixtures();
  const input = directoryDealInput({
    jobId: VERIFY_ONE_SIDED_JOB_ID,
    buyerBundle: fixtures.oneSidedBuyer,
    publicKeys: fixtures.publicKeys,
  });
  input.expectations!.expectedVerdict = "one-sided";
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.verdict).toBe("one-sided");
  expect(result.result.reputation?.buyer.bundleCount).toBe(1);
  expect(result.result.reputation?.seller.bundleCount).toBe(1);
  expect(result.checks.find((entry) => entry.id === "directory.deal.expected-verdict")?.status).toBe("pass");
});

test("Evidence Inspector reports a divergent Directory deal and drops it from strict reputation", () => {
  const fixtures = buildSessionBundleFixtures();
  const input = directoryDealInput({
    jobId: VERIFY_DIVERGENT_JOB_ID,
    buyerBundle: fixtures.divergentBuyer,
    sellerBundle: fixtures.divergentSeller,
    publicKeys: fixtures.publicKeys,
  });
  input.expectations!.expectedVerdict = "divergent";
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.verdict).toBe("divergent");
  expect(result.result.reputation?.buyer.bundleCount).toBe(0);
  expect(result.result.reputation?.seller.bundleCount).toBe(0);
});

test("Evidence Inspector rejects a malformed Directory deal", () => {
  const fixtures = buildSessionBundleFixtures();
  const input = directoryDealInput({
    jobId: VERIFY_DIVERGENT_JOB_ID,
    buyerBundle: fixtures.divergentBuyer,
    sellerBundle: fixtures.divergentSeller,
    publicKeys: fixtures.publicKeys,
  });
  delete ((input.artifact as { owners?: unknown }).owners);
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.verdict).toBeUndefined();
  expect(result.checks.find((entry) => entry.id === "directory.deal.shape")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory deal when the expected verdict is wrong", () => {
  const fixtures = buildSessionBundleFixtures();
  const buyerBundle = fixtures.fetchUnified(bundleAddress(VERIFY_DIVERGENT_JOB_ID, "buyer"));
  const sellerBundle = fixtures.fetchUnified(bundleAddress(VERIFY_DIVERGENT_JOB_ID, "seller"));
  const input = directoryDealInput({
    jobId: VERIFY_DIVERGENT_JOB_ID,
    buyerBundle: buyerBundle!,
    sellerBundle: sellerBundle!,
    publicKeys: fixtures.publicKeys,
  });
  input.expectations!.expectedVerdict = "divergent";
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.result.verdict).toBe("unified");
  expect(result.checks.find((entry) => entry.id === "directory.deal.expected-verdict")?.status).toBe("fail");
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

test("Evidence Inspector verifies a listed Directory service profile", () => {
  const result = inspectEvidence(directoryServiceProfileInput());
  expect(result.result.status).toBe("verified");
  expect(result.checks.find((entry) => entry.id === "directory.profile.listed-no-evidence-required")?.status).toBe("pass");
});

test("Evidence Inspector rejects a Directory service profile with a wrong expected listing version", () => {
  const input = directoryServiceProfileInput();
  input.expectations!.listingVersion = 2;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.listing-version")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory service profile with contradictory limitation flags", () => {
  const input = directoryServiceProfileInput();
  const profile = structuredClone(input.artifact) as ReturnType<typeof directoryServiceProfile>;
  profile.maturityProfile.noReputationClaim = false;
  profile.maturityProfile.noLivePaymentClaim = false;
  input.artifact = profile;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.limitation-flags")?.status).toBe("fail");
});

test("Evidence Inspector verifies a sample-backed Directory service profile with an embedded receipt", () => {
  const result = inspectEvidence(directoryServiceProfileInput("sample-backed", makeDirectorySampleReceipt()));
  expect(result.result.status).toBe("verified");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-receipt-verifies")?.status).toBe("pass");
});

test("Evidence Inspector rejects a Directory service profile with a wrong expected receipt hash", () => {
  const input = directoryServiceProfileInput("sample-backed", makeDirectorySampleReceipt());
  input.expectations!.expectedReceiptHash = "0".repeat(64);
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-receipt-verifies")?.status).toBe("fail");
});

test("Evidence Inspector rejects a sample-backed Directory service profile without an embedded receipt", () => {
  const result = inspectEvidence(directoryServiceProfileInput("sample-backed"));
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-receipt-present")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory service profile with a tampered sample receipt", () => {
  const receipt = makeDirectorySampleReceipt();
  receipt.workProduct.descriptor.changedFiles.push("src/hidden.ts");
  const result = inspectEvidence(directoryServiceProfileInput("sample-backed", receipt));
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-receipt-verifies")?.status).toBe("fail");
});

test("Evidence Inspector rejects a Directory service profile whose sample receipt targets another listing version", () => {
  const input = directoryServiceProfileInput("sample-backed", makeDirectorySampleReceipt());
  const profile = structuredClone(input.artifact) as ReturnType<typeof directoryServiceProfile>;
  profile.listing.version = 2;
  input.artifact = profile;
  const result = inspectEvidence(input);
  expect(result.result.status).toBe("rejected");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-listing-binding")?.status).toBe("fail");
  expect(result.checks.find((entry) => entry.id === "directory.profile.sample-receipt-verifies")?.status).toBe("fail");
});

test("Evidence Inspector blocks future Directory service maturity without an adapter", () => {
  const result = inspectEvidence(directoryServiceProfileInput("strict-bundle-history"));
  expect(result.result.status).toBe("blocked");
  expect(result.result.blockedReason).toBe("missing-verifier-adapter");
  expect(result.checks.find((entry) => entry.id === "directory.profile.future-maturity-adapter")?.status).toBe("blocked");
});
