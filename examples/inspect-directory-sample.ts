import { sign as nodeSign } from "node:crypto";

import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { inspectEvidence, type EvidenceInspectionInput } from "../src/inspector.ts";
import { buildSignedBytes } from "../src/signing.ts";
import { keypairFromSeed } from "./issuer-kit.ts";

const DIRECTORY_SAMPLE_SEPARATOR = "dacs-x-directory-sample-receipt:v0.1:";
const signer = keypairFromSeed("d4".repeat(32));
const signerClaim = "did:demos:agent:directory-sample-demo";

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

const payload = {
  receiptKind: "dependency-upgrade-sample-receipt",
  receiptVersion: "0.1",
  listingRef: {
    listingId: "dep-upgrade-plan",
    version: 1,
    seller: signerClaim,
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
const signedPayloadHash = sha256Hex(canonicalize(payload));
const signature = nodeSign(
  null,
  buildSignedBytes(DIRECTORY_SAMPLE_SEPARATOR, signedPayloadHash),
  signer.privateKey,
).toString("base64url");
const receipt = {
  ...payload,
  authorship: {
    signer: signerClaim,
    algorithm: "ed25519",
    signature,
    signedPayloadHash,
  },
};
const artifact = {
  ...receipt,
  receiptHash: sha256Hex(canonicalize(receipt)),
};

const input: EvidenceInspectionInput = {
  artifactType: "directory-sample-receipt",
  source: {
    kind: "fixture",
    label: "Directory dependency-upgrade sample receipt",
    url: "examples/inspect-directory-sample.ts",
  },
  artifact,
  expectations: {
    listingId: "dep-upgrade-plan",
    expectedMaturity: "sample-backed",
    expectedReceiptHash: artifact.receiptHash,
  },
  publicKeys: {
    [signerClaim]: Buffer.from(signer.publicKeyRaw).toString("hex"),
  },
};

console.log(JSON.stringify(inspectEvidence(input), null, 2));
