import { canonicalize } from "./canonicalize.ts";
import { sha256Hex } from "./hash.ts";
import { buildSignedBytes, verifyEd25519 } from "./signing.ts";
import {
  bundleHash,
  verifyBundle,
  type AttestationBundle,
  type BundleDecision,
} from "./dacs5/index.ts";

export type EvidenceArtifactType =
  | "dacs-5-attestation-bundle"
  | "directory-sample-receipt"
  | "directory-service-profile";
export type EvidenceInspectionStatus = "verified" | "rejected" | "indeterminate" | "error" | "blocked";
export type EvidenceCheckStatus = "pass" | "fail" | "indeterminate" | "error" | "blocked";
export type BlockedReason =
  | "unsupported-artifact-type"
  | "network-fetch-disabled"
  | "missing-artifact"
  | "invalid-envelope"
  | "missing-verifier-adapter"
  | "source-truth-out-of-scope";

export interface EvidenceInspectionSource {
  kind: "fixture" | "local-file" | "directory-artifact-ref" | "directory-api";
  label: string;
  url?: string;
  locator?: string;
  retrievedAt?: string;
}

export interface EvidenceInspectionInput {
  artifactType: EvidenceArtifactType | string;
  source: EvidenceInspectionSource;
  artifact: unknown;
  expectations?: {
    jobId?: string;
    expectedDecision?: BundleDecision;
    expectedBundleHash?: string;
    listingId?: string;
    listingVersion?: number;
    expectedReceiptHash?: string;
    expectedMaturity?: string;
  };
  /** Claim -> Ed25519 public key as 64-hex, 0x64-hex, or base64url. */
  publicKeys?: Record<string, string>;
}

export interface EvidenceInspectionCheck {
  id: string;
  label: string;
  status: EvidenceCheckStatus;
  specRef?: string;
  detail?: string;
}

export interface EvidenceInspectionResult {
  inspectorVersion: "0.1.0";
  generatedAt: string;
  input: {
    artifactType: string;
    source: EvidenceInspectionSource;
    inputHash: string;
    artifactHash?: string;
  };
  result: {
    status: EvidenceInspectionStatus;
    decision?: BundleDecision;
    blockedReason?: BlockedReason;
    reason: string;
  };
  checks: EvidenceInspectionCheck[];
  limitations: string[];
  provenance: {
    repo: "mj-deving/dacs-verify";
    fixturePath?: string;
    conformanceVectorIds?: string[];
  };
}

const LIMITATIONS = [
  "fixture sample",
  "no live payment",
  "no live source fetch",
  "verifies supplied bytes and signatures, not source truth",
  "non-normative contributor tool",
];

const HASH_RE = /^[0-9a-f]{64}$/;
const DACS_VERIFY_0004_BUNDLE_HASH = "9e5ea58d198b459a2929d38019807c465ce9988dcb89c847cce8e80210df39ba";
const DACS_VERIFY_0004_FULL_ARTIFACT_HASH = "a9c81cb97ce5a4e4a80678086ac34cd43b688ff2d3c195178d973307d24af981";
const DIRECTORY_SAMPLE_SEPARATOR = "dacs-x-directory-sample-receipt:v0.1:";
const DIRECTORY_MATURITY = ["listed", "sample-backed", "callable", "strict-bundle-history", "live-paid"] as const;

function safeInputHash(input: unknown): string {
  try {
    return sha256Hex(canonicalize(input));
  } catch {
    try {
      const json = JSON.stringify(input);
      if (json !== undefined) return sha256Hex(json);
    } catch {
      // Fall through to a lossy but non-throwing string hash.
    }
    try {
      return sha256Hex(String(input));
    } catch {
      return sha256Hex("unhashable-inspection-input");
    }
  }
}

function rec(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function generatedAt(): string {
  return new Date().toISOString();
}

function parseSource(value: unknown): EvidenceInspectionSource | null {
  const source = rec(value);
  if (source === null || typeof source.kind !== "string" || typeof source.label !== "string") return null;
  if (!["fixture", "local-file", "directory-artifact-ref", "directory-api"].includes(source.kind)) return null;
  const parsed: EvidenceInspectionSource = {
    kind: source.kind as EvidenceInspectionSource["kind"],
    label: source.label,
  };
  if (typeof source.url === "string") parsed.url = source.url;
  if (typeof source.locator === "string") parsed.locator = source.locator;
  if (typeof source.retrievedAt === "string") parsed.retrievedAt = source.retrievedAt;
  return parsed;
}

function decodePublicKey(value: string): Uint8Array | null {
  const hex = value.replace(/^0x/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Uint8Array.from(Buffer.from(hex, "hex"));
  try {
    const bytes = Buffer.from(value, "base64url");
    return bytes.length === 32 ? Uint8Array.from(bytes) : null;
  } catch {
    return null;
  }
}

function keyFromClaim(claim: string): Uint8Array | null {
  const prefix = "key:";
  if (!claim.toLowerCase().startsWith(prefix)) return null;
  const value = claim.slice(prefix.length);
  const hex = value.replace(/^0x/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(hex)) return Uint8Array.from(Buffer.from(hex, "hex"));
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const publicKeyRaw = new Uint8Array(Buffer.from(value, "base64url"));
  return publicKeyRaw.length === 32 ? publicKeyRaw : null;
}

function stringAt(value: Record<string, unknown> | null, key: string): string | null {
  const candidate = value?.[key];
  return typeof candidate === "string" ? candidate : null;
}

function boolAt(value: Record<string, unknown> | null, key: string): boolean | null {
  const candidate = value?.[key];
  return typeof candidate === "boolean" ? candidate : null;
}

function check(
  checks: EvidenceInspectionCheck[],
  id: string,
  label: string,
  status: EvidenceCheckStatus,
  specRef?: string,
  detail?: string,
): void {
  const entry: EvidenceInspectionCheck = { id, label, status };
  if (specRef !== undefined) entry.specRef = specRef;
  if (detail !== undefined) entry.detail = detail;
  checks.push(entry);
}

function blocked(
  input: unknown,
  artifactType: string,
  source: EvidenceInspectionSource,
  blockedReason: BlockedReason,
  reason: string,
  checks: EvidenceInspectionCheck[] = [],
): EvidenceInspectionResult {
  return {
    inspectorVersion: "0.1.0",
    generatedAt: generatedAt(),
    input: {
      artifactType,
      source,
      inputHash: safeInputHash(input),
    },
    result: { status: "blocked", blockedReason, reason },
    checks,
    limitations: LIMITATIONS,
    provenance: { repo: "mj-deving/dacs-verify" },
  };
}

export function inspectEvidence(input: EvidenceInspectionInput): EvidenceInspectionResult {
  const checks: EvidenceInspectionCheck[] = [];
  const envelope = rec(input);
  const artifactType = typeof envelope?.artifactType === "string" ? envelope.artifactType : "unknown";
  const source = parseSource(envelope?.source) ?? { kind: "local-file", label: "invalid inspection envelope" };

  try {
    if (envelope === null || parseSource(envelope.source) === null || typeof envelope.artifactType !== "string") {
      check(checks, "input.envelope.parse", "Input envelope has artifactType, source, and artifact", "fail");
      return blocked(input, artifactType, source, "invalid-envelope", "input must be an inspection envelope", checks);
    }

    if (!rec(envelope.artifact)) {
      check(checks, "input.envelope.parse", "Input envelope includes an object artifact", "fail");
      return blocked(input, artifactType, source, "missing-artifact", "artifact must be an object", checks);
    }
    check(checks, "input.envelope.parse", "Input envelope includes an object artifact", "pass");

    if (
      artifactType !== "dacs-5-attestation-bundle" &&
      artifactType !== "directory-sample-receipt" &&
      artifactType !== "directory-service-profile"
    ) {
      check(checks, "input.artifact-type", "Artifact type is supported", "blocked", undefined, artifactType);
      return blocked(input, artifactType, source, "unsupported-artifact-type", `unsupported artifactType: ${artifactType}`, checks);
    }

    if (artifactType === "directory-service-profile") {
      return inspectDirectoryServiceProfile(input as EvidenceInspectionInput, checks);
    }
    if (artifactType === "directory-sample-receipt") {
      return inspectDirectorySampleReceipt(input as EvidenceInspectionInput, checks);
    }
    return inspectBundle(input as EvidenceInspectionInput, checks);
  } catch (cause) {
    check(checks, "inspector.exception", "Inspector completed without exception", "error", undefined, cause instanceof Error ? cause.message : String(cause));
    return {
      inspectorVersion: "0.1.0",
      generatedAt: generatedAt(),
      input: {
        artifactType,
        source,
        inputHash: safeInputHash(input),
      },
      result: { status: "error", reason: "inspector failed while processing the supplied artifact" },
      checks,
      limitations: LIMITATIONS,
      provenance: { repo: "mj-deving/dacs-verify" },
    };
  }
}

function directoryReceiptPayload(receipt: Record<string, unknown>): Record<string, unknown> {
  const { authorship: _authorship, receiptHash: _receiptHash, ...payload } = receipt;
  return payload;
}

function directoryReceiptHashScope(receipt: Record<string, unknown>): Record<string, unknown> {
  const { receiptHash: _receiptHash, ...scope } = receipt;
  return scope;
}

function nestedStatusToCheckStatus(status: EvidenceInspectionStatus): EvidenceCheckStatus {
  if (status === "verified") return "pass";
  if (status === "rejected") return "fail";
  return status;
}

function inspectDirectoryServiceProfile(
  input: EvidenceInspectionInput,
  checks: EvidenceInspectionCheck[],
): EvidenceInspectionResult {
  const profile = input.artifact as Record<string, unknown>;
  const inputHash = safeInputHash(input);
  const artifactHash = sha256Hex(canonicalize(profile));
  check(checks, "input.hash.jcs-sha256", "Input envelope hash is deterministic JCS sha256", "pass", "§7.1/§7.2", inputHash);
  check(checks, "directory.profile.hash", "Directory service profile hash is deterministic JCS sha256", "pass", "§7.2", artifactHash);

  const listing = rec(profile.listing);
  const maturityProfile = rec(profile.maturityProfile);
  const sampleReceipt = rec(profile.sampleReceipt);
  const limitations = Array.isArray(profile.limitations) ? profile.limitations : [];

  const listingId = stringAt(listing, "listingId");
  const seller = stringAt(listing, "seller");
  const listingVersion = typeof listing?.version === "number" && Number.isSafeInteger(listing.version) ? listing.version : null;
  const listingShapeOk = (
    profile.profileKind === "directory-service-profile" &&
    profile.profileVersion === "0.1" &&
    listingId !== null &&
    listingVersion !== null &&
    listingVersion > 0 &&
    seller !== null
  );
  check(checks, "directory.profile.listing-shape", "Directory profile carries stable listing id, version, and seller", listingShapeOk ? "pass" : "fail");

  if (input.expectations?.listingId !== undefined) {
    check(
      checks,
      "directory.profile.listing-id",
      "Directory profile listingId matches the expected listing",
      listingId === input.expectations.listingId ? "pass" : "fail",
      undefined,
      listingId ?? "missing",
    );
  }

  if (input.expectations?.listingVersion !== undefined) {
    check(
      checks,
      "directory.profile.listing-version",
      "Directory profile listing version matches the expected listing version",
      listingVersion === input.expectations.listingVersion ? "pass" : "fail",
      undefined,
      listingVersion === input.expectations.listingVersion
        ? String(listingVersion)
        : `${listingVersion ?? "missing"} !== ${input.expectations.listingVersion}`,
    );
  }

  const maturity = stringAt(maturityProfile, "maturity");
  const maturityKnown = maturity !== null && DIRECTORY_MATURITY.includes(maturity as typeof DIRECTORY_MATURITY[number]);
  check(
    checks,
    "directory.profile.maturity-known",
    "Directory profile maturity is from the supported closed set",
    maturityKnown ? "pass" : "fail",
    undefined,
    maturity ?? "missing",
  );

  if (input.expectations?.expectedMaturity !== undefined) {
    check(
      checks,
      "directory.profile.expected-maturity",
      "Directory profile maturity matches the expected maturity",
      maturity === input.expectations.expectedMaturity ? "pass" : "fail",
      undefined,
      maturity ?? "missing",
    );
  }

  const limitationProfileOk = (
    limitations.includes("roster maturity hint") &&
    limitations.includes("not reputation evidence") &&
    limitations.includes("not source truth")
  );
  check(checks, "directory.profile.limitations", "Directory profile carries explicit roster limitation labels", limitationProfileOk ? "pass" : "fail");

  const noReputationClaim = boolAt(maturityProfile, "noReputationClaim");
  const noLivePaymentClaim = boolAt(maturityProfile, "noLivePaymentClaim");
  const limitationFlagsOk = (
    noReputationClaim === true &&
    (maturity === "live-paid" ? true : noLivePaymentClaim === true)
  );
  check(
    checks,
    "directory.profile.limitation-flags",
    "Directory profile limitation flags do not claim reputation or unsupported live-payment evidence",
    limitationFlagsOk ? "pass" : "fail",
    undefined,
    `noReputationClaim=${String(noReputationClaim)} noLivePaymentClaim=${String(noLivePaymentClaim)}`,
  );

  if (maturity === "listed") {
    check(checks, "directory.profile.listed-no-evidence-required", "Listed maturity does not claim sample, payment, or reputation evidence", "pass");
  } else if (maturity === "sample-backed") {
    check(
      checks,
      "directory.profile.sample-receipt-present",
      "Sample-backed maturity includes a sample receipt",
      sampleReceipt !== null ? "pass" : "fail",
    );

    if (sampleReceipt !== null) {
      const sampleListing = rec(sampleReceipt.listingRef);
      const sampleListingId = stringAt(sampleListing, "listingId");
      const sampleSeller = stringAt(sampleListing, "seller");
      const sampleVersion = typeof sampleListing?.version === "number" && Number.isSafeInteger(sampleListing.version) ? sampleListing.version : null;
      check(
        checks,
        "directory.profile.sample-listing-binding",
        "Embedded sample receipt is bound to the profile listing, version, and seller",
        sampleListingId === listingId && sampleVersion === listingVersion && sampleSeller === seller ? "pass" : "fail",
        undefined,
        `${sampleListingId ?? "missing"} v${sampleVersion ?? "missing"} / ${sampleSeller ?? "missing"}`,
      );

      const nestedExpectations: EvidenceInspectionInput["expectations"] = {
        expectedMaturity: "sample-backed",
      };
      if (listingId !== null) nestedExpectations.listingId = listingId;
      if (listingVersion !== null) nestedExpectations.listingVersion = listingVersion;
      if (input.expectations?.expectedReceiptHash !== undefined) {
        nestedExpectations.expectedReceiptHash = input.expectations.expectedReceiptHash;
      }

      const nestedInput: EvidenceInspectionInput = {
        artifactType: "directory-sample-receipt",
        source: input.source,
        artifact: sampleReceipt,
        expectations: nestedExpectations,
      };
      if (input.publicKeys !== undefined) nestedInput.publicKeys = input.publicKeys;

      const nested = inspectDirectorySampleReceipt(nestedInput, []);
      check(
        checks,
        "directory.profile.sample-receipt-verifies",
        "Embedded sample receipt verifies with the Directory sample receipt inspector",
        nestedStatusToCheckStatus(nested.result.status),
        undefined,
        nested.result.reason,
      );
    }
  } else if (maturityKnown) {
    check(
      checks,
      "directory.profile.future-maturity-adapter",
      "Callable, strict-bundle-history, and live-paid maturity require a dedicated evidence adapter",
      "blocked",
      undefined,
      maturity ?? "missing",
    );
  }

  const failed = checks.some((entry) => entry.status === "fail" || entry.status === "error");
  const blockedCheck = checks.some((entry) => entry.status === "blocked");
  const indeterminate = checks.some((entry) => entry.status === "indeterminate");
  const status: EvidenceInspectionStatus = failed
    ? "rejected"
    : blockedCheck
      ? "blocked"
      : indeterminate
        ? "indeterminate"
        : "verified";
  const reason = failed
    ? "directory service profile failed one or more maturity checks"
    : blockedCheck
      ? "directory service profile claims a maturity level that needs a future evidence adapter"
      : indeterminate
        ? "directory service profile could not be fully verified with supplied keys"
        : "directory service profile maturity verified";

  const result: EvidenceInspectionResult["result"] = {
    status,
    reason,
  };
  if (status === "blocked") result.blockedReason = "missing-verifier-adapter";

  return {
    inspectorVersion: "0.1.0",
    generatedAt: generatedAt(),
    input: {
      artifactType: input.artifactType,
      source: input.source,
      inputHash,
      artifactHash,
    },
    result,
    checks,
    limitations: LIMITATIONS,
    provenance: { repo: "mj-deving/dacs-verify" },
  };
}

function inspectDirectorySampleReceipt(
  input: EvidenceInspectionInput,
  checks: EvidenceInspectionCheck[],
): EvidenceInspectionResult {
  const receipt = input.artifact as Record<string, unknown>;
  const inputHash = safeInputHash(input);
  const payload = directoryReceiptPayload(receipt);
  const expectedSignedPayloadHash = sha256Hex(canonicalize(payload));
  const expectedReceiptHash = sha256Hex(canonicalize(directoryReceiptHashScope(receipt)));
  check(checks, "input.hash.jcs-sha256", "Input envelope hash is deterministic JCS sha256", "pass", "§7.1/§7.2", inputHash);
  check(checks, "directory.receipt.hash", "Receipt hash recomputes over the signed receipt", "pass", "§7.2", expectedReceiptHash);

  const listingRef = rec(receipt.listingRef);
  const sampleProfile = rec(receipt.sampleProfile);
  const receiptInput = rec(receipt.input);
  const workProduct = rec(receipt.workProduct);
  const authorship = rec(receipt.authorship);
  const limitations = Array.isArray(receipt.limitations) ? receipt.limitations : [];

  const basicShapeOk = (
    stringAt(receipt, "receiptKind") !== null &&
    receipt.receiptVersion === "0.1" &&
    listingRef !== null &&
    sampleProfile !== null &&
    receiptInput !== null &&
    workProduct !== null &&
    authorship !== null &&
    stringAt(receipt, "generatedAt") !== null &&
    stringAt(receipt, "receiptHash") !== null
  );
  check(checks, "directory.receipt.shape", "Directory sample receipt has the required envelope fields", basicShapeOk ? "pass" : "fail");

  const maturity = stringAt(sampleProfile, "maturity");
  const sampleFlagsOk = (
    maturity === "sample-backed" &&
    boolAt(sampleProfile, "noLivePayment") === true &&
    boolAt(sampleProfile, "noSourceTruthClaim") === true &&
    boolAt(sampleProfile, "noLegalOrPerformanceClaim") === true
  );
  check(checks, "directory.receipt.sample-profile", "Sample profile states no live payment and explicit limitation flags", sampleFlagsOk ? "pass" : "fail");

  if (input.expectations?.listingId !== undefined) {
    const actual = stringAt(listingRef, "listingId");
    check(
      checks,
      "directory.receipt.listing-id",
      "Receipt listingId matches the expected listing",
      actual === input.expectations.listingId ? "pass" : "fail",
      undefined,
      actual === input.expectations.listingId ? actual : `${actual ?? "missing"} !== ${input.expectations.listingId}`,
    );
  }

  if (input.expectations?.listingVersion !== undefined) {
    const actual = typeof listingRef?.version === "number" && Number.isSafeInteger(listingRef.version) ? listingRef.version : null;
    check(
      checks,
      "directory.receipt.listing-version",
      "Receipt listing version matches the expected listing version",
      actual === input.expectations.listingVersion ? "pass" : "fail",
      undefined,
      actual === input.expectations.listingVersion ? String(actual) : `${actual ?? "missing"} !== ${input.expectations.listingVersion}`,
    );
  }

  if (input.expectations?.expectedMaturity !== undefined) {
    check(
      checks,
      "directory.receipt.maturity",
      "Receipt maturity matches the expected sample stage",
      maturity === input.expectations.expectedMaturity ? "pass" : "fail",
      undefined,
      maturity ?? "missing",
    );
  }

  const inputDescriptor = rec(receiptInput?.descriptor);
  const claimedInputHash = stringAt(receiptInput, "inputHash");
  const recomputedInputHash = inputDescriptor === null ? null : sha256Hex(canonicalize(inputDescriptor));
  check(
    checks,
    "directory.receipt.input-hash",
    "Input descriptor hash recomputes",
    recomputedInputHash !== null && claimedInputHash === recomputedInputHash ? "pass" : "fail",
    "§7.2",
    claimedInputHash ?? "missing",
  );

  const workDescriptor = rec(workProduct?.descriptor);
  const claimedWorkHash = stringAt(workProduct, "contentHash");
  const recomputedWorkHash = workDescriptor === null ? null : sha256Hex(canonicalize(workDescriptor));
  check(
    checks,
    "directory.receipt.work-product-hash",
    "Work-product descriptor hash recomputes",
    recomputedWorkHash !== null && claimedWorkHash === recomputedWorkHash ? "pass" : "fail",
    "§7.2",
    claimedWorkHash ?? "missing",
  );

  const claimedSignedPayloadHash = stringAt(authorship, "signedPayloadHash");
  check(
    checks,
    "directory.receipt.signed-payload-hash",
    "Signed payload hash recomputes",
    claimedSignedPayloadHash === expectedSignedPayloadHash ? "pass" : "fail",
    "§7.2",
    claimedSignedPayloadHash ?? "missing",
  );

  const claimedReceiptHash = stringAt(receipt, "receiptHash");
  const receiptHashMatches = claimedReceiptHash === expectedReceiptHash;
  check(
    checks,
    "directory.receipt.expected-hash",
    "Receipt hash matches the supplied receiptHash",
    receiptHashMatches ? "pass" : "fail",
    "§7.2",
    claimedReceiptHash ?? "missing",
  );

  if (input.expectations?.expectedReceiptHash !== undefined) {
    check(
      checks,
      "directory.receipt.caller-expected-hash",
      "Receipt hash matches the caller expected hash",
      expectedReceiptHash === input.expectations.expectedReceiptHash ? "pass" : "fail",
      "§7.2",
      input.expectations.expectedReceiptHash,
    );
  }

  const hasLimitationProfile = (
    limitations.includes("sample-backed receipt") &&
    limitations.includes("no live payment") &&
    limitations.includes("not source truth") &&
    limitations.includes("not reputation evidence")
  );
  check(checks, "directory.receipt.limitations", "Receipt carries explicit sample limitations", hasLimitationProfile ? "pass" : "fail");

  const signer = stringAt(authorship, "signer");
  const signature = stringAt(authorship, "signature");
  const seller = stringAt(listingRef, "seller");
  check(
    checks,
    "directory.receipt.signer-binding",
    "Receipt signer matches the referenced listing seller",
    signer !== null && seller !== null && signer === seller ? "pass" : "fail",
    undefined,
    signer !== null && seller !== null ? `${signer} -> ${seller}` : "missing signer or seller",
  );

  const publicKeys = input.publicKeys ?? {};
  const publicKey = signer !== null
    ? (publicKeys[signer] !== undefined ? decodePublicKey(publicKeys[signer]!) : keyFromClaim(signer))
    : null;
  let signatureStatus: EvidenceCheckStatus = signer === null || signature === null ? "fail" : "indeterminate";
  let signatureDetail = signer ?? "missing signer";
  if (publicKey !== null && signature !== null && claimedSignedPayloadHash === expectedSignedPayloadHash) {
    try {
      const ok = verifyEd25519(
        publicKey,
        buildSignedBytes(DIRECTORY_SAMPLE_SEPARATOR, expectedSignedPayloadHash),
        new Uint8Array(Buffer.from(signature, "base64url")),
      );
      signatureStatus = ok ? "pass" : "fail";
      signatureDetail = signer ?? "missing signer";
    } catch (cause) {
      signatureStatus = "error";
      signatureDetail = cause instanceof Error ? cause.message : String(cause);
    }
  }
  check(
    checks,
    "directory.receipt.signature",
    "Receipt signature verifies over the directory sample payload",
    signatureStatus,
    undefined,
    signatureDetail,
  );

  const failed = checks.some((entry) => entry.status === "fail" || entry.status === "error");
  const indeterminate = checks.some((entry) => entry.status === "indeterminate");
  const status: EvidenceInspectionStatus = failed ? "rejected" : indeterminate ? "indeterminate" : "verified";
  const reason = failed
    ? "directory sample receipt failed one or more verification checks"
    : indeterminate
      ? "directory sample receipt could not be fully verified with supplied keys"
      : "directory sample receipt verified";

  return {
    inspectorVersion: "0.1.0",
    generatedAt: generatedAt(),
    input: {
      artifactType: input.artifactType,
      source: input.source,
      inputHash,
      artifactHash: expectedReceiptHash,
    },
    result: { status, reason },
    checks,
    limitations: LIMITATIONS,
    provenance: { repo: "mj-deving/dacs-verify" },
  };
}

function inspectBundle(input: EvidenceInspectionInput, checks: EvidenceInspectionCheck[]): EvidenceInspectionResult {
  const bundle = input.artifact as AttestationBundle;
  const inputHash = safeInputHash(input);
  const artifactHash = bundleHash(bundle);
  const fullArtifactHash = safeInputHash(bundle);
  check(checks, "input.hash.jcs-sha256", "Input envelope hash is deterministic JCS sha256", "pass", "§7.1/§7.2", inputHash);
  check(checks, "bundle.hash", "Bundle hash excludes the DACS-5 signature envelope and anchoredByRole", "pass", "§10.4.1", artifactHash);

  const publicKeys = input.publicKeys ?? {};
  const decision = verifyBundle(bundle, (claim) => {
    const explicit = publicKeys[claim];
    if (explicit !== undefined) return decodePublicKey(explicit) ?? new Uint8Array([0]);
    return keyFromClaim(claim);
  });
  const verifyStatus: EvidenceCheckStatus = decision === "pass" ? "pass" : decision;
  check(checks, "bundle.verify", "Bundle verifies with the supplied or claim-derived Ed25519 keys", verifyStatus, "§10.4/§10.4.1", decision);

  if (input.expectations?.jobId !== undefined) {
    const jobIdMatches = bundle.jobId === input.expectations.jobId;
    check(
      checks,
      "bundle.job-id",
      "Bundle jobId matches the expected jobId",
      jobIdMatches ? "pass" : "fail",
      "§10.4",
      jobIdMatches ? bundle.jobId : `${bundle.jobId} !== ${input.expectations.jobId}`,
    );
  }

  if (input.expectations?.expectedBundleHash !== undefined) {
    check(
      checks,
      "bundle.expected-hash",
      "Bundle hash matches the expected hash",
      artifactHash === input.expectations.expectedBundleHash ? "pass" : "fail",
      "§10.4.1",
      input.expectations.expectedBundleHash,
    );
  } else if (!HASH_RE.test(artifactHash)) {
    check(checks, "bundle.expected-hash", "Bundle hash has sha256 hex form", "fail", "§7.2", artifactHash);
  }

  if (input.expectations?.expectedDecision !== undefined) {
    check(
      checks,
      "bundle.expected-decision",
      "Verifier decision matches the expected decision",
      decision === input.expectations.expectedDecision ? "pass" : "fail",
      "§10.4.1",
      input.expectations.expectedDecision,
    );
  }

  check(
    checks,
    "bundle.signature-scope",
    "Bundle signatures use the DACS-5 signed scope",
    decision === "pass" ? "pass" : verifyStatus,
    "§10.4.1",
  );

  const expectationFailed = checks.some((entry) =>
    (entry.id === "bundle.job-id" || entry.id.startsWith("bundle.expected")) && entry.status === "fail",
  );
  const status: EvidenceInspectionStatus = expectationFailed
    ? "rejected"
    : decision === "pass"
      ? "verified"
      : decision === "fail"
        ? "rejected"
        : decision;
  const reason = expectationFailed
    ? "bundle verified result did not match one or more caller expectations"
    : decision === "pass"
      ? "bundle verified under DACS-5 bundle rules"
      : `bundle verifier returned ${decision}`;
  const provenance: EvidenceInspectionResult["provenance"] = {
    repo: "mj-deving/dacs-verify",
  };
  if (
    bundle.jobId === "DACS-VERIFY-0004" &&
    artifactHash === DACS_VERIFY_0004_BUNDLE_HASH &&
    fullArtifactHash === DACS_VERIFY_0004_FULL_ARTIFACT_HASH
  ) {
    provenance.conformanceVectorIds = ["DACS-VERIFY-0004"];
  }

  return {
    inspectorVersion: "0.1.0",
    generatedAt: generatedAt(),
    input: {
      artifactType: input.artifactType,
      source: input.source,
      inputHash,
      artifactHash,
    },
    result: { status, decision, reason },
    checks,
    limitations: LIMITATIONS,
    provenance,
  };
}
