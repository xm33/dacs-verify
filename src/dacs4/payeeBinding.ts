import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { buildSignedBytes, verifyArtifactSignatureWithSeparator } from "../signing.ts";

export type ReaderMode = "legacy" | "current";
export type CommitPhaseKind = "commit-agreement" | "commit-payee-bound-agreement";
export type Verdict = "pass" | "fail" | "indeterminate" | "error";
export type ErrorClass = "permanent" | "counterparty" | "substrate";

export type AgreementParty = {
  role: "buyer" | "seller" | "orchestrator";
  primaryClaim: string;
  bundleHash: string;
  vetRecordRef: { kind: string; id: string; contentHash: string };
};

export type AgreementSignature = {
  party: string;
  algorithm: "ed25519";
  value: string;
};

export type PayoutBinding = {
  railId: string;
  phaseIndex: number;
  payeeAddress: string;
};

export type AgreementTerms = {
  price: { amount: string; currency: string };
  rail?: string;
  deliverable: { deliverableType: string; hash: string };
  deadline: number;
  payoutBindings?: PayoutBinding[];
};

export type AgreementArtifact = {
  agreementVersion?: "1";
  payeeBoundAgreementVersion?: "1";
  jobId: string;
  listingRef: { listingId: string; version: number; contentHash: string };
  parties: AgreementParty[];
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope";
  terms: AgreementTerms;
  generatedAt: number;
  signatures: AgreementSignature[];
};

export type PipelineStep = { kind: string; parameters?: { rail?: string } };
export type ListingFixture = {
  listingId: string;
  version: number;
  contentHash: string;
  pipeline: PipelineStep[];
};

export type PaymentPhaseInput = {
  jobId: string;
  railId: string;
  phaseIndex: number;
  payee: {
    bundleHash: string;
    primaryClaim: string;
    payeeAddress: string;
  };
};

export type BindingContext = {
  strongestApplicableTier?: 1 | 2 | 3;
  tier1Intrinsic?: boolean;
  controlledLinkedClaim?: string;
  verifyResult?: { decision: "pass" | "indeterminate" | "error"; reason: string };
  tier3AgreementAssertionPresent?: boolean;
  sb3FallbackAvailable?: boolean;
  sb3JobIdBinding?: "absent-or-unverifiable";
};

export type GateResult = {
  expected: Verdict;
  maySubmitPayment: boolean;
  ok: boolean;
  errorClass?: ErrorClass;
  failedAt?: string;
  bindingTier?: 1 | 2 | 3;
  boundDestination?: string;
  sessionTransition?: "paused";
  recordedVerifyResultEquals?: BindingContext["verifyResult"];
  mustNotApplySb3Fallback?: boolean;
  reason: string;
};

export type ArtifactCheckResult = {
  expected: Verdict;
  ok: boolean;
  failedAt?: string;
  errorClass?: ErrorClass;
  artifactHash?: string;
  signatureDomain?: string;
  reason: string;
};

const LEGACY_DOMAIN = "dacs-agreement:v1:";
const PAYEE_BOUND_DOMAIN = "dacs-payee-bound-agreement:v1:";
const HEX_64 = /^[0-9a-f]{64}$/;

export const FIXTURE_KEYS = {
  buyer: {
    publicJwk: { crv: "Ed25519", x: "Ngsms4AKMIpGv3Ssc54Msf_RF7kDyNRbE5A4kGl0Wvs", kty: "OKP" },
    privateJwk: { crv: "Ed25519", d: "S446oncjXPYhAyB5zZLy1C7gNyXOXKdUanXskdfThXE", x: "Ngsms4AKMIpGv3Ssc54Msf_RF7kDyNRbE5A4kGl0Wvs", kty: "OKP" },
  },
  seller: {
    publicJwk: { crv: "Ed25519", x: "BuwkmF-v_71CiQrUMIDkQHwQlKiJPWch4F_Q_DmHhNY", kty: "OKP" },
    privateJwk: { crv: "Ed25519", d: "IIrRGxzitfsGww3PXzsc4hmYh531QzwRtHv6WFJF4hg", x: "BuwkmF-v_71CiQrUMIDkQHwQlKiJPWch4F_Q_DmHhNY", kty: "OKP" },
  },
  orchestrator: {
    publicJwk: { crv: "Ed25519", x: "yra4qKH2-KfQGZVE9e1w-c7fVuKT50z9cHUTdYQWaEE", kty: "OKP" },
    privateJwk: { crv: "Ed25519", d: "fHjyIVSUI4Fx_OhkKWiixX1i9coAKrtc2Kvp3IZ4xYU", x: "yra4qKH2-KfQGZVE9e1w-c7fVuKT50z9cHUTdYQWaEE", kty: "OKP" },
  },
} as const;

export function artifactHash(artifact: AgreementArtifact): string {
  return sha256Hex(canonicalize(withoutSignature(artifact, "signatures")));
}

export function signAgreement(artifact: Omit<AgreementArtifact, "signatures">, domain: typeof LEGACY_DOMAIN | typeof PAYEE_BOUND_DOMAIN): AgreementArtifact {
  const hash = sha256Hex(canonicalize(artifact));
  const signedBytes = buildSignedBytes(domain, hash);
  const signatures = artifact.parties.map((party) => {
    const key = FIXTURE_KEYS[party.role];
    const privateKey = createPrivateKey({ key: key.privateJwk, format: "jwk" });
    return {
      party: party.primaryClaim,
      algorithm: "ed25519" as const,
      value: Buffer.from(nodeSign(null, signedBytes, privateKey)).toString("base64"),
    };
  });
  return { ...artifact, signatures };
}

function keyForSignature(artifact: AgreementArtifact, signature: AgreementSignature): string | undefined {
  const party = artifact.parties.find((candidate) => candidate.primaryClaim === signature.party);
  if (party === undefined || signature.algorithm !== "ed25519") return undefined;
  return FIXTURE_KEYS[party.role]?.publicJwk.x;
}

export function verifyAgreementArtifact(
  artifact: AgreementArtifact,
  listing: ListingFixture,
  commitPhase: CommitPhaseKind,
  readerMode: ReaderMode,
): ArtifactCheckResult {
  const hasLegacy = artifact.agreementVersion === "1";
  const hasPayeeBound = artifact.payeeBoundAgreementVersion === "1";
  if (hasLegacy === hasPayeeBound) {
    return rejectArtifact("versionDiscriminator", "permanent", hasLegacy ? "artifact carries both version discriminators" : "artifact carries neither version discriminator");
  }
  if (readerMode === "legacy" && hasPayeeBound) {
    return rejectArtifact("versionDiscriminator", "permanent", "legacy reader refuses PayeeBoundAgreementDocument before action");
  }
  if (hasLegacy && Array.isArray(artifact.terms.payoutBindings)) {
    return rejectArtifact("terms.payoutBindings", "permanent", "legacy AgreementDocument MUST NOT carry payoutBindings");
  }
  if (commitPhase === "commit-agreement" && !hasLegacy) {
    return rejectArtifact("commitPhase", "permanent", "commit-agreement requires AgreementDocument");
  }
  if (commitPhase === "commit-payee-bound-agreement" && !hasPayeeBound) {
    return rejectArtifact("commitPhase", "permanent", "commit-payee-bound-agreement requires PayeeBoundAgreementDocument");
  }

  const domain = hasLegacy ? LEGACY_DOMAIN : PAYEE_BOUND_DOMAIN;
  const hash = artifactHash(artifact);
  for (const signature of artifact.signatures) {
    const publicKey = keyForSignature(artifact, signature);
    if (publicKey === undefined) return rejectArtifact("signatures", "permanent", "signature party is not a known ed25519 agreement party");
    const publicKeyRaw = Buffer.from(publicKey, "base64url");
    const signatureRaw = Buffer.from(signature.value, "base64");
    const result = verifyArtifactSignatureWithSeparator({
      separator: domain,
      doc: artifact,
      publicKeyRaw,
      signatureRaw,
      signatureFields: ["signatures"],
    });
    if (!result.ok) {
      return {
        expected: "fail",
        ok: false,
        failedAt: "signatures",
        errorClass: "permanent",
        artifactHash: hash,
        signatureDomain: domain,
        reason: result.reason ?? "artifact signature failed",
      };
    }
  }

  if (hasPayeeBound) {
    const coverage = validatePayoutCoverage(artifact, listing);
    if (!coverage.ok) return { ...coverage, artifactHash: hash, signatureDomain: domain };
  }

  return { expected: "pass", ok: true, artifactHash: hash, signatureDomain: domain, reason: "artifact schema, commit phase, signatures, and payout coverage verified" };
}

export function verifyWithDomain(artifact: AgreementArtifact, domain: typeof LEGACY_DOMAIN | typeof PAYEE_BOUND_DOMAIN): ArtifactCheckResult {
  const hash = artifactHash(artifact);
  for (const signature of artifact.signatures) {
    const publicKey = keyForSignature(artifact, signature);
    if (publicKey === undefined) return rejectArtifact("signatures", "permanent", "signature party is not a known ed25519 agreement party");
    const result = verifyArtifactSignatureWithSeparator({
      separator: domain,
      doc: artifact,
      publicKeyRaw: Buffer.from(publicKey, "base64url"),
      signatureRaw: Buffer.from(signature.value, "base64"),
      signatureFields: ["signatures"],
    });
    if (!result.ok) {
      return { expected: "fail", ok: false, failedAt: "signatures", errorClass: "permanent", artifactHash: hash, signatureDomain: domain, reason: result.reason ?? "artifact signature failed" };
    }
  }
  return { expected: "pass", ok: true, artifactHash: hash, signatureDomain: domain, reason: "all artifact signatures verified" };
}

export function evaluatePrePayGate(artifact: AgreementArtifact, listing: ListingFixture, phaseInput: PaymentPhaseInput, bindingContext: BindingContext = {}): GateResult {
  const artifactResult = verifyAgreementArtifact(artifact, listing, "commit-payee-bound-agreement", "current");
  if (!artifactResult.ok) {
    const result: GateResult = {
      expected: artifactResult.expected,
      maySubmitPayment: false,
      ok: false,
      reason: artifactResult.reason,
    };
    if (artifactResult.errorClass !== undefined) result.errorClass = artifactResult.errorClass;
    if (artifactResult.failedAt !== undefined) result.failedAt = artifactResult.failedAt;
    return result;
  }

  const binding = artifact.terms.payoutBindings?.find((b) => b.railId === phaseInput.railId && b.phaseIndex === phaseInput.phaseIndex);
  if (binding === undefined) {
    return failGate("permanent", "terms.payoutBindings", "no payout binding for phase tuple");
  }
  if (binding.payeeAddress !== phaseInput.payee.payeeAddress) {
    return failGate("counterparty", "payoutBinding.payeeAddress", "phase payeeAddress differs from signed payout binding");
  }

  if (bindingContext.strongestApplicableTier === 1 || bindingContext.tier1Intrinsic) {
    return passGate(1, binding.payeeAddress, "tier-1 intrinsic destination binding holds");
  }
  if (bindingContext.strongestApplicableTier === 2 || bindingContext.controlledLinkedClaim !== undefined || bindingContext.verifyResult !== undefined) {
    const verifyResult = bindingContext.verifyResult;
    if (verifyResult?.decision === "error") {
      return { expected: "error", maySubmitPayment: false, ok: false, errorClass: "permanent", failedAt: "payee.primaryClaim.binding", reason: verifyResult.reason, recordedVerifyResultEquals: verifyResult };
    }
    if (verifyResult?.decision === "indeterminate") {
      return {
        expected: "indeterminate",
        maySubmitPayment: false,
        ok: false,
        errorClass: "substrate",
        sessionTransition: "paused",
        failedAt: "payee.primaryClaim.binding",
        reason: verifyResult.reason,
        recordedVerifyResultEquals: verifyResult,
        ...(bindingContext.sb3FallbackAvailable ? { mustNotApplySb3Fallback: true } : {}),
      };
    }
    const linkedAddress = bindingContext.controlledLinkedClaim?.split(":").at(-1);
    if (verifyResult?.decision === "pass" && linkedAddress === binding.payeeAddress) {
      return { ...passGate(2, binding.payeeAddress, "tier-2 controlled linked claim resolves to signed destination"), recordedVerifyResultEquals: verifyResult };
    }
    return failGate("counterparty", "payee.primaryClaim.binding", "tier-2 controlled linked claim resolves to a different destination");
  }
  if (bindingContext.tier3AgreementAssertionPresent !== false && !bindingContext.sb3FallbackAvailable) {
    return passGate(3, binding.payeeAddress, "tier-3 payee co-signature assertion is applicable");
  }
  return failGate("counterparty", "payee.primaryClaim.binding", "no satisfiable PB tier for a valid payee-bound artifact");
}

function validatePayoutCoverage(artifact: AgreementArtifact, listing: ListingFixture): ArtifactCheckResult {
  const bindings = artifact.terms.payoutBindings;
  if (!Array.isArray(bindings)) return rejectArtifact("terms.payoutBindings", "permanent", "PayeeBoundAgreementDocument missing payoutBindings");

  const expected = listing.pipeline
    .map((step, index) => ({ step, index }))
    .filter(({ step }) => step.kind.startsWith("pay-"))
    .map(({ step, index }) => ({ railId: step.parameters?.rail, phaseIndex: index }));
  if (expected.some((p) => typeof p.railId !== "string" || p.railId.length === 0)) {
    return rejectArtifact("listing.pipeline", "permanent", "pay phase missing parameters.rail");
  }

  const expectedKeys = new Set(expected.map((p) => `${p.railId}:${p.phaseIndex}`));
  const seen = new Set<string>();
  for (const binding of bindings) {
    const key = `${binding.railId}:${binding.phaseIndex}`;
    if (seen.has(key)) return rejectArtifact("terms.payoutBindings", "permanent", "duplicate payout binding key");
    seen.add(key);
    if (!expectedKeys.has(key)) return rejectArtifact("terms.payoutBindings", "permanent", "wrong railId/phaseIndex or extra payout binding");
    if (typeof binding.payeeAddress !== "string" || binding.payeeAddress.length === 0) {
      return rejectArtifact("terms.payoutBindings.payeeAddress", "permanent", "payout binding payeeAddress must be non-empty");
    }
  }
  for (const key of expectedKeys) {
    if (!seen.has(key)) return rejectArtifact("terms.payoutBindings", "permanent", "missing payout binding for pay phase");
  }
  return { expected: "pass", ok: true, reason: "payoutBindings exactly cover pay phases" };
}

function rejectArtifact(failedAt: string, errorClass: ErrorClass, reason: string): ArtifactCheckResult {
  return { expected: "fail", ok: false, failedAt, errorClass, reason };
}

function failGate(errorClass: ErrorClass, failedAt: string, reason: string): GateResult {
  return { expected: "fail", maySubmitPayment: false, ok: false, errorClass, failedAt, reason };
}

function passGate(bindingTier: 1 | 2 | 3, boundDestination: string, reason: string): GateResult {
  return { expected: "pass", maySubmitPayment: true, ok: true, bindingTier, boundDestination, reason };
}

export function hashSecurityVectors(vectors: unknown[]): string {
  return sha256Hex(canonicalize(vectors));
}

export function assertFixtureHash(hash: string): void {
  if (!HEX_64.test(hash)) throw new Error(`invalid sha256 hash: ${hash}`);
}
