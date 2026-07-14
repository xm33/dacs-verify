import { canonicalize } from "./canonicalize.ts";
import { sha256Hex } from "./hash.ts";
import {
  bundleHash,
  verifyBundle,
  type AttestationBundle,
  type BundleDecision,
} from "./dacs5/index.ts";

export type EvidenceArtifactType = "dacs-5-attestation-bundle";
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

    if (artifactType !== "dacs-5-attestation-bundle") {
      check(checks, "input.artifact-type", "Artifact type is supported", "blocked", undefined, artifactType);
      return blocked(input, artifactType, source, "unsupported-artifact-type", `unsupported artifactType: ${artifactType}`, checks);
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
