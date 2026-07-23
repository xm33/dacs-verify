/**
 * Candidate-only evaluator for DACS-Standard PR #248 bundle-binding-v0.1.
 *
 * This is a conformance harness, not the package's production DACS-5 consumer.
 * Its frozen input envelope is the nine inline, Ed25519-signed candidate vectors;
 * extended-pointer dereferencing and other BundleSignature suites are deliberately
 * outside this cross-run rather than claimed as implemented product behavior.
 */
import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { verifyArtifactSignatureWithSeparator } from "../src/signing.ts";

export type BundleBindingRole = "buyer" | "seller" | "orchestrator";
export type BundleBindingDecision = "pass" | "fail" | "indeterminate";

export interface BundleBindingResolutionInput {
  readonly request: { readonly jobId: string; readonly role: BundleBindingRole };
  readonly authorizedParties: {
    readonly buyer: string;
    readonly seller: string;
    readonly orchestrator?: string;
  };
  readonly bindings: readonly unknown[];
  readonly anchored: Readonly<Record<string, unknown>>;
}

export interface BundleBindingResolutionResult {
  readonly decision: BundleBindingDecision;
  readonly code:
    | "resolved"
    | "invalid-binding"
    | "invalid-bundle"
    | "missing-binding"
    | "fetch-budget-exhausted"
    | "equal-standing-divergence";
  readonly resolvedNativeAddress?: string;
  readonly faultedParty?: BundleBindingRole | "none";
}

export type BundleBindingKeyResolver = (claim: string) => Uint8Array | null | undefined;

interface ComponentSignature {
  readonly algorithm: "ed25519";
  readonly signer: string;
  readonly value: string;
}

interface BundleBinding {
  readonly bindingVersion: "1";
  readonly jobId: string;
  readonly role: BundleBindingRole;
  readonly logicalAddress: string;
  readonly nativeAddress: string;
  readonly bundleContentHash: string;
  readonly signer: string;
  readonly signature: ComponentSignature;
  readonly source: Record<string, unknown>;
}

interface VerifiedBundle {
  readonly contentHash: string;
  readonly faultedParty?: BundleBindingRole | "none";
  readonly fullSignatureStanding: boolean;
}

interface ResolvedCopy {
  readonly binding: BundleBinding;
  readonly bundle: VerifiedBundle;
}

const BINDING_SEPARATOR = "dacs-bundle-binding:v1:";
const LEGACY_BUNDLE_SEPARATOR = "dacs-bundle:v1:";
const FAULT_BUNDLE_SEPARATOR = "dacs-fault-bundle:v1:";
const HASH_RE = /^[0-9a-f]{64}$/;
const LOGICAL_ADDRESS_RE = /^stor-[0-9a-f]{64}$/;
const NATIVE_ADDRESS_RE = /^stor-[0-9a-f]{40}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ROLES = new Set<BundleBindingRole>(["buyer", "seller", "orchestrator"]);
const FAULT_PARTIES = new Set<BundleBindingRole | "none">([
  "buyer", "seller", "orchestrator", "none",
]);
const OUTCOMES = new Set([
  "completed", "failed-perm", "failed-counterparty", "failed-substrate",
  "aborted-by-self", "aborted-by-other",
]);
const FULL_SIGNATURE_OUTCOMES = new Set([
  "completed", "failed-perm", "failed-counterparty", "failed-substrate",
]);
const PHASE_OUTCOMES = new Set(["ok", "fail"]);
const ERROR_CLASSES = new Set([
  "permanent", "transient", "counterparty", "substrate", "settlement-atomicity",
]);
const PHASE_TYPES = new Set([
  "vet-credentials",
  "negotiate-fixed-price", "negotiate-rfq", "negotiate-sealed-envelope",
  "negotiate-sealed-envelope-procurement", "commit-agreement",
  "commit-payee-bound-agreement", "pay-evm-erc20", "pay-solana-spl",
  "pay-cross-chain-htlc", "pay-cross-chain-liquidity-tank", "pay-ap2", "pay-x402",
  "pay-dem", "deliver-storage-program", "deliver-entitlement",
  "deliver-attested-payload", "rate",
]);
const MAX_FETCHES_PER_SIGNER = 8;

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function role(value: unknown): value is BundleBindingRole {
  return typeof value === "string" && ROLES.has(value as BundleBindingRole);
}

function canonicalBase64Url(value: unknown, byteLength: number): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0 || !BASE64URL_RE.test(value)) return null;
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (decoded.length !== byteLength || Buffer.from(decoded).toString("base64url") !== value) return null;
  return decoded;
}

function componentSignature(value: unknown): ComponentSignature | null {
  const signature = record(value);
  if (signature === null || signature.algorithm !== "ed25519"
    || typeof signature.signer !== "string" || signature.signer.length === 0
    || canonicalBase64Url(signature.value, 64) === null) return null;
  return { algorithm: "ed25519", signer: signature.signer, value: signature.value as string };
}

function parseBinding(value: unknown): BundleBinding | null {
  const source = record(value);
  if (source === null || source.bindingVersion !== "1"
    || typeof source.jobId !== "string" || source.jobId.length === 0
    || !role(source.role)
    || typeof source.logicalAddress !== "string" || !LOGICAL_ADDRESS_RE.test(source.logicalAddress)
    || typeof source.nativeAddress !== "string" || !NATIVE_ADDRESS_RE.test(source.nativeAddress)
    || typeof source.bundleContentHash !== "string" || !HASH_RE.test(source.bundleContentHash)
    || typeof source.signer !== "string" || source.signer.length === 0) return null;
  const signature = componentSignature(source.signature);
  if (signature === null) return null;
  return {
    bindingVersion: "1",
    jobId: source.jobId,
    role: source.role,
    logicalAddress: source.logicalAddress,
    nativeAddress: source.nativeAddress,
    bundleContentHash: source.bundleContentHash,
    signer: source.signer,
    signature,
    source,
  };
}

function bindingSignatureValid(binding: BundleBinding, resolveKey: BundleBindingKeyResolver): boolean {
  if (binding.signature.signer !== binding.signer) return false;
  const key = resolveKey(binding.signer);
  const signature = canonicalBase64Url(binding.signature.value, 64);
  if (key === null || key === undefined || key.length !== 32 || signature === null) return false;
  try {
    return verifyArtifactSignatureWithSeparator({
      separator: BINDING_SEPARATOR,
      doc: binding.source,
      publicKeyRaw: key,
      signatureRaw: signature,
      signatureFields: ["signature"],
    }).ok;
  } catch {
    return false;
  }
}

function attestationRefValid(value: unknown): boolean {
  const ref = record(value);
  return ref !== null
    && typeof ref.kind === "string" && ref.kind.length > 0
    && typeof ref.id === "string" && ref.id.length > 0
    && typeof ref.contentHash === "string" && HASH_RE.test(ref.contentHash);
}

function attestationRefsValid(value: unknown): boolean {
  return Array.isArray(value) && value.every(attestationRefValid);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function chainTxRefValid(value: unknown): boolean {
  const ref = record(value);
  if (ref === null || !nonEmptyString(ref.kind)) return false;
  switch (ref.kind) {
    case "evm":
      return nonNegativeInteger(ref.chainId) && nonEmptyString(ref.txHash);
    case "solana":
      return (ref.cluster === "mainnet" || ref.cluster === "devnet" || ref.cluster === "testnet")
        && nonEmptyString(ref.signature);
    case "demos":
      return nonEmptyString(ref.txHash)
        && (ref.blockNumber === undefined || nonNegativeInteger(ref.blockNumber));
    case "storage-program":
      return nonEmptyString(ref.address) && nonEmptyString(ref.writeTxHash);
    case "ap2":
      return nonEmptyString(ref.mandateId)
        && nonEmptyString(ref.providerRef)
        && nonEmptyString(ref.protocolVersion)
        && (ref.receiptAttestation === undefined || attestationRefValid(ref.receiptAttestation));
    case "x402":
      return nonEmptyString(ref.httpResource)
        && nonEmptyString(ref.paymentReceiptHash)
        && nonEmptyString(ref.protocolVersion)
        && (ref.settlementTxHash === undefined || nonEmptyString(ref.settlementTxHash))
        && (ref.chainId === undefined || nonNegativeInteger(ref.chainId));
    case "htlc-lock":
      return nonNegativeInteger(ref.chainId)
        && nonEmptyString(ref.contractAddress)
        && nonEmptyString(ref.lockTxHash);
    case "htlc-reveal":
      return nonNegativeInteger(ref.chainId)
        && nonEmptyString(ref.contractAddress)
        && nonEmptyString(ref.revealTxHash);
    case "htlc-claim":
      return nonNegativeInteger(ref.chainId)
        && nonEmptyString(ref.contractAddress)
        && nonEmptyString(ref.claimTxHash);
    case "htlc-refund":
      return nonNegativeInteger(ref.chainId)
        && nonEmptyString(ref.contractAddress)
        && nonEmptyString(ref.refundTxHash);
    case "liquidity-tank":
      return nonEmptyString(ref.bridgeId)
        && nonNegativeInteger(ref.sourceChainId)
        && nonNegativeInteger(ref.destChainId)
        && nonEmptyString(ref.lockTxHash)
        && (ref.releaseTxHash === undefined || nonEmptyString(ref.releaseTxHash))
        && (ref.recoveryDeadline === undefined || nonNegativeInteger(ref.recoveryDeadline));
    default:
      return false;
  }
}

function listingRefValid(value: unknown): boolean {
  const ref = record(value);
  return ref !== null
    && typeof ref.listingId === "string" && ref.listingId.length > 0
    && Number.isSafeInteger(ref.version)
    && typeof ref.contentHash === "string" && HASH_RE.test(ref.contentHash);
}

function requiredPartyMap(source: Record<string, unknown>): Map<BundleBindingRole, string> | null {
  if (!Array.isArray(source.parties) || source.parties.length < 2) return null;
  const result = new Map<BundleBindingRole, string>();
  for (const item of source.parties) {
    const party = record(item);
    if (party === null || !role(party.role)
      || typeof party.primaryClaim !== "string" || party.primaryClaim.length === 0
      || typeof party.bundleHash !== "string" || !HASH_RE.test(party.bundleHash)
      || result.has(party.role)) return null;
    result.set(party.role, party.primaryClaim);
  }
  return result.has("buyer") && result.has("seller") ? result : null;
}

function phaseSummaryValid(value: unknown): boolean {
  if (!Array.isArray(value)) return false;
  const indices = new Set<number>();
  for (const item of value) {
    const phase = record(item);
    if (phase === null || typeof phase.index !== "number" || !Number.isSafeInteger(phase.index)
      || indices.has(phase.index)
      || typeof phase.kind !== "string" || !PHASE_TYPES.has(phase.kind)
      || typeof phase.outcome !== "string" || !PHASE_OUTCOMES.has(phase.outcome)
      || (phase.errorClass !== undefined
        && (typeof phase.errorClass !== "string" || !ERROR_CLASSES.has(phase.errorClass)))
      || (phase.txRefs !== undefined
        && (!Array.isArray(phase.txRefs) || !phase.txRefs.every(chainTxRefValid)))
      || (phase.attestationRef !== undefined && !attestationRefValid(phase.attestationRef))) return false;
    indices.add(phase.index);
  }
  return true;
}

function faultBundleContextValid(source: Record<string, unknown>): boolean {
  const cancellation = source.cancellation === undefined ? null : record(source.cancellation);
  return listingRefValid(source.listingRef)
    && (source.agreementRef === undefined || attestationRefValid(source.agreementRef))
    && (source.cancellation === undefined || cancellation?.claimedPolicy === "pre-commit")
    && attestationRefsValid(source.vetRecords)
    && attestationRefsValid(source.settlementEvidence)
    && (source.amendments === undefined || attestationRefsValid(source.amendments))
    && (source.ratingRefs === undefined || attestationRefsValid(source.ratingRefs));
}

function faultedPartyValid(
  outcome: string,
  anchoredByRole: BundleBindingRole,
  faultedParty: BundleBindingRole | "none",
  partyMap: ReadonlyMap<BundleBindingRole, string>,
): boolean {
  if (outcome === "completed" || outcome === "failed-substrate") return faultedParty === "none";
  if (outcome === "failed-perm" || outcome === "aborted-by-self") return faultedParty === anchoredByRole;
  return faultedParty !== "none" && faultedParty !== anchoredByRole && partyMap.has(faultedParty);
}

function verifiedSignatureStanding(
  source: Record<string, unknown>,
  binding: BundleBinding,
  authorizedParties: BundleBindingResolutionInput["authorizedParties"],
  resolveKey: BundleBindingKeyResolver,
  separator: string,
): { readonly contentHash: string; readonly fullSignatureStanding: boolean } | null {
  if (typeof source.outcome !== "string"
    || !Array.isArray(source.signatures) || source.signatures.length === 0) return null;
  let contentHash: string;
  try {
    contentHash = sha256Hex(canonicalize(withoutSignature(source, "signatures", "anchoredByRole")));
  } catch {
    return null;
  }
  if (contentHash !== binding.bundleContentHash) return null;

  const partyClaims = Object.values(authorizedParties).filter((claim): claim is string => claim !== undefined);
  const verifiedSigners = new Set<string>();
  for (const item of source.signatures) {
    const signature = record(item);
    if (signature === null || signature.algorithm !== "ed25519"
      || typeof signature.party !== "string" || !partyClaims.includes(signature.party)) return null;
    const signatureBytes = canonicalBase64Url(signature.value, 64);
    const key = resolveKey(signature.party);
    if (signatureBytes === null || key === null || key === undefined || key.length !== 32) return null;
    let verified;
    try {
      verified = verifyArtifactSignatureWithSeparator({
        separator,
        doc: source,
        publicKeyRaw: key,
        signatureRaw: signatureBytes,
        signatureFields: ["signatures", "anchoredByRole"],
      });
    } catch {
      return null;
    }
    if (!verified.ok || verified.artifactHash !== contentHash) return null;
    verifiedSigners.add(signature.party);
  }
  if (!verifiedSigners.has(binding.signer)) return null;

  const requiredSigners = new Set<string>([authorizedParties.buyer, authorizedParties.seller]);
  const orchestrator = authorizedParties.orchestrator;
  if (orchestrator !== undefined && !requiredSigners.has(orchestrator)) requiredSigners.add(orchestrator);
  const fullSignatureStanding = [...requiredSigners].every((claim) => verifiedSigners.has(claim));
  if (FULL_SIGNATURE_OUTCOMES.has(source.outcome) && !fullSignatureStanding) return null;
  return { contentHash, fullSignatureStanding };
}

function legacyFaultedParty(
  outcome: string,
  anchoredByRole: BundleBindingRole,
  partyMap: ReadonlyMap<BundleBindingRole, string>,
): BundleBindingRole | "none" | undefined {
  if (outcome === "completed" || outcome === "failed-substrate") return "none";
  if (outcome === "failed-perm" || outcome === "aborted-by-self") return anchoredByRole;
  const counterpartRoles = [...partyMap.keys()].filter((partyRole) => partyRole !== anchoredByRole);
  return counterpartRoles.length === 1 ? counterpartRoles[0] : undefined;
}

function verifyLegacyBundle(
  value: unknown,
  binding: BundleBinding,
  authorizedParties: BundleBindingResolutionInput["authorizedParties"],
  resolveKey: BundleBindingKeyResolver,
): VerifiedBundle | null {
  const source = record(value);
  if (source === null || source.bundleVersion !== "1" || source.faultBundleVersion !== undefined
    || source.faultedParty !== undefined
    || source.jobId !== binding.jobId
    || typeof source.outcome !== "string" || !OUTCOMES.has(source.outcome)
    || !role(source.anchoredByRole) || source.anchoredByRole !== binding.role
    || !phaseSummaryValid(source.phaseSummary)
    || !faultBundleContextValid(source)
    || !Number.isSafeInteger(source.recipeRegistryVersion)
    || !Number.isSafeInteger(source.railRegistryVersion)
    || !Number.isSafeInteger(source.finalisedAt)) return null;

  const partyMap = requiredPartyMap(source);
  if (partyMap === null
    || partyMap.get("buyer") !== authorizedParties.buyer
    || partyMap.get("seller") !== authorizedParties.seller
    || partyMap.get("orchestrator") !== authorizedParties.orchestrator
    || authorizedParties[binding.role] !== binding.signer) return null;
  const standing = verifiedSignatureStanding(
    source, binding, authorizedParties, resolveKey, LEGACY_BUNDLE_SEPARATOR,
  );
  if (standing === null) return null;
  const faultedParty = legacyFaultedParty(source.outcome, binding.role, partyMap);
  return faultedParty === undefined ? standing : { ...standing, faultedParty };
}

function verifyFaultBundle(
  value: unknown,
  binding: BundleBinding,
  authorizedParties: BundleBindingResolutionInput["authorizedParties"],
  resolveKey: BundleBindingKeyResolver,
): VerifiedBundle | null {
  const source = record(value);
  if (source === null || source.faultBundleVersion !== "1" || source.bundleVersion !== undefined
    || source.jobId !== binding.jobId
    || typeof source.outcome !== "string" || !OUTCOMES.has(source.outcome)
    || !role(source.anchoredByRole) || source.anchoredByRole !== binding.role
    || typeof source.faultedParty !== "string"
    || !FAULT_PARTIES.has(source.faultedParty as BundleBindingRole | "none")
    || !phaseSummaryValid(source.phaseSummary)
    || !faultBundleContextValid(source)
    || !Number.isSafeInteger(source.recipeRegistryVersion)
    || !Number.isSafeInteger(source.railRegistryVersion)
    || !Number.isSafeInteger(source.finalisedAt)) return null;

  const partyMap = requiredPartyMap(source);
  if (partyMap === null
    || partyMap.get("buyer") !== authorizedParties.buyer
    || partyMap.get("seller") !== authorizedParties.seller
    || partyMap.get("orchestrator") !== authorizedParties.orchestrator
    || authorizedParties[binding.role] !== binding.signer) return null;
  const faultedParty = source.faultedParty as BundleBindingRole | "none";
  if (!faultedPartyValid(source.outcome, binding.role, faultedParty, partyMap)) return null;
  const standing = verifiedSignatureStanding(
    source, binding, authorizedParties, resolveKey, FAULT_BUNDLE_SEPARATOR,
  );
  return standing === null ? null : { ...standing, faultedParty };
}

function verifyBoundBundle(
  value: unknown,
  binding: BundleBinding,
  authorizedParties: BundleBindingResolutionInput["authorizedParties"],
  resolveKey: BundleBindingKeyResolver,
): VerifiedBundle | null {
  const source = record(value);
  if (source?.faultBundleVersion === "1") {
    return verifyFaultBundle(value, binding, authorizedParties, resolveKey);
  }
  if (source?.bundleVersion === "1") {
    return verifyLegacyBundle(value, binding, authorizedParties, resolveKey);
  }
  return null;
}

function result(
  decision: BundleBindingDecision,
  code: BundleBindingResolutionResult["code"],
  copy?: ResolvedCopy,
): BundleBindingResolutionResult {
  if (copy === undefined) return { decision, code };
  const resolved = { decision, code, resolvedNativeAddress: copy.binding.nativeAddress };
  return copy.bundle.faultedParty === undefined
    ? resolved
    : { ...resolved, faultedParty: copy.bundle.faultedParty };
}

export function logicalBundleAddress(jobId: string, roleValue: BundleBindingRole): string {
  return `stor-${sha256Hex(`${jobId}-bundle-${roleValue}`)}`;
}

export function resolveBundleBindingSide(
  input: BundleBindingResolutionInput,
  resolveKey: BundleBindingKeyResolver,
): BundleBindingResolutionResult {
  const authorizedSigner = input.authorizedParties[input.request.role];
  if (typeof input.authorizedParties.buyer !== "string" || input.authorizedParties.buyer.length === 0
    || typeof input.authorizedParties.seller !== "string" || input.authorizedParties.seller.length === 0
    || (input.authorizedParties.orchestrator !== undefined
      && (typeof input.authorizedParties.orchestrator !== "string"
        || input.authorizedParties.orchestrator.length === 0))
    || authorizedSigner === undefined) return result("indeterminate", "missing-binding");
  const logicalAddress = logicalBundleAddress(input.request.jobId, input.request.role);
  const discovered = input.bindings.filter((value) => record(value)?.logicalAddress === logicalAddress);
  if (discovered.length === 0) return result("indeterminate", "missing-binding");

  const bb4Valid: BundleBinding[] = [];
  for (const value of discovered) {
    const binding = parseBinding(value);
    if (binding !== null && bindingSignatureValid(binding, resolveKey)) bb4Valid.push(binding);
  }
  if (bb4Valid.length === 0) return result("fail", "invalid-binding");

  const candidates = bb4Valid.filter((binding) => binding.signer === authorizedSigner
    && binding.jobId === input.request.jobId
    && binding.role === input.request.role
    && binding.logicalAddress === logicalBundleAddress(binding.jobId, binding.role));
  if (candidates.length === 0) return result("fail", "invalid-binding");

  const candidatesBySigner = new Map<string, Map<string, BundleBinding[]>>();
  for (const binding of candidates) {
    const byAddress = candidatesBySigner.get(binding.signer) ?? new Map<string, BundleBinding[]>();
    const atAddress = byAddress.get(binding.nativeAddress) ?? [];
    if (!atAddress.some((item) => item.bundleContentHash === binding.bundleContentHash)) {
      atAddress.push(binding);
    }
    byAddress.set(binding.nativeAddress, atAddress);
    candidatesBySigner.set(binding.signer, byAddress);
  }

  const resolved: ResolvedCopy[] = [];
  const exhaustedSigners = new Set<string>();
  let fetchedInvalid = false;
  for (const [signer, byAddress] of candidatesBySigner) {
    const addresses = [...byAddress.entries()].map(([nativeAddress, bindings]) => {
      bindings.sort((left, right) => left.bundleContentHash.localeCompare(right.bundleContentHash));
      return { nativeAddress, bindings };
    }).sort((left, right) => left.bindings[0]!.bundleContentHash
      .localeCompare(right.bindings[0]!.bundleContentHash)
      || left.nativeAddress.localeCompare(right.nativeAddress));
    if (addresses.length > MAX_FETCHES_PER_SIGNER) exhaustedSigners.add(signer);
    for (const address of addresses.slice(0, MAX_FETCHES_PER_SIGNER)) {
      const anchored = input.anchored[address.nativeAddress];
      if (anchored === undefined) continue;
      let addressResolved = false;
      for (const binding of address.bindings) {
        const bundle = verifyBoundBundle(anchored, binding, input.authorizedParties, resolveKey);
        if (bundle === null) continue;
        resolved.push({ binding, bundle });
        addressResolved = true;
        break;
      }
      if (!addressResolved) fetchedInvalid = true;
    }
  }
  if (resolved.length === 0) {
    if (exhaustedSigners.size > 0) return result("indeterminate", "fetch-budget-exhausted");
    return result(fetchedInvalid ? "fail" : "indeterminate",
      fetchedInvalid ? "invalid-bundle" : "missing-binding");
  }

  const authorizedSigners = new Set(resolved.map((copy) => copy.binding.signer));
  if ([...exhaustedSigners].some((signer) => authorizedSigners.has(signer))) {
    return result("indeterminate", "fetch-budget-exhausted");
  }

  const canonicalForms = new Map<string, ResolvedCopy>();
  for (const copy of resolved) {
    const existing = canonicalForms.get(copy.bundle.contentHash);
    if (existing === undefined
      || (!existing.bundle.fullSignatureStanding && copy.bundle.fullSignatureStanding)) {
      canonicalForms.set(copy.bundle.contentHash, copy);
    }
  }
  const distinct = [...canonicalForms.values()];
  if (distinct.length === 1) return result("pass", "resolved", distinct[0]);

  const fullStanding = distinct.filter((copy) => copy.bundle.fullSignatureStanding);
  if (fullStanding.length === 1) return result("pass", "resolved", fullStanding[0]);
  return result("indeterminate", "equal-standing-divergence");
}
