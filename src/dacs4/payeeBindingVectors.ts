import { writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { canonicalize } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import {
  evaluatePrePayGate,
  FIXTURE_KEYS,
  hashSecurityVectors,
  signAgreement,
  verifyAgreementArtifact,
  verifyWithDomain,
  type AgreementArtifact,
  type AgreementParty,
  type BindingContext,
  type CommitPhaseKind,
  type GateResult,
  type ListingFixture,
  type PaymentPhaseInput,
  type ReaderMode,
} from "./payeeBinding.ts";

type Vector = Record<string, unknown> & {
  name: string;
  rule: string;
  op: string;
  expected: "pass" | "fail" | "indeterminate" | "error";
  note: string;
};

const GENERATED_AT = 1720968000000;
const JOB_ID = "pb-job-2026-07-14";
const EVM_RAIL = "evm-erc20:8453:USDC";
const DEM_RAIL = "demos-native:DEM";
const X402_RAIL = "pay-x402:base:USDC";
const GOOD_EVM_PAYEE = "0x1111111111111111111111111111111111111111";
const OTHER_EVM_PAYEE = "0x2222222222222222222222222222222222222222";
const UNBOUND_PAYEE_CLAIM = "cci-lei:984500PBUNBOUND00001";
const DEM_PAYEE = "0x1111111111111111111111111111111111111111111111111111111111111111";
const BUNDLE_NO_STRONGER_TIER = `sha256:${sha256Hex("payee-bundle-no-stronger-tier")}`;
const BUNDLE_CONTROLLED_EVM = `sha256:${sha256Hex("payee-bundle-controlled-evm")}`;
const BUNDLE_CONTROLLED_X402 = `sha256:${sha256Hex("payee-bundle-controlled-x402")}`;
const BUNDLE_DEMOS_NATIVE = `sha256:${sha256Hex("payee-bundle-demos-native")}`;

const parties: AgreementParty[] = [
  {
    role: "buyer",
    primaryClaim: "cci-lei:984500PBBUYER0000010",
    bundleHash: `sha256:${sha256Hex("buyer-bundle")}`,
    vetRecordRef: { kind: "dacs-2-composite", id: "vet-buyer", contentHash: sha256Hex("vet-buyer") },
  },
  {
    role: "seller",
    primaryClaim: "cci-lei:984500PBSELLER000010",
    bundleHash: `sha256:${sha256Hex("seller-bundle")}`,
    vetRecordRef: { kind: "dacs-2-composite", id: "vet-seller", contentHash: sha256Hex("vet-seller") },
  },
];

const demosParties: AgreementParty[] = [
  parties[0]!,
  {
    role: "seller",
    primaryClaim: `cci-xm:demos:testnet:${DEM_PAYEE}`,
    bundleHash: `sha256:${sha256Hex("seller-demos-bundle")}`,
    vetRecordRef: { kind: "dacs-2-composite", id: "vet-seller-demos", contentHash: sha256Hex("vet-seller-demos") },
  },
];

const publicKeys: Record<string, string> = Object.fromEntries([
  [parties[0]!.primaryClaim, FIXTURE_KEYS.buyer.publicJwk.x],
  [parties[1]!.primaryClaim, FIXTURE_KEYS.seller.publicJwk.x],
  [demosParties[1]!.primaryClaim, FIXTURE_KEYS.seller.publicJwk.x],
]);

const deliverable = {
  deliverableType: "storage-program",
  hash: sha256Hex("pb-deliverable"),
};

const listing: ListingFixture = {
  listingId: "did:demos:agent:pb-fixture/payee-binding/1",
  version: 1,
  contentHash: sha256Hex("pb-listing"),
  pipeline: [
    { kind: "negotiate-fixed-price" },
    { kind: "commit-payee-bound-agreement" },
    { kind: "pay-evm-erc20", parameters: { rail: EVM_RAIL } },
    { kind: "deliver-storage-program" },
  ],
};

const legacyListing: ListingFixture = {
  ...listing,
  listingId: "did:demos:agent:pb-fixture/payee-binding-legacy/1",
  contentHash: sha256Hex("pb-listing-legacy"),
  pipeline: [
    { kind: "negotiate-fixed-price" },
    { kind: "commit-agreement" },
    { kind: "pay-evm-erc20", parameters: { rail: EVM_RAIL } },
    { kind: "deliver-storage-program" },
  ],
};

const demosListing: ListingFixture = {
  ...listing,
  listingId: "did:demos:agent:pb-fixture/payee-binding-dem/1",
  contentHash: sha256Hex("pb-listing-dem"),
  pipeline: [
    { kind: "negotiate-fixed-price" },
    { kind: "commit-payee-bound-agreement" },
    { kind: "pay-dem", parameters: { rail: DEM_RAIL } },
  ],
};

const x402Listing: ListingFixture = {
  ...listing,
  listingId: "did:demos:agent:pb-fixture/payee-binding-x402/1",
  contentHash: sha256Hex("pb-listing-x402"),
  pipeline: [
    { kind: "negotiate-fixed-price" },
    { kind: "commit-payee-bound-agreement" },
    { kind: "pay-x402", parameters: { rail: X402_RAIL } },
  ],
};

const repeatedPayListing: ListingFixture = {
  ...listing,
  listingId: "did:demos:agent:pb-fixture/payee-binding-repeated/1",
  contentHash: sha256Hex("pb-listing-repeated"),
  pipeline: [
    { kind: "negotiate-fixed-price" },
    { kind: "commit-payee-bound-agreement" },
    { kind: "pay-evm-erc20", parameters: { rail: EVM_RAIL } },
    { kind: "pay-evm-erc20", parameters: { rail: EVM_RAIL } },
    { kind: "deliver-storage-program" },
  ],
};

function baseArtifact(
  version: "legacy" | "payee-bound",
  bindings = [{ railId: EVM_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE }],
  forListing: ListingFixture = listing,
  artifactParties = parties,
  termsRail = EVM_RAIL,
  termsCurrency = "USDC",
): AgreementArtifact {
  const artifact = {
    ...(version === "legacy" ? { agreementVersion: "1" as const } : { payeeBoundAgreementVersion: "1" as const }),
    jobId: JOB_ID,
    listingRef: { listingId: forListing.listingId, version: forListing.version, contentHash: forListing.contentHash },
    parties: artifactParties,
    derivedFromPattern: "fixed-price" as const,
    terms: {
      price: { amount: "10", currency: termsCurrency },
      rail: { railId: termsRail },
      deliverable,
      deadline: GENERATED_AT + 3_600_000,
      ...(version === "payee-bound" ? { payoutBindings: bindings } : {}),
    },
    generatedAt: GENERATED_AT,
  };
  return signAgreement(artifact, version === "legacy" ? "dacs-agreement:v1:" : "dacs-payee-bound-agreement:v1:");
}

function unsigned(artifact: AgreementArtifact): Omit<AgreementArtifact, "signatures"> {
  const { signatures: _signatures, ...rest } = artifact;
  return rest;
}

function phaseInput(
  payeeAddress = GOOD_EVM_PAYEE,
  railId = EVM_RAIL,
  phaseIndex = 2,
  primaryClaim = "cci-lei:984500PBSELLER000010",
  bundleHash = BUNDLE_NO_STRONGER_TIER,
): PaymentPhaseInput {
  return {
    jobId: JOB_ID,
    railId,
    phaseIndex,
    payee: {
      bundleHash,
      primaryClaim,
      payeeAddress,
    },
  };
}

function artifactVector(
  name: string,
  rule: string,
  note: string,
  artifact: AgreementArtifact,
  forListing: ListingFixture,
  commitPhase: CommitPhaseKind,
  readerMode: ReaderMode,
): Vector {
  const result = verifyAgreementArtifact(artifact, forListing, commitPhase, readerMode);
  return {
    name,
    rule,
    op: "agreement-artifact-gate",
    expected: result.expected,
    note,
    readerMode,
    commitPhase,
    listing: forListing,
    agreement: artifact,
    artifactHash: result.artifactHash,
    signatureDomain: result.signatureDomain,
    want: result,
  };
}

function domainVector(
  name: string,
  rule: string,
  note: string,
  artifact: AgreementArtifact,
  domain: "dacs-agreement:v1:" | "dacs-payee-bound-agreement:v1:",
): Vector {
  const result = verifyWithDomain(artifact, domain);
  return {
    name,
    rule,
    op: "agreement-signature-domain",
    expected: result.expected,
    note,
    signatureDomain: domain,
    agreement: artifact,
    artifactHash: result.artifactHash,
    want: result,
  };
}

function gateVector(
  name: string,
  rule: string,
  note: string,
  artifact: AgreementArtifact,
  input: PaymentPhaseInput,
  context: BindingContext,
  forListing: ListingFixture = listing,
): Vector {
  const result = evaluatePrePayGate(artifact, forListing, input, context);
  return {
    name,
    rule,
    op: "pre-pay-destination-gate",
    expected: result.expected,
    note,
    listing: forListing,
    agreement: artifact,
    phaseInput: input,
    bindingContext: context,
    want: result,
  };
}

function repeatedPayVector(): Vector {
  const artifact = baseArtifact("payee-bound", [
    { railId: EVM_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE },
    { railId: EVM_RAIL, phaseIndex: 3, payeeAddress: OTHER_EVM_PAYEE },
  ], repeatedPayListing);
  const phaseInputs = [phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2), phaseInput(OTHER_EVM_PAYEE, EVM_RAIL, 3)];
  const results: GateResult[] = phaseInputs.map((input) => evaluatePrePayGate(artifact, repeatedPayListing, input, { strongestApplicableTier: 3, tier3AgreementAssertionPresent: true }));
  return {
    name: "pb1-repeated-pay-phases-distinct-bindings",
    rule: "PB-1",
    op: "pre-pay-destination-gate",
    expected: results.every((r) => r.expected === "pass") ? "pass" : "fail",
    note: "Two repeated pay phases share a railId but different phaseIndex values; each resolves the independently signed destination for its tuple.",
    listing: repeatedPayListing,
    agreement: artifact,
    phaseInputs,
    want: { results },
  };
}

export function buildPayeeBindingVectorSet() {
  const legacy = baseArtifact("legacy", [], legacyListing);
  const payeeBound = baseArtifact("payee-bound");
  const payeeBoundOnLegacyCommit = baseArtifact("payee-bound", [{ railId: EVM_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE }], legacyListing);
  const legacyOnPayeeBoundCommit = baseArtifact("legacy", [], listing);
  const both = signAgreement({ ...unsigned(payeeBound), agreementVersion: "1" }, "dacs-payee-bound-agreement:v1:");
  const { payeeBoundAgreementVersion: _neitherVersion, ...neitherRest } = unsigned(payeeBound);
  const neither = signAgreement(neitherRest, "dacs-payee-bound-agreement:v1:");
  const { payoutBindings: _omittedPayoutBindings, ...omittedPayoutTerms } = payeeBound.terms;
  const omittedPayoutBindings = signAgreement({
    ...unsigned(payeeBound),
    terms: omittedPayoutTerms,
  }, "dacs-payee-bound-agreement:v1:");
  const { payoutBindings: _payoutBindings, ...strippedTerms } = payeeBound.terms;
  const { payeeBoundAgreementVersion: _strippedVersion, ...strippedRest } = unsigned(payeeBound);
  const stripped: AgreementArtifact = {
    ...strippedRest,
    agreementVersion: "1",
    terms: strippedTerms,
    signatures: payeeBound.signatures,
  };
  const x402PayeeBound = baseArtifact("payee-bound", [{ railId: X402_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE }], x402Listing, parties, X402_RAIL);

  const vectors: Vector[] = [
    artifactVector("agreement-legacy-reader-accepts-legacy", "§8.5 compatibility", "A legacy reader accepts a valid AgreementDocument and applies no PB claim.", legacy, legacyListing, "commit-agreement", "legacy"),
    artifactVector("agreement-legacy-reader-refuses-payee-bound", "§8.5 compatibility", "A legacy reader structurally refuses PayeeBoundAgreementDocument before invoking any pay handler.", payeeBound, listing, "commit-payee-bound-agreement", "legacy"),
    artifactVector("agreement-current-reader-accepts-legacy-no-pb", "§8.5 compatibility", "A current reader still accepts a legacy AgreementDocument, but PB-1..PB-3 do not apply.", legacy, legacyListing, "commit-agreement", "current"),
    artifactVector("agreement-current-reader-accepts-payee-bound", "§8.5 compatibility", "A current reader accepts PayeeBoundAgreementDocument when the artifact, phase, signatures, and payout coverage are coherent.", payeeBound, listing, "commit-payee-bound-agreement", "current"),
    artifactVector("agreement-both-discriminators-reject", "§8.5 compatibility", "An artifact carrying both agreementVersion and payeeBoundAgreementVersion rejects at the discriminator gate.", both, listing, "commit-payee-bound-agreement", "current"),
    artifactVector("agreement-neither-discriminator-reject", "§8.5 compatibility", "An artifact carrying neither version discriminator rejects at the discriminator gate.", neither, listing, "commit-payee-bound-agreement", "current"),
    artifactVector("agreement-payee-bound-omitted-payoutbindings-reject", "§8.5 compatibility", "A PayeeBoundAgreementDocument omitting the required terms.payoutBindings field rejects before any pay handler.", omittedPayoutBindings, listing, "commit-payee-bound-agreement", "current"),
    artifactVector("agreement-commit-agreement-with-payee-bound-rejects", "CA-5", "commit-agreement MUST NOT coerce a PayeeBoundAgreementDocument into the legacy type.", payeeBoundOnLegacyCommit, legacyListing, "commit-agreement", "current"),
    artifactVector("agreement-commit-payee-bound-with-legacy-rejects", "CA-5", "commit-payee-bound-agreement MUST NOT coerce a legacy AgreementDocument into the payee-bound type.", legacyOnPayeeBoundCommit, listing, "commit-payee-bound-agreement", "current"),
    domainVector("agreement-legacy-signature-domain-rejects-payee-bound", "SIG-2", "A PayeeBoundAgreementDocument signature does not verify under dacs-agreement:v1:.", payeeBound, "dacs-agreement:v1:"),
    domainVector("agreement-payee-bound-signature-domain-rejects-legacy", "SIG-2", "A legacy AgreementDocument signature does not verify under dacs-payee-bound-agreement:v1:.", legacy, "dacs-payee-bound-agreement:v1:"),
    artifactVector("agreement-stripped-payee-bound-cannot-downgrade", "§8.5 compatibility", "Stripping payeeBoundAgreementVersion/payoutBindings from the original payee-bound artifact and retrying as legacy changes the signed scope and fails signature verification.", stripped, listing, "commit-agreement", "current"),

    gateVector("pb1-agreement-bound-destination-matches", "PB-1/PB-2", "The phase tuple resolves to a signed payout binding and tier 3 is applicable, so the payer may submit.", payeeBound, phaseInput(), { strongestApplicableTier: 3, tier3AgreementAssertionPresent: true }),
    gateVector("pb1-destination-mismatch-aborts-before-pay", "PB-1", "The phase payeeAddress differs from the signed payout binding; the handler aborts before payment.", payeeBound, phaseInput(OTHER_EVM_PAYEE), { tier3AgreementAssertionPresent: true }),
    gateVector("pb1-missing-payoutbinding-permanent", "PB-1", "A PayeeBoundAgreementDocument missing the phase tuple is an incomplete artifact and fails permanently before Settle.", baseArtifact("payee-bound", []), phaseInput(), { tier3AgreementAssertionPresent: true }),
    gateVector("pb1-duplicate-payoutbinding-permanent", "PB-1", "Duplicate (railId, phaseIndex) payout bindings make the payee-bound artifact invalid.", baseArtifact("payee-bound", [
      { railId: EVM_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE },
      { railId: EVM_RAIL, phaseIndex: 2, payeeAddress: OTHER_EVM_PAYEE },
    ]), phaseInput(), { tier3AgreementAssertionPresent: true }),
    gateVector("pb1-wrong-rail-payoutbinding-permanent", "PB-1", "A payout binding for the wrong railId does not cover the pinned pay phase and fails as malformed coverage.", baseArtifact("payee-bound", [{ railId: "evm-erc20:1:USDC", phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE }]), phaseInput(), { tier3AgreementAssertionPresent: true }),
    gateVector("pb1-extra-payoutbinding-permanent", "PB-1", "An extra payout binding for a non-pay tuple makes the payee-bound artifact invalid before payment.", baseArtifact("payee-bound", [
      { railId: EVM_RAIL, phaseIndex: 2, payeeAddress: GOOD_EVM_PAYEE },
      { railId: EVM_RAIL, phaseIndex: 99, payeeAddress: GOOD_EVM_PAYEE },
    ]), phaseInput(), { tier3AgreementAssertionPresent: true }),
    repeatedPayVector(),
    gateVector("pb2-no-satisfiable-tier-refuses", "PB-2/PB-3", "The phase payee claim is not one of the agreement co-signers and has no intrinsic or controlled linked binding, so no PB tier is satisfiable and the payer refuses before payment.", payeeBound, phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2, UNBOUND_PAYEE_CLAIM), {
      tier1Intrinsic: false,
      tier3AgreementAssertionPresent: false,
    }),

    gateVector("pb2-tier2-resolves-different-address", "PB-2", "Tier 2 is applicable, but the controlled linked claim resolves to a different address than the signed destination.", payeeBound, phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2, "cci-lei:984500PBSELLER000010", BUNDLE_CONTROLLED_EVM), {
      strongestApplicableTier: 2,
      controlledLinkedClaim: `cci-xm:evm:8453:${OTHER_EVM_PAYEE}`,
      verifyResult: { decision: "pass", reason: "controlled-linked-claim-resolved" },
    }),
    gateVector("pb2-tier2-controlled-claim-matches", "PB-2", "Tier 2 is applicable and the controlled linked claim resolves to the signed destination.", payeeBound, phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2, "cci-lei:984500PBSELLER000010", BUNDLE_CONTROLLED_EVM), {
      strongestApplicableTier: 2,
      controlledLinkedClaim: `cci-xm:evm:8453:${GOOD_EVM_PAYEE}`,
      verifyResult: { decision: "pass", reason: "controlled-linked-claim-resolved" },
    }),
    gateVector("pb2-tier1-pay-dem-intrinsic-matches", "PB-2", "For pay-dem, the destination is definitionally the primary claim's Demos address and binds at tier 1.", baseArtifact("payee-bound", [{ railId: DEM_RAIL, phaseIndex: 2, payeeAddress: DEM_PAYEE }], demosListing, demosParties, DEM_RAIL, "DEM"), phaseInput(DEM_PAYEE, DEM_RAIL, 2, `cci-xm:demos:testnet:${DEM_PAYEE}`, BUNDLE_DEMOS_NATIVE), {
      strongestApplicableTier: 1,
      tier1Intrinsic: true,
    }, demosListing),
    gateVector("pb2-tier2-applicable-unresolvable-pauses-no-tier3", "PB-2/PB-3", "Tier 2 is applicable but cannot resolve; the payer pauses with the VerifyResult and does not downgrade to tier 3.", payeeBound, phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2, "cci-lei:984500PBSELLER000010", BUNDLE_CONTROLLED_EVM), {
      strongestApplicableTier: 2,
      controlledLinkedClaim: `cci-xm:evm:8453:${GOOD_EVM_PAYEE}`,
      verifyResult: { decision: "indeterminate", reason: "linked-claim-anchor-unavailable" },
      tier3AgreementAssertionPresent: true,
    }),
    gateVector("pb2-tier2-resolver-error-no-downgrade", "PB-2/PB-3", "A tier-2 resolver error stays error, with no tier-3 downgrade and no payment.", payeeBound, phaseInput(GOOD_EVM_PAYEE, EVM_RAIL, 2, "cci-lei:984500PBSELLER000010", BUNDLE_CONTROLLED_EVM), {
      strongestApplicableTier: 2,
      controlledLinkedClaim: `cci-xm:evm:8453:${GOOD_EVM_PAYEE}`,
      verifyResult: { decision: "error", reason: "resolver-malformed-response" },
      tier3AgreementAssertionPresent: true,
    }),
    gateVector("pb3-sb3-absent-fallback-not-imported", "PB-3", "SB-3 fallback semantics are settlement-evidence semantics and cannot downgrade an applicable-but-unresolvable tier-2 pre-pay gate.", x402PayeeBound, phaseInput(GOOD_EVM_PAYEE, X402_RAIL, 2, "cci-lei:984500PBSELLER000010", BUNDLE_CONTROLLED_X402), {
      strongestApplicableTier: 2,
      controlledLinkedClaim: `cci-xm:evm:8453:${GOOD_EVM_PAYEE}`,
      verifyResult: { decision: "indeterminate", reason: "linked-claim-anchor-unavailable" },
      tier3AgreementAssertionPresent: true,
      sb3FallbackAvailable: true,
      sb3JobIdBinding: "absent-or-unverifiable",
    }, x402Listing),
  ];

  return {
    set: "payee-destination-binding-v0.1",
    spec: "DACS-3 §8.5/§8.6 PayeeBoundAgreementDocument compatibility; DACS-4 §9.5.1 PB-1..PB-3",
    provenance: {
      generator: "github.com/mj-deving/dacs-verify",
      command: "bun scripts/emit-payee-binding-vectors.ts",
      commit: currentCommit(),
    },
    gaps: [
      "#231 PB conformance row and vectors",
      "#236 PayeeBoundAgreementDocument redesign compatibility matrix",
    ],
    decisionModel: "artifact gate plus pre-pay destination gate. Artifact failures are permanent pre-Settle failures; payout coverage precedence is omitted field, duplicate key, non-pay/wrong tuple, then missing expected tuple; tier 3 is satisfiable only when the phase payee claim is one of the agreement co-signers for the signed payout binding; PB destination mismatch and no satisfiable PB tier are counterparty; applicable-but-unresolvable tier 2 pauses as substrate with mustNotUseTier3; resolver errors remain error; valid legacy AgreementDocument carries no PB claim.",
    publicKeys,
    hash: hashSecurityVectors(vectors),
    count: vectors.length,
    vectors,
  };
}

function currentCommit(): string {
  try {
    return execSync("git rev-parse HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}

export function emitPayeeBindingVectorSet(path?: string): void {
  const set = buildPayeeBindingVectorSet();
  const text = `${JSON.stringify(set, null, 2)}\n`;
  if (path === undefined) {
    process.stdout.write(text);
  } else {
    writeFileSync(path, text);
    process.stdout.write(`wrote ${path} (${set.count} vectors, hash ${set.hash})\n`);
  }
}

if (import.meta.main) {
  const path = process.argv[2];
  emitPayeeBindingVectorSet(path);
}
