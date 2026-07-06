#!/usr/bin/env bun
/**
 * DACS v0.1 — conformance vector runner.  (proposed / non-normative · MIT)
 *
 * Executes the golden conformance vectors against this independent verifier
 * (github.com/mj-deving/dacs-verify) and prints a per-case PASS/FAIL report.
 *
 * Deterministic by construction: every key and signature is derived from a
 * fixed public seed via examples/issuer-kit.ts, and every timestamp is pinned —
 * so each run is byte-stable. No private key material is stored; seeds are
 * public test material.
 *
 *   bun conformance/run.ts          run all vectors
 *   bun conformance/run.ts --emit   (re)write MANIFEST.json + vectors/golden.json
 *
 * Golden surface: 24 primitive checks + one §10.4 bundle area (4 checks) + 18
 * dispute / disclosure checks, all byte-stable and accepted by this reference
 * verifier.
 *
 * An external implementer can read MANIFEST.json (the case index) and
 * vectors/golden.json (the pinned outputs), point their own DACS verifier at the
 * same inputs, and diff. See README.md for the spec §-map.
 */
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex, contentHash } from "../src/hash.ts";
import { canonicalDecimal, assertPositiveAmount } from "../src/decimal.ts";
import { cf4Decode, cf4Encode } from "../src/logical-address.ts";
import {
  DOMAIN_SEPARATOR_REGISTRY,
  verifyArtifactSignature,
  isRegisteredSeparator,
} from "../src/signing.ts";
import {
  matchRequirement,
  deriveIdentityTier,
  isVerifyResultRef,
  listingLogicalAddress,
  nativeAddressPerSpec,
  validateListingStructure,
  type IdentityBundle,
  type BundleClaim,
  type BundleRequirement,
  type ClaimReference,
  type IdentityTier,
} from "../src/dacs1.ts";
import {
  classifyVetOutcome,
  evaluateVetRequirement,
  mayRetry,
  validateMethodContract,
  vetAttestationAddress,
  vetCompositeAddress,
  vetControlledPresentedBy,
  vetMatch,
  VET_DECISIONS,
  type VerifyResult,
  type VerifyResultResolver,
} from "../src/dacs2/vet.ts";
import {
  deliverableSpecHash,
  listingContentHash,
  negotiableBand,
  validateAgreement,
  type AgreementDocument,
  type ListingForValidation,
} from "../src/dacs3/agreement.ts";
import {
  ANCHORING_PHASES,
  classifyAnchoringPhase,
  evaluatePinnedRecipe,
  isCanonicallyAnchored,
  validateStewardDisclosure,
  type AnchoringPhase,
} from "../src/dacs2/governance.ts";
import {
  verifyDisputeFlow,
  verifyTranscriptDisclosure,
  transcriptContentHash,
  dacsXSeparator,
  disputeRecordHash,
  DACS_X_SEPARATORS,
  type DisputeRecord,
  type DisputeOutcome,
  type ArbitrationRule,
  type RemedyDecision,
  type DisputeFlowInput,
  type ChannelTranscript,
  type DisclosureGrant,
  type DisclosureAuthority,
  type DisclosureInput,
} from "../src/dacsx/index.ts";
import {
  bundleAddress,
  bundleHash,
  consumeBundles,
  deriveReputation,
  isLegalTransition,
  ratingAddress,
  stateToOutcome,
  twoSidedLookup,
  verifyBundle,
} from "../src/dacs5/index.ts";
import {
  evidenceHash,
  paymentEvidenceAddress,
  settlementTxId,
  verifySettlementEvidence,
  verifySettlementTxUniqueness,
  type PaymentPhaseInput,
  type PhaseHandlerResult,
  type RailDefinition,
  type SettlementEvidence,
} from "../src/dacs4/index.ts";
import { keypairFromSeed, signArtifact, type Keypair } from "../examples/issuer-kit.ts";
import {
  ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
  buildAttestationBundle0004,
  buildAttestationBundle0004Seller,
  buildAttestationBundleHtlc9,
} from "../examples/attestation-bundle-0004.ts";
import {
  SETTLEMENT_ORCHESTRATOR_CLAIM,
  buildSettlementDeliverySuccess,
  buildSettlementPaymentSuccess,
} from "../examples/settlement-evidence.ts";
import {
  VERIFY_BUYER_CLAIM,
  VERIFY_SELLER_CLAIM,
  VERIFY_DIVERGENT_JOB_ID,
  VERIFY_ONE_SIDED_JOB_ID,
  VERIFY_MISANCHORED_JOB_ID,
  VERIFY_MIXEDROLE_JOB_ID,
  VERIFY_REPUTATION_COMPUTED_AT,
  VERIFY_REPUTATION_WINDOW_END,
  VERIFY_REPUTATION_WINDOW_START,
  buildSessionBundleFixtures,
  makeBundleFetch,
} from "../examples/session-bundles.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const EMIT = process.argv.includes("--emit");
const SOLANA_SIGNATURE_64B = "6pc4LiB8KHAPvbUbkozrTcPL5zXspYBdATv5raNDyVbhiKjrKokLb9o111kxTD5KkPVd7UBSCcFcnWFkrJ82Hu6";
const SOLANA_OTHER_SIGNATURE_64B = "1".repeat(64);
const SOLANA_SIGNATURE_65B = "Sh7jjzjhHgLUBZApQNSMJTBZF2wHJpdtcmoJRpGgGMEAhPi8i1LHTjp314M1kgJ5kWHLPYy4EEbWwr88YaZzhauA";
const SOLANA_SIGNATURE_63B = "2KVLLRHLnNndTeGKJBCJ6aPjPRpKmJVEdajqgKtUrxRB8YtPxTuQvWBRUC3i7Pg3SEhvVesrD9SWrjRe86EpsW";

const statusOf = (_area: string): "golden" => "golden";
const reasonOf = (area: string): string =>
  area === "bundle" || area === "dispute" || area === "disclosure"
    ? "reference-verifier-accepted (verifyBundle) + byte-stable"
    : "reference-verifier-accepted + byte-stable";

const bundle0004 = buildAttestationBundle0004();
const bundle0004Seller = buildAttestationBundle0004Seller();
const bundleHtlc9 = buildAttestationBundleHtlc9();
const settlementPayment = buildSettlementPaymentSuccess();
const settlementDelivery = buildSettlementDeliverySuccess();
const verifySession = buildSessionBundleFixtures();
const bundle0004Keys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(bundle0004.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;
const bundleHtlc9Keys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(bundleHtlc9.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;
const settlementKeys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(settlementPayment.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;

// ── tiny harness ─────────────────────────────────────────────────────────────
type Case = { id: string; area: string; spec: string; summary: string; got: unknown; want: unknown };
const cases: Case[] = [];
const golden: Record<string, unknown> = {};

function rec(id: string, area: string, spec: string, summary: string, got: unknown, want: unknown): void {
  cases.push({ id, area, spec, summary, got, want });
}
/** Returns "throws" if fn throws (optionally matching `re`), else "no-throw". */
function throwResult(fn: () => unknown, re?: RegExp): string {
  try { fn(); return "no-throw"; } catch (e) { return !re || re.test(String(e)) ? "throws" : "throws:wrong-message"; }
}
function stable(x: unknown): string {
  return JSON.stringify(x, (_k, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1)))
      : v,
  );
}
const eq = (a: unknown, b: unknown): boolean => stable(a) === stable(b);

// ── §7.1 — JCS canonicalization ──────────────────────────────────────────────
rec("canon-key-order", "canonicalize", "§7.1", "object members ordered by UTF-16 code unit of key",
  canonicalize({ b: 1, a: 2, A: 3 }), '{"A":3,"a":2,"b":1}');
rec("canon-nested", "canonicalize", "§7.1", "nested objects sorted; array order preserved",
  canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 } }), '{"a":{"x":2,"y":1},"z":[3,1,2]}');
rec("canon-escaping", "canonicalize", "§7.1", "only JCS-required escapes are applied",
  canonicalize('a"b\\c\n\t'), '"a\\"b\\\\c\\n\\t"');
rec("canon-no-escape-slash", "canonicalize", "§7.1", "forward slash and non-ASCII are not escaped",
  canonicalize("a/bé"), '"a/bé"');
rec("canon-int", "canonicalize", "§7.1", "safe integers serialise as plain decimals",
  canonicalize(Number.MAX_SAFE_INTEGER), "9007199254740991");
rec("canon-noninteger-throws", "canonicalize", "§7.1", "non-integer numbers are rejected",
  throwResult(() => canonicalize(1.5), /§7\.1/), "throws");
rec("canon-without-signature", "canonicalize", "§7.2", "the signed scope excludes the signature field",
  canonicalize(withoutSignature({ a: 1, signature: "x" })), '{"a":1}');

// ── §14.4 / §9.3 — CD-1 canonical decimals ──────────────────────────────────
rec("cd1-trailing-zeros", "decimal", "§14.4", "1.50 / 01.5 / 1.500 all canonicalise to 1.5",
  [canonicalDecimal("1.50"), canonicalDecimal("01.5"), canonicalDecimal("1.500")], ["1.5", "1.5", "1.5"]);
rec("cd1-normal-forms", "decimal", "§14.4", "0.0 → 0 ; .5 → 0.5 ; 0.50 → 0.5",
  [canonicalDecimal("0.0"), canonicalDecimal(".5"), canonicalDecimal("0.50")], ["0", "0.5", "0.5"]);
rec("cd1-reject-exponent", "decimal", "§14.4", "exponent / sign-plus / non-numeric are rejected",
  [throwResult(() => canonicalDecimal("1e3")), throwResult(() => canonicalDecimal("+1")), throwResult(() => canonicalDecimal("abc"))],
  ["throws", "throws", "throws"]);
rec("cd1-economic-equality", "decimal", "§14.4", "economically-equal amounts share a content hash; raw strings do not",
  {
    canonicalEqual: contentHash({ amount: canonicalDecimal("1.50"), currency: "USDC" }) === contentHash({ amount: canonicalDecimal("1.500"), currency: "USDC" }),
    rawDiffers: contentHash({ amount: "1.50", currency: "USDC" }) !== contentHash({ amount: "1.500", currency: "USDC" }),
  },
  { canonicalEqual: true, rawDiffers: true });
rec("cd1-positivity", "decimal", "§9.3", "amount MUST be > 0",
  throwResult(() => assertPositiveAmount("0"), /> 0/), "throws");

// ── §7.7 — domain-separated Ed25519 signing ─────────────────────────────────
{
  const SEED = "11".repeat(32);
  const { publicKeyRaw, privateKey } = keypairFromSeed(SEED);
  const doc = { listingId: "conf-listing", listingVersion: 1 };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-1-listing"];
  const signature = signArtifact(separator, doc as unknown as Record<string, unknown>, privateKey);
  const signatureRaw = new Uint8Array(Buffer.from(signature, "base64url"));

  const roundtrip = verifyArtifactSignature({ kind: "dacs-1-listing", doc, publicKeyRaw, signatureRaw });
  rec("sig-roundtrip", "signing", "§7.7", "a dacs-1-listing signature verifies under its own separator",
    { ok: roundtrip.ok, separator: roundtrip.separator }, { ok: true, separator });

  const tampered = verifyArtifactSignature({ kind: "dacs-1-listing", doc: { ...doc, listingVersion: 2 }, publicKeyRaw, signatureRaw });
  rec("sig-tamper", "signing", "§7.7", "mutating the signed scope breaks verification",
    tampered.ok, false);

  const crossDomain = verifyArtifactSignature({ kind: "dacs-5-bundle", doc, publicKeyRaw, signatureRaw });
  rec("sig-sig2-cross-domain", "signing", "§7.7", "SIG-2: a listing signature does not verify as a bundle signature",
    crossDomain.ok, false);

  rec("sig-registry-closed-16", "signing", "§7.7", "the domain-separator registry is the closed set of 16",
    Object.keys(DOMAIN_SEPARATOR_REGISTRY).length, 16);

  rec("sig-sig4-dacsx-disjoint", "signing", "§7.7", "SIG-4: DACS-X separators are dacs-x-* and disjoint from the §7.7 registry",
    Object.values(DACS_X_SEPARATORS).every((s) => s.startsWith("dacs-x-") && !isRegisteredSeparator(s)), true);

  golden["signing"] = { seed: SEED, kind: "dacs-1-listing", separator, doc, signature, publicKeyHex: Buffer.from(publicKeyRaw).toString("hex") };
}

// ── §6.3 — DACS-1 identity-bundle validation ────────────────────────────────
{
  const NOW = 1_900_000_000_000;
  const verifiedByFor = (ref: string, locator = `stor-verify-${ref.replaceAll(":", "-")}`): NonNullable<BundleClaim["verifiedBy"]> => ({
    anchor: { kind: "storage-program", locator },
    contentHash: sha256Hex(`verify-result:${ref}:${locator}:pass`),
    recipeVersion: 1,
  });
  const resolvedPass = (claim: BundleClaim): boolean =>
    isVerifyResultRef(claim.verifiedBy)
    && claim.verifiedBy.contentHash === sha256Hex(`verify-result:${claim.ref}:${claim.verifiedBy.anchor.locator}:pass`);
  const mkBundle = (claims: { ref: string; verified?: boolean }[], presentedBy?: string): IdentityBundle => ({
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => ({
      ref: c.ref,
      issuedAt: NOW - 1_000,
      ...(c.verified ? { verifiedBy: verifiedByFor(c.ref) } : {}),
    })),
    presentation: { kind: "siwd" },
  });

  const cciLeiBundle = mkBundle([{ ref: "cci-lei:984500ABCDEF12345678", verified: true }]);
  const reqLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const reqCciLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "cci-lei", verificationRequired: true }] };
  rec("dacs1-cci-lei-defect", "dacs1", "§6.3.3", "OBSERVATION DACS-VERIFY-0001 (adjacent issue #42): a cci-lei: claim does NOT satisfy a bare lei requirement",
    matchRequirement(cciLeiBundle, reqLei, NOW).ok, false);
  rec("dacs1-cci-lei-named-matches", "dacs1", "§6.3.1", "0001 is naming-only: cci-lei: satisfies a cci-lei requirement",
    matchRequirement(cciLeiBundle, reqCciLei, NOW).ok, true);

  const launderBundle = mkBundle(
    [{ ref: "lei:984500ABCDEF12345678", verified: false }, { ref: "lei:529900T8BM49AABBCC11", verified: true }],
    "lei:984500ABCDEF12345678",
  );
  const reqPrimary: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }], primaryClaimSelector: "lei" };
  rec("dacs1-tier-laundering-guard", "dacs1", "§6.3.3", "step 3b: an unverified presentedBy claim is rejected even if another verified claim satisfies the requirement",
    matchRequirement(launderBundle, reqPrimary, NOW).ok, false);

  const freshVerifiedBy = { anchor: { kind: "storage-program", locator: "stor-fresh" }, contentHash: "h", recipeVersion: 1 };
  const freshnessReq: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const freshnessMaxAgeReq: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }] };
  rec("dacs1-freshness-fail-closed", "dacs1", "§6.3.2/§6.3.3", "freshness Option A: absent timestamps and expired expiresAt fail before maxAge; expiresAt-only can pass unless maxAge needs issuedAt",
    {
      absentBoth: matchRequirement({ bundleVersion: "1", presentedBy: "lei:529900T8BM49AURSDO55", presentedAt: NOW, claims: [{ ref: "lei:529900T8BM49AURSDO55", verifiedBy: freshVerifiedBy }], presentation: { kind: "siwd" } }, freshnessReq, NOW).ok,
      expired: matchRequirement({ bundleVersion: "1", presentedBy: "lei:529900T8BM49AURSDO55", presentedAt: NOW, claims: [{ ref: "lei:529900T8BM49AURSDO55", issuedAt: NOW - 1_000, expiresAt: NOW - 1, verifiedBy: freshVerifiedBy }], presentation: { kind: "siwd" } }, freshnessReq, NOW).ok,
      expiresOnly: matchRequirement({ bundleVersion: "1", presentedBy: "lei:529900T8BM49AURSDO55", presentedAt: NOW, claims: [{ ref: "lei:529900T8BM49AURSDO55", expiresAt: NOW + 1_000, verifiedBy: freshVerifiedBy }], presentation: { kind: "siwd" } }, freshnessReq, NOW).ok,
      expiresOnlyMaxAge: matchRequirement({ bundleVersion: "1", presentedBy: "lei:529900T8BM49AURSDO55", presentedAt: NOW, claims: [{ ref: "lei:529900T8BM49AURSDO55", expiresAt: NOW + 1_000, verifiedBy: freshVerifiedBy }], presentation: { kind: "siwd" } }, freshnessMaxAgeReq, NOW).ok,
      stalePresentedByPrimary: matchRequirement({ bundleVersion: "1", presentedBy: "lei:STALE", presentedAt: NOW, claims: [{ ref: "lei:STALE", issuedAt: NOW - 10_000, expiresAt: NOW - 1, verifiedBy: freshVerifiedBy }, { ref: "lei:FRESH", issuedAt: NOW - 1_000, expiresAt: NOW + 60_000, verifiedBy: freshVerifiedBy }], presentation: { kind: "siwd" } }, { ...freshnessMaxAgeReq, primaryClaimSelector: "lei" }, NOW).ok,
    },
    { absentBoth: false, expired: false, expiresOnly: true, expiresOnlyMaxAge: false, stalePresentedByPrimary: false });

  const siwdBundle = mkBundle([{ ref: "key:siwd-resource" }]);
  const { presentation: _siwdPresentation, ...siwdSignedScope } = siwdBundle;
  const siwdBundleHash = sha256Hex(canonicalize(siwdSignedScope));
  const siwdSignedBytes = `dacs-bundle-presentation:v1:${siwdBundleHash}`;
  const siwdResource = `dacs:${Buffer.from(siwdSignedBytes, "utf8").toString("hex")}`;
  rec("dacs1-siwd-resource-binding", "dacs1", "§6.3.2", "SIWD Resource binds to lowercase hex of the full domain-separated signed_bytes",
    {
      bundleHash: siwdBundleHash,
      signedBytes: siwdSignedBytes,
      resource: siwdResource,
      decoded: Buffer.from(siwdResource.slice("dacs:".length), "hex").toString("utf8"),
    },
    {
      bundleHash: siwdBundleHash,
      signedBytes: siwdSignedBytes,
      resource: siwdResource,
      decoded: siwdSignedBytes,
    });

  type IdentityTierCase = {
    kind: "IdentityTierCase";
    identityBundle: IdentityBundle;
    expectedIdentityTier: IdentityTier;
    note?: string;
    specRefs?: string[];
  };
  const identityTierFixture = (name: string): IdentityTierCase =>
    JSON.parse(readFileSync(join(HERE, "fixtures", "identity", name), "utf8")) as IdentityTierCase;
  const identityTierCases: { id: string; description: string; fixture?: string; bundle: IdentityBundle; expected: IdentityTier }[] = [
    {
      id: "identity-tier-institutional",
      description: "IT-1: verified-and-fresh authority-issued claim derives institutional",
      fixture: "conformance/fixtures/identity/identity-tier-institutional.json",
      bundle: identityTierFixture("identity-tier-institutional.json").identityBundle,
      expected: "institutional",
    },
    {
      id: "identity-tier-verified",
      description: "IT-1: verified-and-fresh non-authority claim derives verified",
      fixture: "conformance/fixtures/identity/identity-tier-verified.json",
      bundle: identityTierFixture("identity-tier-verified.json").identityBundle,
      expected: "verified",
    },
    {
      id: "identity-tier-raw-key",
      description: "IT-1: raw key with no verifiedBy derives self-declared",
      bundle: mkBundle([{ ref: "key:1234abcd" }]),
      expected: "self-declared",
    },
    {
      id: "identity-tier-self-asserted-ignored",
      description: "IT-2: self-asserted identityTier is ignored and recomputed",
      fixture: "conformance/fixtures/identity/identity-tier-self-declared.json",
      bundle: identityTierFixture("identity-tier-self-declared.json").identityBundle,
      expected: "self-declared",
    },
    {
      id: "identity-tier-highest-wins",
      description: "IT-3: verified institutional claim wins over verified non-authority claim",
      bundle: {
        bundleVersion: "1",
        presentedBy: "lei:529900T8BM49AURSDO55",
        presentedAt: NOW,
        claims: [
          { ref: "domain:example.com", issuedAt: NOW - 1_000, verifiedBy: verifiedByFor("domain:example.com") },
          { ref: "lei:529900T8BM49AURSDO55", issuedAt: NOW - 1_000, verifiedBy: verifiedByFor("lei:529900T8BM49AURSDO55") },
        ],
        presentation: { kind: "per-claim" },
      },
      expected: "institutional",
    },
    {
      id: "identity-tier-stale-not-elevated",
      description: "IT-3: stale verifiedBy does not elevate an authority-issued claim",
      bundle: {
        bundleVersion: "1",
        presentedBy: "lei:529900T8BM49AURSDO55",
        presentedAt: NOW,
        claims: [
          { ref: "lei:529900T8BM49AURSDO55", issuedAt: NOW - 10_000, expiresAt: NOW - 1, verifiedBy: verifiedByFor("lei:529900T8BM49AURSDO55") },
        ],
        presentation: { kind: "per-claim" },
      },
      expected: "self-declared",
    },
    {
      id: "identity-tier-forged-unresolved",
      description: "IT-3: malformed or unresolved verifiedBy does not elevate an authority-issued claim",
      bundle: {
        bundleVersion: "1",
        presentedBy: "lei:529900T8BM49AURSDO55",
        presentedAt: NOW,
        claims: [
          { ref: "lei:529900T8BM49AURSDO55", issuedAt: NOW - 1_000, verifiedBy: { kind: "storage-program", locator: "stor-forged", contentHash: sha256Hex("forged") } as never },
        ],
        presentation: { kind: "per-claim" },
      },
      expected: "self-declared",
    },
  ];
  for (const tc of identityTierCases) {
    rec(tc.id, "dacs1", "§6.3.2.1", tc.description, deriveIdentityTier(tc.bundle, NOW, resolvedPass), tc.expected);
  }

  const intake = { dacsVersion: "1", listingId: "rfp-intake-1", listingVersion: 1, validity: { notBefore: NOW - 1000 }, pipeline: [{ kind: "negotiate-sealed-envelope" }, { kind: "commit-agreement" }] };
  rec("dacs1-listing-intake-ok", "dacs1", "§6.3.4", "an intake-only listing (no pay phase) may omit acceptedRails",
    validateListingStructure(intake, NOW).ok, true);

  const payNoRails = { dacsVersion: "1", listingId: "buy-1", listingVersion: 1, validity: { notBefore: NOW - 1000 }, pipeline: [{ kind: "pay-evm-erc20" }, { kind: "deliver-storage-program" }] };
  const payRes = validateListingStructure(payNoRails, NOW);
  rec("dacs1-listing-pay-no-rails-fail", "dacs1", "§6.3.4", "step 8: a pay-* phase without acceptedRails fails",
    { ok: payRes.ok, failedAt: payRes.ok ? null : payRes.failedAt }, { ok: false, failedAt: "accepted-rails-conditional" });

  const expired = { dacsVersion: "1", listingId: "old-1", listingVersion: 1, validity: { notBefore: NOW - 2000, notAfter: NOW - 1000 }, pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "commit-agreement" }] };
  const expRes = validateListingStructure(expired, NOW);
  rec("dacs1-listing-expired-fail", "dacs1", "§6.3.4", "an expired validity window is rejected",
    { ok: expRes.ok, failedAt: expRes.ok ? null : expRes.failedAt }, { ok: false, failedAt: "validity-window" });

  const logical = listingLogicalAddress("lei:984500ABCDEF12345678", "fx-rfq-eur-usd", 1);
  const native = nativeAddressPerSpec(logical);
  rec("dacs1-native-address", "dacs1", "§6.3.4", "OBSERVATION DACS-VERIFY-0003: spec rule yields stor-<64hex> (Demos uses stor-<40hex>; verify on substrate before relying)",
    { shape64: /^stor-[0-9a-f]{64}$/.test(native), notLen40: native.length !== "stor-".length + 40 }, { shape64: true, notLen40: true });
  const cf4Input = "cci-xm:evm:mainnet:0x1234?x=1&y=100%";
  const cf4Encoded = cf4Encode(cf4Input);
  rec("cf4-encode-delimiters", "addressing", "§6.3.4 CF-4", "reserved delimiters (: ? & = %) are percent-encoded with uppercase hex, and no other bytes are guessed",
    { encoded: cf4Encoded, decoded: cf4Decode(cf4Encoded) },
    { encoded: "cci-xm%3Aevm%3Amainnet%3A0x1234%3Fx%3D1%26y%3D100%25", decoded: cf4Input });
  const colonListing = listingLogicalAddress("cci-xm:evm:mainnet:0x1234", "rfq:lot?x=1", 3);
  rec("cf4-dacs1-listing-address", "addressing", "§6.3.4 CF-4", "listing logical address encodes sellerPrimaryClaim + listingId variable segments before assembly",
    colonListing, "dacs1:cci-xm%3Aevm%3Amainnet%3A0x1234:rfq%3Alot%3Fx%3D1:v3");
  golden["identityTier"] = {
    status: "golden — reference-verifier-accepted + byte-stable",
    fixtureDir: "conformance/fixtures/identity",
    cases: identityTierCases.map((tc) => ({
      id: tc.id,
      ...(tc.fixture !== undefined ? { fixture: tc.fixture } : {}),
      derived: deriveIdentityTier(tc.bundle, NOW, resolvedPass),
      expected: tc.expected,
    })),
  };
  golden["addressing"] = { logical, native, cf4: { input: cf4Input, encoded: cf4Encoded, colonListing } };
}

// ── §14.2 — DACS-2 Vet: method contract (CM-1..5), retry (VP-R1..4), match (MA-1..3) ──
{
  rec("vet-cm4-classify", "vet", "§7.5.1", "CM-4: the four §7.5.1 outcomes classify; an unknown decision throws",
    { classified: ["pass", "fail", "indeterminate", "error"].map(classifyVetOutcome), unknown: throwResult(() => classifyVetOutcome("maybe"), /§7\.5\.1/) },
    { classified: ["pass", "fail", "indeterminate", "error"], unknown: "throws" });

  rec("vet-cm5-method-contract", "vet", "§7.5", "CM-5: VerifyResult.method must equal the producing kind — match accepted, mismatch rejected",
    {
      match: validateMethodContract({ decision: "pass", method: "vc-presentation" }, "vc-presentation").ok,
      mismatch: validateMethodContract({ decision: "pass", method: "oauth-oidc" }, "vc-presentation").ok,
    },
    { match: true, mismatch: false });

  rec("vet-cm1-input-shape", "vet", "§7.5", "CM-1/CM-3: a VerifyResult missing/invalid decision or method is rejected, never silently passed",
    {
      noMethod: validateMethodContract({ decision: "pass" }).ok,
      noDecision: validateMethodContract({ method: "vc-presentation" }).ok,
      badDecision: validateMethodContract({ decision: "maybe", method: "vc-presentation" } as unknown as Partial<VerifyResult>).ok,
      wellFormed: validateMethodContract({ decision: "indeterminate", method: "vc-presentation" }).ok,
    },
    { noMethod: false, noDecision: false, badDecision: false, wellFormed: true });

  rec("vet-cm2-address", "vet", "§7.3.1", "CM-2: attestation anchors at dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion} (scheme lowercased per CF-2)",
    vetAttestationAddress("job-abc", "LEI", "984500ABCDEF12345678", 3), "dacs2:job-abc:lei:984500ABCDEF12345678:v3");
  rec("cf4-dacs2-attestation-address", "vet", "§6.3.4 CF-4", "dacs2 attestation address encodes a colon-bearing identifier segment",
    vetAttestationAddress("job-abc", "CCI-XM", "evm:mainnet:0x1234", 3), "dacs2:job-abc:cci-xm:evm%3Amainnet%3A0x1234:v3");
  rec("cf4-dacs2-composite-address", "vet", "§6.3.4 CF-4", "dacs2 composite address encodes a colon-bearing evaluatedParty segment",
    vetCompositeAddress("job-abc", "cci-xm:evm:mainnet:0x1234"), "dacs2:composite:job-abc:cci-xm%3Aevm%3Amainnet%3A0x1234");

  rec("vet-vpr1-transient-retry", "vet", "§7.6.1", "VP-R1: decision=error + retryClass=transient + attempts<budget → retry",
    mayRetry({ decision: "error", retryClass: "transient", attempts: 1, retryBudget: 3 }), true);
  rec("vet-vpr1-budget-exhausted", "vet", "§7.6.1", "VP-R1: decision=error + transient at attempts==budget → no retry",
    mayRetry({ decision: "error", retryClass: "transient", attempts: 3, retryBudget: 3 }), false);
  rec("vet-vpr3-permanent-noretry", "vet", "§7.6.1", "VP-R3: decision=error + retryClass=permanent → never retry within session",
    mayRetry({ decision: "error", retryClass: "permanent", attempts: 0, retryBudget: 3 }), false);
  rec("vet-vpr4-indeterminate-noretry", "vet", "§7.6.1", "VP-R4: indeterminate + retryOnIndeterminate unset (default false) → no retry",
    mayRetry({ decision: "indeterminate", attempts: 0, retryBudget: 3 }), false);
  rec("vet-vpr4-indeterminate-flag-retry", "vet", "§7.6.1", "VP-R4: indeterminate + retryOnIndeterminate=true → retry",
    mayRetry({ decision: "indeterminate", retryOnIndeterminate: true, attempts: 0, retryBudget: 3 }), true);
  rec("vet-terminal-noretry", "vet", "§7.6.1", "a terminal authority answer (pass/fail) is never retried",
    { pass: mayRetry({ decision: "pass", attempts: 0 }), fail: mayRetry({ decision: "fail", attempts: 0 }) }, { pass: false, fail: false });

  // MA-1..3 matching with full verifiedBy → resolved-decision check.
  const NOW = 1_900_000_000_000;
  const vb = (locator: string): NonNullable<BundleClaim["verifiedBy"]> => ({ anchor: { kind: "storage-program", locator }, contentHash: "h", recipeVersion: 1 });
  const resolveVR: VerifyResultResolver = (v) =>
    v.anchor.locator === "stor-fail" ? { decision: "fail", method: "vc-presentation" }
      : v.anchor.locator === "stor-indet" ? { decision: "indeterminate", method: "vc-presentation" }
        : v.anchor.locator === "stor-error" ? { decision: "error", method: "vc-presentation", errorClass: "transient" }
          : v.anchor.locator === "stor-counterparty-malformed" ? { decision: "error", method: "vc-presentation", errorClass: "counterparty" }
            : v.anchor.locator === "stor-vlei-pass" ? { decision: "pass", method: "vlei-presentation", data: { holderBinding: true } }
              : v.anchor.locator === "stor-registry-fake-holderbinding" ? { decision: "pass", method: "gleif-registry", data: { holderBinding: true } }
                : v.anchor.locator === "stor-sr1-pass" ? { decision: "pass", method: "sr1-link", data: { sr1ControlLink: true } }
                : { decision: "pass", method: "gleif-registry" };
  const mk = (claims: BundleClaim[], presentedBy?: string, presentation: IdentityBundle["presentation"] = { kind: "siwd" }): IdentityBundle => ({
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => (c.issuedAt === undefined && c.expiresAt === undefined ? { ...c, issuedAt: NOW - 1_000 } : c)),
    presentation,
  });
  const reqLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const reqOneOf: BundleRequirement = { requirementVersion: "1", required: [], oneOf: [[{ scheme: "lei", verificationRequired: true }, { scheme: "finra-crd", verificationRequired: true }]] };
  const reqPrimary: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }], primaryClaimSelector: "lei" };

  rec("vet-ma1-required-missing", "vet", "§6.3.3", "MA-1: a missing required claim → REJECT",
    vetMatch(mk([{ ref: "did:demos:x", verifiedBy: vb("stor-pass") }]), reqLei, resolveVR, NOW).ok, false);
  rec("vet-ma1-oneof", "vet", "§6.3.3", "MA-1: oneOf satisfied by any member → continue; satisfied by none → REJECT",
    {
      satisfied: vetMatch(mk([{ ref: "finra-crd:12345", verifiedBy: vb("stor-pass") }]), reqOneOf, resolveVR, NOW).ok,
      unsatisfied: vetMatch(mk([{ ref: "did:demos:x", verifiedBy: vb("stor-pass") }]), reqOneOf, resolveVR, NOW).ok,
    },
    { satisfied: true, unsatisfied: false });
  rec("vet-ma2-scheme-mismatch", "vet", "§6.3.3", "MA-2: presentedBy scheme != primaryClaimSelector → REJECT",
    vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-pass") }, { ref: "did:demos:k", verifiedBy: vb("stor-pass") }], "did:demos:k"), reqPrimary, resolveVR, NOW).ok, false);

  const ma3Unverified = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") }, { ref: "lei:529900T8BM49AABBCC11", verifiedBy: vb("stor-pass") }], "lei:984500ABCDEF12345678");
  rec("vet-ma3-unverified-reject", "vet", "§6.3.3", "MA-3: selector set + presentedBy verifiedBy resolves decision!=pass → REJECT (tier-laundering guard)",
    vetMatch(ma3Unverified, reqPrimary, resolveVR, NOW).ok, false);
  rec("vet-ma3-resolution-vs-presence", "vet", "§6.3.3", "MA-3 full resolution: dacs1 presence-only ACCEPTS a present-but-failing verifiedBy; vetMatch REJECTS it",
    { dacs1Presence: matchRequirement(ma3Unverified, reqPrimary, NOW).ok, vetResolved: vetMatch(ma3Unverified, reqPrimary, resolveVR, NOW).ok },
    { dacs1Presence: true, vetResolved: false });
  rec("vet-ma3-verified-accept", "vet", "§6.3.3", "MA-3: selector set + presentedBy resolves to pass → ACCEPT",
    vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-vlei-pass") }], "lei:984500ABCDEF12345678"), reqPrimary, resolveVR, NOW).ok, true);
  const registryLei = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-registry-pass") }], "lei:984500ABCDEF12345678");
  rec("vet-control-existence-only-lei-supporting-context", "vet", "§6.3.2 step (6)", "#170: existence-only bare-registry LEI pass remains valid supporting context for a required claim",
    vetMatch(registryLei, reqLei, resolveVR, NOW).ok, true);
  rec("vet-control-existence-only-lei-presentedby-reject", "vet", "§6.3.2 step (6)", "#170: existence-only bare-registry LEI pass cannot serve as controlled presentedBy",
    vetMatch(registryLei, reqPrimary, resolveVR, NOW).ok, false);
  rec("vet-control-existence-only-lei-reputation-key-reject", "vet", "§10.5.2", "#170: existence-only bare-registry LEI pass cannot serve as a reputation key",
    vetControlledPresentedBy(registryLei, resolveVR, NOW).ok, false);
  const registryLeiWithForgedControlData = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-registry-fake-holderbinding") }], "lei:984500ABCDEF12345678");
  rec("vet-control-existence-method-forged-holderbinding-reject", "vet", "§6.3.2 step (6)", "#170: existence-only methods cannot forge control by setting holderBinding data",
    vetMatch(registryLeiWithForgedControlData, reqPrimary, resolveVR, NOW).ok,
    false);
  const keyControlKp = keypairFromSeed("17".repeat(32));
  const keyControlClaim = `key:${keyControlKp.publicKeyB64u}`;
  const unsignedKeyControl = mk([{ ref: keyControlClaim, issuedAt: NOW - 1_000 }], keyControlClaim, { kind: "per-claim", signatures: [] });
  const keyControlSignature = signArtifact("dacs-bundle-presentation:v1:", unsignedKeyControl as unknown as Record<string, unknown>, keyControlKp.privateKey, ["presentation"]);
  rec("vet-control-key-presentation-accept", "vet", "§6.3.2 step (6)", "#170: a key: claim is controlled by a per-claim presentation signature",
    vetMatch({ ...unsignedKeyControl, presentation: { kind: "per-claim", signatures: [{ ref: keyControlClaim, signature: keyControlSignature }] } }, { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" }, resolveVR, NOW).ok,
    true);
  const malformedKeyControlKp = keypairFromSeed("1a".repeat(32));
  const malformedKeyControlClaim = `key:${malformedKeyControlKp.publicKeyB64u}`;
  const unsignedMalformedKeyControl = mk([{ ref: malformedKeyControlClaim, issuedAt: NOW - 1_000 }], malformedKeyControlClaim, { kind: "per-claim", signatures: [] });
  const malformedKeyControlSignature = signArtifact("dacs-bundle-presentation:v1:", unsignedMalformedKeyControl as unknown as Record<string, unknown>, malformedKeyControlKp.privateKey, ["presentation"]);
  const malformedKeyControlBundle = { ...unsignedMalformedKeyControl, presentedAt: Number.MAX_SAFE_INTEGER + 1, presentation: { kind: "per-claim", signatures: [{ ref: malformedKeyControlClaim, signature: malformedKeyControlSignature }] } } as unknown as IdentityBundle;
  const malformedKeyControlResult = (() => {
    try {
      return vetMatch(malformedKeyControlBundle, { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" }, resolveVR, NOW).ok ? "pass" : "fail";
    } catch {
      return "throw";
    }
  })();
  rec("vet-control-key-malformed-scope-reject-no-throw", "vet", "§6.3.2 step (6)", "#170: malformed key presentation scope rejects instead of throwing",
    malformedKeyControlResult,
    "fail");
  const staleKeyControlKp = keypairFromSeed("18".repeat(32));
  const staleKeyControlClaim = `key:${Buffer.from(staleKeyControlKp.publicKeyRaw).toString("hex")}`;
  const unsignedStaleKeyControl = mk([
    { ref: staleKeyControlClaim, issuedAt: NOW - 2_000, expiresAt: NOW - 1_000 },
    { ref: `key:${"ab".repeat(32)}`, issuedAt: NOW - 1_000 },
  ], staleKeyControlClaim, { kind: "per-claim", signatures: [] });
  const staleKeyControlSignature = signArtifact("dacs-bundle-presentation:v1:", unsignedStaleKeyControl as unknown as Record<string, unknown>, staleKeyControlKp.privateKey, ["presentation"]);
  rec("vet-control-key-stale-reject", "vet", "§6.3.2 step (6)", "#170: a stale key: claim remains rejected even with a valid presentation signature",
    vetMatch({ ...unsignedStaleKeyControl, presentation: { kind: "per-claim", signatures: [{ ref: staleKeyControlClaim, signature: staleKeyControlSignature }] } }, { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" }, resolveVR, NOW).ok,
    false);
  const unverifiedKeyControlKp = keypairFromSeed("19".repeat(32));
  const unverifiedKeyControlClaim = `key:${Buffer.from(unverifiedKeyControlKp.publicKeyRaw).toString("hex")}`;
  const unsignedUnverifiedKeyControl = mk([
    { ref: unverifiedKeyControlClaim, issuedAt: NOW - 1_000 },
    { ref: `key:${"cd".repeat(32)}`, issuedAt: NOW - 1_000, verifiedBy: vb("stor-pass") },
  ], unverifiedKeyControlClaim, { kind: "per-claim", signatures: [] });
  const unverifiedKeyControlSignature = signArtifact("dacs-bundle-presentation:v1:", unsignedUnverifiedKeyControl as unknown as Record<string, unknown>, unverifiedKeyControlKp.privateKey, ["presentation"]);
  rec("vet-control-key-verified-selector-laundering-reject", "vet", "§6.3.2 step (6)", "#170: verificationRequired key selectors reject an unverified presentedBy even when another key satisfies MA-1",
    vetMatch({ ...unsignedUnverifiedKeyControl, presentation: { kind: "per-claim", signatures: [{ ref: unverifiedKeyControlClaim, signature: unverifiedKeyControlSignature }] } }, { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: true }], primaryClaimSelector: "key" }, resolveVR, NOW).ok,
    false);
  rec("vet-findclaim-decision", "vet", "§6.3.3", "find_claim: a verificationRequired claim whose verifiedBy resolves to indeterminate is treated as absent",
    vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-indet") }]), reqLei, resolveVR, NOW).ok, false);

  const vetMaxAgeReq: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }] };
  rec("vet-freshness-fail-closed", "vet", "§6.3.2/§6.3.3", "vetFindClaim applies the same freshness pre-gate before maxAge after resolving verifiedBy decision",
    {
      absentBoth: vetMatch({ bundleVersion: "1", presentedBy: "lei:984500ABCDEF12345678", presentedAt: NOW, claims: [{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } }, reqLei, resolveVR, NOW).ok,
      expired: vetMatch({ bundleVersion: "1", presentedBy: "lei:984500ABCDEF12345678", presentedAt: NOW, claims: [{ ref: "lei:984500ABCDEF12345678", issuedAt: NOW - 1_000, expiresAt: NOW - 1, verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } }, reqLei, resolveVR, NOW).ok,
      expiresOnly: vetMatch({ bundleVersion: "1", presentedBy: "lei:984500ABCDEF12345678", presentedAt: NOW, claims: [{ ref: "lei:984500ABCDEF12345678", expiresAt: NOW + 1_000, verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } }, reqLei, resolveVR, NOW).ok,
      expiresOnlyMaxAge: vetMatch({ bundleVersion: "1", presentedBy: "lei:984500ABCDEF12345678", presentedAt: NOW, claims: [{ ref: "lei:984500ABCDEF12345678", expiresAt: NOW + 1_000, verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } }, vetMaxAgeReq, resolveVR, NOW).ok,
      stalePresentedByPrimary: vetMatch({ bundleVersion: "1", presentedBy: "lei:STALE", presentedAt: NOW, claims: [{ ref: "lei:STALE", issuedAt: NOW - 10_000, expiresAt: NOW - 1, verifiedBy: vb("stor-pass") }, { ref: "lei:FRESH", issuedAt: NOW - 1_000, expiresAt: NOW + 60_000, verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } }, { ...vetMaxAgeReq, primaryClaimSelector: "lei" }, resolveVR, NOW).ok,
    },
    { absentBoth: false, expired: false, expiresOnly: true, expiresOnlyMaxAge: false, stalePresentedByPrimary: false });

  const aggregationOneOf: BundleRequirement = { requirementVersion: "1", required: [], oneOf: [[{ scheme: "lei", verificationRequired: true }, { scheme: "domain", verificationRequired: true }]] };
  rec("vet-oneof-error-over-fail", "vet", "§7.7.1", "oneOf within-group precedence: error > indeterminate > fail",
    evaluateVetRequirement(mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-error") },
    ]), aggregationOneOf, resolveVR, NOW),
    { decision: "error", errorClass: "transient" });
  rec("vet-oneof-indeterminate-over-fail", "vet", "§7.7.1", "oneOf within-group precedence: indeterminate > fail when no error/pass is present",
    evaluateVetRequirement(mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-indet") },
    ]), aggregationOneOf, resolveVR, NOW),
    { decision: "indeterminate" });
  rec("vet-cross-accumulator-fail-over-error", "vet", "§7.7.1", "cross-accumulator precedence across required + oneOf: fail > error > indeterminate",
    evaluateVetRequirement(mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-error") },
    ]), { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }], oneOf: [[{ scheme: "domain", verificationRequired: true }]] }, resolveVR, NOW),
    { decision: "fail", errorClass: "permanent" });
  rec("vet-counterparty-malformed-attribution", "vet", "§7.8.2", "VPC-4/R8-E: counterparty-malformed oneOf alternative keeps decision=error but attributes phaseSummary.errorClass=counterparty",
    evaluateVetRequirement(mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-counterparty-malformed") },
    ]), aggregationOneOf, resolveVR, NOW),
    { decision: "error", errorClass: "counterparty" });

  golden["vet"] = {
    decisions: VET_DECISIONS,
    address: vetAttestationAddress("job-abc", "LEI", "984500ABCDEF12345678", 3),
    cf4Address: vetAttestationAddress("job-abc", "CCI-XM", "evm:mainnet:0x1234", 3),
    cf4Composite: vetCompositeAddress("job-abc", "cci-xm:evm:mainnet:0x1234"),
    retryBudgetDefault: 3,
    aggregation: {
      oneOfPrecedence: "error > indeterminate > fail",
      crossAccumulatorPrecedence: "fail > error > indeterminate",
      counterpartyMalformedErrorClass: "counterparty",
    },
  };
}

// ── §14.3 — DACS-3 Negotiate: §8.5.2 listing-conformance validation ──────────
{
  const COMMITTED_AT = 1_900_000_000_000;
  const deliverableSpec = { deliverableType: "attested-payload", verificationMethod: "http-attestation", schemaUrl: "https://schemas.example/x.json" };
  const dHash = deliverableSpecHash(deliverableSpec);
  const baseListing: ListingForValidation = {
    listingId: "L1",
    listingVersion: 1,
    pricing: { kind: "negotiable", bandCenter: { amount: "100", currency: "USDC" }, minPct: 10, maxPct: 20 },
    acceptedRails: ["erc20-usdc-base", "spl-usdc"],
    offering: { deliverable: deliverableSpec },
    pattern: "rfq",
    terms: { deadlineSecAfterCommit: 86400 },
    validity: { notBefore: COMMITTED_AT - 100_000, notAfter: COMMITTED_AT + 1_000_000 },
  };
  const okAgreement: AgreementDocument = {
    derivedFromPattern: "rfq",
    terms: {
      price: { amount: "95", currency: "USDC" },
      rail: "erc20-usdc-base",
      deliverable: { deliverableType: "attested-payload", hash: dHash, schemaUrl: "https://schemas.example/x.json" },
      deadline: COMMITTED_AT + 1000,
    },
  };
  const atPrice = (amount: string): AgreementDocument => ({ ...okAgreement, terms: { ...okAgreement.terms, price: { amount, currency: "USDC" } } });
  const bind = (a: AgreementDocument, l: ListingForValidation = baseListing): AgreementDocument => ({
    ...a,
    listingRef: {
      listingId: l.listingId!,
      version: (l.version ?? l.listingVersion)!,
      contentHash: listingContentHash(l),
    },
  });
  const valid = (a: AgreementDocument, l: ListingForValidation = baseListing): boolean => validateAgreement(bind(a, l), l, COMMITTED_AT).ok;
  const failedAt = (a: AgreementDocument, l: ListingForValidation): unknown => { const r = validateAgreement(bind(a, l), l, COMMITTED_AT); return { ok: r.ok, failedAt: r.ok ? null : r.failedAt }; };

  rec("neg-band-inclusive", "negotiate", "§8.5.2", "price-band [bandCenter×(100−minPct)/100, ×(100+maxPct)/100] inclusive; edges accept, just-outside reject (CD-1 full precision)",
    {
      inBand: valid(atPrice("95")),
      lowerEdge: valid(atPrice("90")),
      upperEdge: valid(atPrice("120")),
      below: valid(atPrice("89.999")),
      above: valid(atPrice("120.001")),
    },
    { inBand: true, lowerEdge: true, upperEdge: true, below: false, above: false });

  rec("neg-currency-mismatch", "negotiate", "§8.5.2", "a cross-currency agreement is rejected before any amount comparison",
    failedAt({ ...okAgreement, terms: { ...okAgreement.terms, price: { amount: "95", currency: "EURC" } } }, baseListing),
    { ok: false, failedAt: "currency" });

  rec("neg-rail-reject", "negotiate", "§8.5.2", "terms.rail not in listing.acceptedRails → REJECT",
    failedAt({ ...okAgreement, terms: { ...okAgreement.terms, rail: "wire-transfer" } }, baseListing),
    { ok: false, failedAt: "rail" });

  const delivBad = (deliverable: AgreementDocument["terms"]["deliverable"]): AgreementDocument => ({ ...okAgreement, terms: { ...okAgreement.terms, deliverable } });
  rec("neg-deliverable", "negotiate", "§8.5.2", "deliverable conformance: deliverableType + canonical hash + schemaUrl must all match the listing offering.deliverable",
    {
      conforming: valid(okAgreement),
      typeMismatch: valid(delivBad({ deliverableType: "entitlement", hash: dHash, schemaUrl: "https://schemas.example/x.json" })),
      hashMismatch: valid(delivBad({ deliverableType: "attested-payload", hash: "deadbeef", schemaUrl: "https://schemas.example/x.json" })),
      schemaMismatch: valid(delivBad({ deliverableType: "attested-payload", hash: dHash, schemaUrl: "https://other.example/y.json" })),
    },
    { conforming: true, typeMismatch: false, hashMismatch: false, schemaMismatch: false });

  const deadlineAgreement = (deadline: number): AgreementDocument => ({ ...okAgreement, terms: { ...okAgreement.terms, deadline } });
  rec("neg-deadline-committedat", "negotiate", "§8.5.2", "deadline ≤ committedAt + deadlineSecAfterCommit, measured against the ANCHORED committedAt (not generatedAt)",
    {
      within: valid(deadlineAgreement(COMMITTED_AT + 86400 * 1000)),
      beyond: valid(deadlineAgreement(COMMITTED_AT + 86400 * 1000 + 1)),
    },
    { within: true, beyond: false });

  rec("neg-notafter", "negotiate", "§8.5.2", "listing.validity.notAfter < committedAt → REJECT (listing expired between read and commit)",
    failedAt(okAgreement, { ...baseListing, validity: { notBefore: COMMITTED_AT - 100_000, notAfter: COMMITTED_AT - 1 } }),
    { ok: false, failedAt: "notAfter" });

  rec("neg-pattern-mismatch", "negotiate", "§8.5.2", "derivedFromPattern != listing pipeline pattern → REJECT",
    failedAt({ ...okAgreement, derivedFromPattern: "sealed-envelope" }, baseListing),
    { ok: false, failedAt: "pattern" });

  const fixedOverNeg: ListingForValidation = { ...baseListing, pattern: "fixed-price" };
  rec("neg-ps3-fixed-over-negotiable", "negotiate", "§8.5.2", "PS-3: a fixed-price agreement over negotiable pricing MUST equal bandCenter exactly, not merely lie within the band",
    {
      exact: valid({ ...atPrice("100"), derivedFromPattern: "fixed-price" }, fixedOverNeg),
      inBandNotExact: valid({ ...atPrice("95"), derivedFromPattern: "fixed-price" }, fixedOverNeg),
    },
    { exact: true, inBandNotExact: false });

  rec("neg-priceanchor-absent-ok", "negotiate", "§8.5.2", "priceAnchor absent MUST NOT cause rejection — an otherwise-valid agreement is accepted",
    valid(okAgreement), true);

  const withAnchor = (price: string): AgreementDocument => ({ ...okAgreement, terms: { ...okAgreement.terms, priceAnchor: { price, attestationRef: { contentHash: "abc123" } } } });
  rec("neg-priceanchor-present", "negotiate", "§8.5.2", "when present, priceAnchor.price MUST be CD-1 canonical + attestationRef.contentHash present; non-canonical → REJECT",
    {
      valid: valid(withAnchor("100")),
      nonCanonical: valid(withAnchor("100.00")),
    },
    { valid: true, nonCanonical: false });

  rec("neg-price-noncanonical", "negotiate", "§8.5.1", "terms.price.amount MUST be CD-1 canonical — a non-canonical amount (\"100.00\") is rejected before comparison, not normalized-then-accepted (consistent with the §14.4 settlement lane)",
    failedAt(atPrice("100.00"), baseListing),
    { ok: false, failedAt: "price" });

  golden["negotiate"] = { deliverableHash: dHash, band: negotiableBand("100", 10, 20) };
}

// ── §14.7 — DACS-2 Governance (GOV-1..3) ────────────────────────────────────
{
  const throws = (fn: () => unknown): boolean => { try { fn(); return false; } catch { return true; } };

  // GOV-2 — closed-set anchoring phase classification + in-code ≠ anchored.
  rec("gov-gov2-classify", "governance", "§7.4.4", "GOV-2: the three §7.4.1 anchoring phases classify; an unknown phase throws",
    [...ANCHORING_PHASES.map(classifyAnchoringPhase), throws(() => classifyAnchoringPhase("constituted"))],
    ["in-code", "single-signer", "multisig", true]);

  rec("gov-gov2-incode-not-anchored", "governance", "§7.4.4", "GOV-3 core: `in-code` (PA-1) is NOT canonically anchored; single-signer/multisig are",
    ANCHORING_PHASES.map(isCanonicallyAnchored), [false, true, true]);

  // GOV-1 — steward disclosure (ADVISORY: `represents` is a verifier-internal
  // disclosure hint, NOT a DACS wire-field; GOV-1 is a UX/disclosure obligation
  // the spec defines no wire format for — enforced advisorily, steward owns any
  // normative representation).
  rec("gov-gov1-discloses-key", "governance", "§14.7", "GOV-1 (advisory; `represents` is a verifier-internal hint, not a spec wire-field): a consumer surfacing a key + presenting PA-2 as single-steward → ACCEPT",
    validateStewardDisclosure({ authoritativeSigningKey: "ed25519:kynesys-v0.1", represents: "single-steward", actualPhase: "single-signer" }),
    { ok: true });

  rec("gov-gov1-missing-key", "governance", "§14.7", "GOV-1: a consumer that does not surface an authoritative signing key → REJECT",
    validateStewardDisclosure({ represents: "single-steward", actualPhase: "single-signer" }).ok, false);

  rec("gov-gov1-misrepresent-constituted", "governance", "§12", "GOV-1: presenting a single-signer (PA-2) steward as a constituted multi-party body → REJECT",
    validateStewardDisclosure({ authoritativeSigningKey: "ed25519:kynesys-v0.1", represents: "constituted-body", actualPhase: "single-signer" }).ok, false);

  rec("gov-gov1-constituted-ok-at-multisig", "governance", "§7.4.4", "GOV-1: presenting a constituted body is honest only once the registry is actually multisig (PA-3)",
    validateStewardDisclosure({ authoritativeSigningKey: "multisig:dacs-wg", represents: "constituted-body", actualPhase: "multisig" }),
    { ok: true });

  // GOV-3 — pin-time anchoring-phase verification (the temporal-trust invariant).
  rec("gov-gov3-pintime-governs", "governance", "§7.4.4", "GOV-3: a recipeVersion pinned at single-signer (PA-2) is evaluated against PIN-TIME phase, NOT the current multisig (PA-3) registry — append-only re-anchoring MUST NOT retro-upgrade a pin",
    evaluatePinnedRecipe({ recipeVersion: 3, pinTimePhase: "single-signer", currentPhase: "multisig" }),
    { recipeVersion: 3, evaluatedPhase: "single-signer", canonicallyAnchored: true, ok: true });

  rec("gov-gov3-incode-pin-not-anchored", "governance", "§7.4.4", "GOV-3: a pinned `in-code` recipeVersion evaluates as not canonically anchored",
    (() => { const d = evaluatePinnedRecipe({ recipeVersion: 1, pinTimePhase: "in-code" }); return { canonicallyAnchored: d.canonicallyAnchored, ok: d.ok }; })(),
    { canonicallyAnchored: false, ok: true });

  rec("gov-gov3-below-trust-floor", "governance", "§7.4.4", "GOV-3: a single-signer pin under a consumer trust floor of multisig → REJECT",
    evaluatePinnedRecipe({ recipeVersion: 3, pinTimePhase: "single-signer", requiredMinPhase: "multisig" }).ok, false);

  rec("gov-gov3-meets-trust-floor", "governance", "§7.4.4", "GOV-3: a multisig pin meeting a multisig trust floor → ACCEPT",
    evaluatePinnedRecipe({ recipeVersion: 7, pinTimePhase: "multisig", requiredMinPhase: "multisig" }).ok, true);

  // Trust-boundary fail-closed: a malformed `governance.anchoring` (a parsed/JS
  // caller defeating the TS type) MUST be rejected, never trusted as anchored.
  rec("gov-gov3-unknown-phase-rejected", "governance", "§7.4.4", "GOV-3 fail-closed: an unrecognised pin-time phase (malformed governance.anchoring) is REJECTED, not treated as canonically anchored",
    throws(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: "constituted" as unknown as AnchoringPhase })), true);

  rec("gov-gov1-unknown-phase-rejected", "governance", "§7.4.4", "GOV-1 fail-closed: an unrecognised actualPhase is REJECTED before any disclosure decision",
    throws(() => validateStewardDisclosure({ authoritativeSigningKey: "ed25519:k", actualPhase: "bogus" as unknown as AnchoringPhase })), true);

  golden["governance"] = {
    status: "golden — reference-verifier-accepted + byte-stable",
    phases: ANCHORING_PHASES,
    pinTimeGoverns: evaluatePinnedRecipe({ recipeVersion: 3, pinTimePhase: "single-signer", currentPhase: "multisig" }),
    gov1Note: "GOV-1 enforced advisorily — `represents` is a verifier-internal disclosure hint, not a DACS wire-field; the steward owns any normative representation.",
  };
}

// ── §10.4 — DACS-5 AttestationBundle verification ───────────────────────────
{
  const resolve = (claim: ClaimReference): Uint8Array | undefined => bundle0004Keys[claim];
  const resolveHtlc9 = (claim: ClaimReference): Uint8Array | undefined => bundleHtlc9Keys[claim];
  const htlc9SettlementPhase = bundleHtlc9.bundle.phaseSummary.find((p) => p.kind === "pay-cross-chain-htlc");
  rec("bundle-0004-pass", "bundle", "§10.4", "DACS-VERIFY-0004 completed AttestationBundle verifies with buyer + seller signatures",
    verifyBundle(bundle0004.bundle, resolve), "pass");

  rec("bundle-htlc9-pass", "bundle", "§10.4", "HTLC-9 AttestationBundle verifies and maps settlement-atomicity failure to failed-counterparty with destination reveal txRef",
    {
      decision: verifyBundle(bundleHtlc9.bundle, resolveHtlc9),
      outcome: bundleHtlc9.bundle.outcome,
      phaseOutcome: htlc9SettlementPhase?.outcome,
      errorClass: htlc9SettlementPhase?.errorClass,
      revealRecorded: htlc9SettlementPhase?.txRefs?.some((tx) => tx.kind === "htlc-reveal" && tx.txHash === ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF) ?? false,
    },
    { decision: "pass", outcome: "failed-counterparty", phaseOutcome: "fail", errorClass: "settlement-atomicity", revealRecorded: true });

  const missingSeller = { ...bundle0004.bundle, signatures: bundle0004.bundle.signatures.filter((s) => s.party !== "did:demos:seller") };
  rec("bundle-required-signer-fail", "bundle", "§10.4.1", "completed bundle missing a required seller signature → FAIL",
    verifyBundle(missingSeller, resolve), "fail");

  rec("bundle-malformed-key-error", "bundle", "§10.4.1", "wrong-length resolved public key → ERROR, not a false-negative FAIL",
    verifyBundle(bundle0004.bundle, (claim) => claim === "did:demos:buyer" ? new Uint8Array([1, 2, 3]) : resolve(claim)), "error");

  golden["bundle"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    fixture: "conformance/fixtures/attestation-bundle-0004.json",
    jobId: bundle0004.bundle.jobId,
    bundleHash: bundle0004.bundleHash,
    decisions: { pass: "pass", requiredSignerReject: "fail", malformedKey: "error" },
    seeds: bundle0004.seeds,
    publicKeys: bundle0004.publicKeys,
    divergentSellerFixture: "conformance/fixtures/attestation-bundle-0004-seller.json",
    divergentSeller: {
      jobId: bundle0004Seller.bundle.jobId,
      bundleHash: bundle0004Seller.bundleHash,
      decision: verifyBundle(bundle0004Seller.bundle, resolve),
      outcome: bundle0004Seller.bundle.outcome,
    },
    htlc9Fixture: "conformance/fixtures/attestation-bundle-htlc9.json",
    htlc9: {
      jobId: bundleHtlc9.bundle.jobId,
      bundleHash: bundleHtlc9.bundleHash,
      decision: verifyBundle(bundleHtlc9.bundle, resolveHtlc9),
      settlementPhase: {
        kind: htlc9SettlementPhase?.kind,
        outcome: htlc9SettlementPhase?.outcome,
        errorClass: htlc9SettlementPhase?.errorClass,
        revealTxRef: ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
      },
    },
  };
}

// ── §11.2.1 — DACS-X dispute flow (4-value decision) ────────────────────────
// Golden: every dispute record pins full §10.4 AttestationBundles by exact
// (jobId, bundleHash), and those bundles verify through verifyBundle above.
{
  const NOW = 1_780_000_000_000;
  const buyer = keypairFromSeed("a1".repeat(32));
  const arbitrator = keypairFromSeed("b2".repeat(32));
  const buyerClaim = "did:demos:buyer";
  const arbitratorClaim = "did:arbitrator:court";
  const jobId = bundle0004.bundle.jobId;
  const bundleHash = bundle0004.bundleHash;
  const sellerBundleHash = bundle0004Seller.bundleHash;
  const divergentBundleRefs = [{ jobId, bundleHash }, { jobId, bundleHash: sellerBundleHash }];
  const knownBundles = divergentBundleRefs;
  const htlc9JobId = bundleHtlc9.bundle.jobId;
  const htlc9BundleHash = bundleHtlc9.bundleHash;
  const requirement: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }], primaryClaimSelector: "did" };
  const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
  const ruleRef = sha256Hex(canonicalize(agreedRule));
  const arbitratorBundle: IdentityBundle = {
    bundleVersion: "1", presentedBy: arbitratorClaim, presentedAt: NOW,
    claims: [
      { ref: arbitratorClaim, verifiedBy: { anchor: { kind: "sr1-root", locator: "x" }, contentHash: sha256Hex("a"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
      { ref: "arbitrator-accreditation:iso", verifiedBy: { anchor: { kind: "sr1-root", locator: "y" }, contentHash: sha256Hex("b"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
    ],
    presentation: {},
  };
  const makeRecord = (signer = buyer): DisputeRecord => {
    const unsigned: Omit<DisputeRecord, "signature"> = {
      dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim, disputed: divergentBundleRefs,
      contestedClaim: "divergent-bundle", requestedRemedy: "refund", arbitration: { ruleRef }, openedAt: NOW,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const makeOutcome = (record: DisputeRecord, signer = arbitrator, remedy: RemedyDecision = { kind: "refund-ordered", amount: "5", asset: "usdc" }): DisputeOutcome => {
    const unsigned: Omit<DisputeOutcome, "signature"> = {
      dacsXVersion: "1", disputeId: record.disputeId, disputeRecordHash: disputeRecordHash(record), arbitrator: arbitratorClaim, remedy, decidedAt: NOW + 1000,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const baseInput = (): DisputeFlowInput => {
    const record = makeRecord();
    return {
      record, initiatorPublicKeyRaw: buyer.publicKeyRaw, knownBundles, arbitratorBundle, agreedRule,
      now: NOW + 1000, outcome: makeOutcome(record), arbitratorPublicKeyRaw: arbitrator.publicKeyRaw, priorReputation: { jobId, weight: 1 },
    };
  };

  const happy = verifyDisputeFlow(baseInput());
  rec("dispute-happy-pass", "dispute", "§11.2.1", "consistent dispute → PASS, disputed contribution reweighted to 0 (prior preserved)",
    { decision: happy.decision, effectiveWeight: happy.reweighted?.effectiveWeight, priorWeight: happy.reweighted?.priorWeight },
    { decision: "pass", effectiveWeight: 0, priorWeight: 1 });

  const open = baseInput(); delete (open as Partial<DisputeFlowInput>).outcome; delete (open as Partial<DisputeFlowInput>).arbitratorPublicKeyRaw;
  rec("dispute-open-indeterminate", "dispute", "§11.2.1", "an open dispute with no outcome yet → INDETERMINATE",
    verifyDisputeFlow(open).decision, "indeterminate");

  const badKey = baseInput(); badKey.initiatorPublicKeyRaw = arbitrator.publicKeyRaw;
  rec("dispute-bad-record-key-fail", "dispute", "§11.2.1", "a dispute-record verified against the wrong key → FAIL",
    verifyDisputeFlow(badKey).decision, "fail");

  const malformed = baseInput(); malformed.initiatorPublicKeyRaw = new Uint8Array([1, 2, 3]);
  rec("dispute-malformed-key-error", "dispute", "§11.2.1", "an unparseable (non-32-byte) key → ERROR, not a false-negative FAIL",
    verifyDisputeFlow(malformed).decision, "error");

  const ruleSwap = baseInput();
  ruleSwap.agreedRule = { requirement: { requirementVersion: "1", required: [{ scheme: "self-signed", verificationRequired: false }] }, arbitrators: [arbitratorClaim], policyVersion: 1 };
  rec("dispute-rule-swap-fail", "dispute", "§11.2.1", "a post-hoc arbitration-rule swap (rule-ref mismatch) → FAIL",
    verifyDisputeFlow(ruleSwap).decision, "fail");

  const wrongOutcomeKey = baseInput(); wrongOutcomeKey.arbitratorPublicKeyRaw = buyer.publicKeyRaw;
  rec("dispute-wrong-outcome-key-fail", "dispute", "§11.2.1", "an outcome signed by the wrong key → FAIL",
    verifyDisputeFlow(wrongOutcomeKey).decision, "fail");

  const nonCanon = baseInput(); nonCanon.outcome = makeOutcome(nonCanon.record, arbitrator, { kind: "refund-ordered", amount: "5.00", asset: "usdc" });
  rec("dispute-noncanonical-amount-fail", "dispute", "§11.2.1", "an outcome with a non-CD-1 refund amount → FAIL",
    verifyDisputeFlow(nonCanon).decision, "fail");

  const unknownBundle = baseInput(); unknownBundle.knownBundles = [{ jobId: "other-job", bundleHash }];
  rec("dispute-unknown-bundle-fail", "dispute", "§11.2.1", "a dispute pinned to an unknown bundle → FAIL",
    verifyDisputeFlow(unknownBundle).decision, "fail");

  // (Removed) The former `dispute-htlc9-correction-pass` golden vector asserted an HTLC-9 asymmetric settlement closing
  // via a `correction` amendment. Round-4 R4-A REMOVED the correction amendment: an HTLC-9 asymmetric loss now resolves
  // at the SETTLEMENT layer through the non-terminal ST-8 `settle-asymmetric` state (→ terminal `completed` on htlc-claim,
  // → terminal `failed-counterparty` on window expiry; covered by the §14.5 verify-st-asymmetric-* vectors). A dispute
  // over the window-expired terminal `failed-counterparty` uses a standard remedy — there is no spec correction path to
  // assert as golden. The DACS-X prototype's `correction-ordered` remedy is now REMOVED (commit "remove spec-obsolete
  // correction-ordered remedy"); ST-8 is covered by the verify-st-asymmetric-* vectors, while
  // ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF remains exercised by bundle-htlc9-pass for the resolved
  // failed-counterparty terminal bundle (structural bundle verification + reveal-txRef presence).

  golden["dispute"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    bundleRef: { jobId, bundleHash },
    divergentBundleRefs,
    htlc9BundleRef: { jobId: htlc9JobId, bundleHash: htlc9BundleHash },
    seeds: { buyer: "a1".repeat(32), arbitrator: "b2".repeat(32) },
    now: NOW,
    decisions: {
      happy: "pass", open: "indeterminate", badRecordKey: "fail", malformedKey: "error",
      ruleSwap: "fail", wrongOutcomeKey: "fail", nonCanonicalAmount: "fail", unknownBundle: "fail",
    },
    inputs: "constructed deterministically in conformance/run.ts from the seeds above; divergent-bundle refs point to conformance/fixtures/attestation-bundle-0004.json + attestation-bundle-0004-seller.json; HTLC-9 bundle ref points to conformance/fixtures/attestation-bundle-htlc9.json",
  };
}

// ── §8.7 — DACS-X step 3: arbitrator transcript-disclosure (DP-1) ────────────
// Realises the §8.7 hook ("DACS-X dispute MAY require selective transcript
// disclosure under signed party agreement or arbitrator order") under steward
// sign-off DP-1: full transcript → named arbitrator only, no presentable artifact.
{
  const NOW = 1_780_000_000_000;
  const buyer = keypairFromSeed("a1".repeat(32));
  const seller = keypairFromSeed("c3".repeat(32));
  const arbitrator = keypairFromSeed("b2".repeat(32));
  const buyerClaim = "did:demos:buyer", sellerClaim = "did:demos:seller", arbitratorClaim = "did:arbitrator:court";
  const transcriptSep = DOMAIN_SEPARATOR_REGISTRY["dacs-3-transcript"];
  const grantSep = dacsXSeparator("dacs-x-disclosure-grant");
  const requirement: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }], primaryClaimSelector: "did" };
  const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
  const ruleRef = sha256Hex(canonicalize(agreedRule));
  const recUnsigned: Omit<DisputeRecord, "signature"> = {
    dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim, disputed: [
      { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
      { jobId: bundle0004Seller.bundle.jobId, bundleHash: bundle0004Seller.bundleHash },
    ],
    contestedClaim: "divergent-bundle", requestedRemedy: "reputation-correction", arbitration: { ruleRef }, openedAt: NOW,
  };
  const record: DisputeRecord = { ...recUnsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), recUnsigned as unknown as Record<string, unknown>, buyer.privateKey) };

  const buildTranscript = (sellerSig?: string): ChannelTranscript => {
    const base: Omit<ChannelTranscript, "signatures"> = {
      transcriptVersion: "1", channelId: "subnet-7", members: [buyerClaim, sellerClaim],
      messages: [{ sequence: 1, author: buyerClaim, envelopeHash: sha256Hex("offer") }, { sequence: 2, author: sellerClaim, envelopeHash: sha256Hex("counter") }],
      generatedAt: NOW - 5000,
    };
    const sign = (kp: Keypair) => signArtifact(transcriptSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
    return { ...base, signatures: [{ signer: buyerClaim, signature: sign(buyer) }, { signer: sellerClaim, signature: sellerSig ?? sign(seller) }] };
  };
  const transcript = buildTranscript();
  const buildGrant = (authority: DisclosureAuthority, signers: [ClaimReference, Keypair][], over: Partial<DisclosureGrant> = {}): DisclosureGrant => {
    const base: Omit<DisclosureGrant, "signatures"> = {
      dacsXVersion: "1", disputeId: "d1", disputeRecordHash: disputeRecordHash(record),
      transcriptHash: transcriptContentHash(transcript), recipient: arbitratorClaim, authority, grantedAt: NOW + 500, ...over,
    };
    const sign = (kp: Keypair) => signArtifact(grantSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
    return { ...base, signatures: signers.map(([signer, kp]) => ({ signer, signature: sign(kp) })) };
  };
  const memberKeys: Record<ClaimReference, Uint8Array> = { [buyerClaim]: buyer.publicKeyRaw, [sellerClaim]: seller.publicKeyRaw };
  const di = (grant: DisclosureGrant, over: Partial<DisclosureInput> = {}): DisclosureInput => ({ grant, transcript, record, agreedRule, recipientPublicKeyRaw: arbitrator.publicKeyRaw, memberKeys, now: NOW + 500, ...over });
  const decide = (input: DisclosureInput): string => { try { return verifyTranscriptDisclosure(input).ok ? "pass" : "fail"; } catch { return "error"; } };

  rec("disclosure-party-agreement-pass", "disclosure", "§8.7", "all channel members co-sign → transcript disclosure to the named arbitrator authorized",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]]))), "pass");
  rec("disclosure-arbitrator-order-pass", "disclosure", "§8.7", "the credentialed arbitrator orders disclosure → authorized",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]]))), "pass");
  rec("disclosure-wrong-recipient-fail", "disclosure", "§8.7", "DP-1 named-arbitrator-only: a recipient not in the agreed arbitrator allow-set → FAIL",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { recipient: "did:rando:x" }))), "fail");
  const rando = keypairFromSeed("d4".repeat(32));
  const swappedRule: ArbitrationRule = { requirement, arbitrators: ["did:rando:x"], policyVersion: 2 };
  rec("disclosure-rule-swap-fail", "disclosure", "§8.7", "DP-1 anti-swap: an agreed rule whose hash ≠ the record's pinned ruleRef → FAIL (can't swap in a rule naming an attacker's recipient)",
    decide(di(buildGrant("arbitrator-order", [["did:rando:x", rando]], { recipient: "did:rando:x" }), { agreedRule: swappedRule, recipientPublicKeyRaw: rando.publicKeyRaw })), "fail");
  rec("disclosure-transcript-substitution-fail", "disclosure", "§8.7", "a grant pinning a different transcript hash → FAIL (the disclosed transcript can't be swapped)",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]], { transcriptHash: sha256Hex("other-transcript") }))), "fail");
  rec("disclosure-missing-consent-fail", "disclosure", "§8.7", "party-agreement missing a member's consent → FAIL (full consent required)",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer]]))), "fail");
  rec("disclosure-wrong-dispute-fail", "disclosure", "§8.7", "a grant not bound to the DisputeRecord → FAIL",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { disputeRecordHash: sha256Hex("nope") }))), "fail");
  rec("disclosure-malformed-key-error", "disclosure", "§8.7", "a non-32-byte member key → ERROR, not a false-negative FAIL",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]]), { memberKeys: { [buyerClaim]: new Uint8Array([1, 2, 3]), [sellerClaim]: seller.publicKeyRaw } })), "error");
  const forged = buildTranscript(buildTranscript().signatures[0]!.signature);
  rec("disclosure-transcript-unsigned-fail", "disclosure", "§8.7", "a transcript with an unverifiable member signature → FAIL (authenticity)",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { transcriptHash: transcriptContentHash(forged) }), { transcript: forged })), "fail");

  golden["disclosure"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    bundleRef: { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
    divergentBundleRefs: [
      { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
      { jobId: bundle0004Seller.bundle.jobId, bundleHash: bundle0004Seller.bundleHash },
    ],
    seeds: { buyer: "a1".repeat(32), seller: "c3".repeat(32), arbitrator: "b2".repeat(32), rando: "d4".repeat(32) },
    now: NOW,
    decisions: {
      partyAgreement: "pass", arbitratorOrder: "pass", wrongRecipient: "fail", ruleSwap: "fail", transcriptSubstitution: "fail",
      missingConsent: "fail", wrongDispute: "fail", malformedKey: "error", transcriptUnsigned: "fail",
    },
    inputs: "constructed deterministically in conformance/run.ts from the seeds above; dispute record points to conformance/fixtures/attestation-bundle-0004.json + attestation-bundle-0004-seller.json",
  };
}

// ── §14.4 — DACS-4 settlement evidence ──────────────────────────────────────
{
  const resolve = (claim: ClaimReference): Uint8Array | undefined => settlementKeys[claim];
  const signSettlement = (unsigned: Omit<SettlementEvidence, "signature">): SettlementEvidence => {
    const orchestrator = keypairFromSeed("e4".repeat(32));
    return {
      ...unsigned,
      signature: {
        algorithm: "ed25519",
        signer: SETTLEMENT_ORCHESTRATOR_CLAIM,
        value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, orchestrator.privateKey, ["signature"]),
      },
    };
  };
  const refreshRef = (result: PhaseHandlerResult, evidence: SettlementEvidence, paymentInput?: PaymentPhaseInput): PhaseHandlerResult => {
    const currentId = result.attestationRef?.id;
    const nextId = paymentInput !== undefined && currentId?.startsWith("dacs4:payment:")
      ? paymentEvidenceAddress(evidence.jobId, paymentInput.rail.railId, evidence.phaseIndex, currentId.endsWith(":resolved"))
      : currentId;
    return {
      ...result,
      attestationRef: {
        ...result.attestationRef!,
        ...(nextId !== undefined ? { id: nextId } : {}),
        contentHash: evidenceHash(evidence),
      },
    };
  };
  const paymentCase = (over: {
    result?: Partial<PhaseHandlerResult>;
    evidence?: Partial<Omit<SettlementEvidence, "signature">>;
    paymentInput?: (input: PaymentPhaseInput) => PaymentPhaseInput;
    refreshHash?: boolean;
  } = {}) => {
    const { signature: _signature, ...unsignedBase } = settlementPayment.evidence;
    const evidence = signSettlement({ ...unsignedBase, ...over.evidence });
    const paymentInput = over.paymentInput?.(settlementPayment.paymentInput) ?? settlementPayment.paymentInput;
    const resultBase = over.refreshHash === false ? settlementPayment.result : refreshRef(settlementPayment.result, evidence, paymentInput);
    const result = { ...resultBase, ...over.result };
    return { result, evidence, paymentInput };
  };
  const htlcParameters = {
    timelockSourceSec: 3_600,
    timelockDestSec: 1_800,
    sourceFinalitySec: 900,
    safetyWindowSec: 600,
  };
  const htlcRail = (parameters: Record<string, unknown> = htlcParameters): RailDefinition => ({
    railVersion: 1,
    railId: "sepolia-polygon-htlc-usdc",
    railType: "cross-chain-htlc",
    asset: {
      kind: "stablecoin-cross-chain",
      canonicalSymbol: "USDC",
      routes: [{ sourceChainId: "eip155:11155111", destChainId: "eip155:80002" }],
    },
    network: { kind: "cross-chain", mechanism: "htlc" },
    phaseHandler: "pay-cross-chain-htlc",
    parameters,
    availability: "mocked",
    governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
    signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-htlc-rail-signature" },
  });
  const htlcPaymentCase = (parameters: Record<string, unknown> = htlcParameters) => paymentCase({
    evidence: {
      phase: "pay-cross-chain-htlc",
      settlementFinality: { model: "htlc-reveal", finalityObservedAt: 1_780_014_501_000 },
      paymentTxRefs: [{ rail: "sepolia-polygon-htlc-usdc", txHash: "polygon-amoy:0xhtlc-reveal-0001", kind: "htlc-reveal" }],
    },
    result: {
      txRefs: [{ rail: "sepolia-polygon-htlc-usdc", txHash: "polygon-amoy:0xhtlc-reveal-0001", kind: "htlc-reveal" }],
    },
    paymentInput: (input) => ({ ...input, rail: htlcRail(parameters) }),
  });
  const liquidityTankPaymentCase = () => paymentCase({
    evidence: {
      phase: "pay-cross-chain-liquidity-tank",
      settlementFinality: { model: "liquidity-tank", finalityObservedAt: 1_780_014_502_000 },
      paymentTxRefs: [{ rail: "base-arbitrum-tank-usdc", txHash: "arbitrum:0xtank-completed-0001", kind: "liquidity-tank-completed" }],
    },
    result: {
      txRefs: [{ rail: "base-arbitrum-tank-usdc", txHash: "arbitrum:0xtank-completed-0001", kind: "liquidity-tank-completed" }],
    },
    paymentInput: (input) => ({
      ...input,
      rail: {
        railVersion: 1,
        railId: "base-arbitrum-tank-usdc",
        railType: "cross-chain-liquidity-tank",
        asset: {
          kind: "stablecoin-cross-chain",
          canonicalSymbol: "USDC",
          routes: [{ sourceChainId: "eip155:8453", destChainId: "eip155:42161" }],
        },
        network: { kind: "cross-chain", mechanism: "liquidity-tank" },
        phaseHandler: "pay-cross-chain-liquidity-tank",
        parameters: { routeId: "base-arbitrum-usdc" },
        availability: "mocked",
        governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
        signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-tank-rail-signature" },
      },
    }),
  });
  // pay-x402 (§9.5.7): x402 settles a gasless USDC transfer on its settlement chain (e.g. Base), so the record is
  // chain-verifiable via the settlement tx exactly like the evm rail — block-depth finality, asset unconstrained by
  // RD-5 (only network.kind == "x402-resource" is pinned). USDC/erc20-on-Base here.
  const x402PaymentCase = () => paymentCase({
    evidence: {
      phase: "pay-x402",
      settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1_780_014_503_000 },
      paymentTxRefs: [{
        rail: "base-usdc-x402",
        txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        kind: "payment",
        chainId: 8453,
        logIndex: 3,
      }],
    },
    result: {
      txRefs: [{
        rail: "base-usdc-x402",
        txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        kind: "payment",
        chainId: 8453,
        logIndex: 3,
      }],
    },
    paymentInput: (input) => ({
      ...input,
      rail: {
        railVersion: 1,
        railId: "base-usdc-x402",
        railType: "x402",
        asset: { kind: "erc20", chainId: 8453, contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6 },
        network: { kind: "x402-resource", resourceBaseUrl: "https://pay.example/x402/resource" },
        phaseHandler: "pay-x402",
        parameters: { finalityBlocks: 1 },
        availability: "live",
        governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
        signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-x402-rail-signature" },
      },
    }),
  });
  const x402ProviderReceiptPaymentCase = () => {
    const txRef = { rail: "base-usdc-x402", txHash: "provider-receipt:pay.example:receipt-0001", kind: "provider-receipt" };
    return paymentCase({
      evidence: {
        phase: "pay-x402",
        settlementFinality: { model: "provider-receipt", finalityObservedAt: 1_780_014_503_000 },
        paymentTxRefs: [txRef],
      },
      result: {
        txRefs: [txRef],
      },
      paymentInput: (input) => ({
        ...input,
        rail: {
          railVersion: 1,
          railId: "base-usdc-x402",
          railType: "x402",
          asset: { kind: "erc20", chainId: 8453, contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6 },
          network: { kind: "x402-resource", resourceBaseUrl: "https://pay.example/x402/resource" },
          phaseHandler: "pay-x402",
          parameters: { finalityBlocks: 1 },
          availability: "live",
          governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
          signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-x402-rail-signature" },
        },
      }),
    });
  };
  const x402MissingEventCoordinatesCase = () => {
    const txRef = {
      rail: "base-usdc-x402",
      txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      kind: "payment",
    };
    return paymentCase({
      evidence: {
        phase: "pay-x402",
        settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1_780_014_504_000 },
        paymentTxRefs: [txRef],
      },
      result: {
        txRefs: [txRef],
      },
      paymentInput: (input) => ({
        ...input,
        rail: {
          railVersion: 1,
          railId: "base-usdc-x402",
          railType: "x402",
          asset: { kind: "erc20", chainId: 8453, contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6 },
          network: { kind: "x402-resource", resourceBaseUrl: "https://pay.example/x402/resource" },
          phaseHandler: "pay-x402",
          parameters: { finalityBlocks: 1 },
          availability: "live",
          governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
          signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-x402-rail-signature" },
        },
      }),
    });
  };
  const x402BlockDepthReceiptKindCase = () => {
    const txRef = {
      rail: "base-usdc-x402",
      txHash: "provider-receipt:pay.example:receipt-0002",
      kind: "provider-receipt",
    };
    return paymentCase({
      evidence: {
        phase: "pay-x402",
        settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1_780_014_504_500 },
        paymentTxRefs: [txRef],
      },
      result: {
        txRefs: [txRef],
      },
      paymentInput: (input) => ({
        ...input,
        rail: {
          railVersion: 1,
          railId: "base-usdc-x402",
          railType: "x402",
          asset: { kind: "erc20", chainId: 8453, contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6 },
          network: { kind: "x402-resource", resourceBaseUrl: "https://pay.example/x402/resource" },
          phaseHandler: "pay-x402",
          parameters: { finalityBlocks: 1 },
          availability: "live",
          governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
          signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-x402-rail-signature" },
        },
      }),
    });
  };
  const decide = (input: { result: PhaseHandlerResult; evidence: SettlementEvidence; expectedOrchestrator?: ClaimReference; paymentInput?: PaymentPhaseInput; resolveKey?: (claim: ClaimReference) => Uint8Array | null | undefined }): string =>
    verifySettlementEvidence({
      result: input.result,
      evidence: input.evidence,
      expectedOrchestrator: input.expectedOrchestrator ?? SETTLEMENT_ORCHESTRATOR_CLAIM,
      ...(input.paymentInput !== undefined ? { paymentInput: input.paymentInput } : {}),
      resolveKey: input.resolveKey ?? resolve,
    });

  rec("settlement-payment-pass", "settlement", "§14.4", "pay-evm-erc20 success evidence passes PC-1..PC-6 + dacs-4-evidence signature",
    decide(settlementPayment), "pass");
  rec("settlement-x402-pass", "settlement", "§9.5.7", "pay-x402 success evidence (gasless USDC on Base, block-depth finality, chain-verifiable like the evm rail) passes PC-1..PC-6 + dacs-4-evidence signature",
    decide(x402PaymentCase()), "pass");
  rec("settlement-x402-provider-receipt-pass", "settlement", "§9.5.7", "pay-x402 provider-receipt fallback without settlement-chain event coordinates remains accepted",
    {
      settlement: decide(x402ProviderReceiptPaymentCase()),
      uniqueness: verifySettlementTxUniqueness([x402ProviderReceiptPaymentCase().evidence]).decision,
    },
    { settlement: "pass", uniqueness: "pass" });
  rec("settlement-x402-block-depth-missing-event-coordinates-fail", "settlement", "§9.5.8 SB-1/SB-2", "pay-x402 block-depth settlement refs without chainId+logIndex fail instead of falling back to a legacy key",
    {
      settlement: decide(x402MissingEventCoordinatesCase()),
      uniqueness: verifySettlementTxUniqueness([x402MissingEventCoordinatesCase().evidence]).decision,
    },
    { settlement: "fail", uniqueness: "error" });
  rec("settlement-x402-block-depth-provider-receipt-kind-fail", "settlement", "§9.5.8 SB-1/SB-2", "pay-x402 block-depth settlement refs cannot use provider-receipt fallback kind",
    {
      settlement: decide(x402BlockDepthReceiptKindCase()),
      uniqueness: verifySettlementTxUniqueness([x402BlockDepthReceiptKindCase().evidence]).decision,
    },
    { settlement: "fail", uniqueness: "error" });
  rec("settlement-delivery-pass", "settlement", "§14.4", "deliver-storage-program success evidence passes with deliverable anchor and no settlementFinality",
    decide(settlementDelivery), "pass");

  const currencyMismatch = paymentCase({
    evidence: { paymentAmount: { amount: "5", currency: "DAI" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "5", currency: "DAI" } }),
  });
  rec("settlement-currency-mismatch-not-rejected-fail", "settlement", "§9.5.1 PC-5", "amount.currency not resolved by rail.asset and handler settled → FAIL",
    decide(currencyMismatch), "fail");

  rec("settlement-success-payment-missing-finality-fail", "settlement", "§9.7 PC-6", "success payment evidence missing settlementFinality → FAIL",
    decide(paymentCase({ evidence: { settlementFinality: undefined } })), "fail");

  const { signature: _deliverySignature, ...deliveryUnsigned } = settlementDelivery.evidence;
  const deliveryWithFinality = signSettlement({
    ...deliveryUnsigned,
    settlementFinality: { model: "provider-receipt", finalityObservedAt: 1_780_014_500_000 },
  });
  rec("settlement-delivery-with-finality-fail", "settlement", "§9.7 PC-6", "delivery evidence carrying settlementFinality → FAIL",
    decide({ result: refreshRef(settlementDelivery.result, deliveryWithFinality), evidence: deliveryWithFinality }), "fail");

  rec("settlement-ok-true-errorclass-fail", "settlement", "§9.5.1 PC-4", "ok:true with errorClass present → FAIL",
    decide(paymentCase({ result: { errorClass: "permanent" } })), "fail");

  rec("settlement-ok-false-no-errorclass-fail", "settlement", "§9.5.1 PC-4", "ok:false without errorClass → FAIL",
    decide(paymentCase({
      result: { ok: false, errorClass: undefined },
      evidence: { outcome: "failure", reason: "rail-rejected", settlementFinality: undefined },
    })), "fail");

  rec("settlement-wrong-anchor-fail", "settlement", "§9.5.1 PC-2", "result.attestationRef id not at expected dacs4 payment anchor → FAIL",
    decide(paymentCase({ result: { attestationRef: { ...settlementPayment.result.attestationRef!, id: "dacs4:payment:wrong:rail" } } })), "fail");

  const colonRail = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "evm-erc20:1:USDC", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "evm-erc20:1:USDC", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    paymentInput: (input) => ({ ...input, rail: { ...input.rail, railId: "evm-erc20:1:USDC" } }),
  });
  rec("cf4-dacs4-payment-address", "settlement", "§6.3.4 CF-4", "dacs4 payment evidence address encodes a colon-bearing railId while phaseIndex stays structural",
    {
      address: colonRail.result.attestationRef?.id,
      decision: decide(colonRail),
    },
    {
      address: paymentEvidenceAddress(colonRail.evidence.jobId, "evm-erc20:1:USDC", colonRail.evidence.phaseIndex),
      decision: "pass",
    });

  const sb2Base = paymentCase();
  const sb2CrossJob = paymentCase({ evidence: { jobId: "DACS-VERIFY-SETTLE-0002" } });
  const sb2CrossPhase = paymentCase({ evidence: { phaseIndex: 1 } });
  rec("settlement-sb1-evm-event-txid-normalisation", "settlement", "§9.5.8 SB-1", "EVM settlement-tx-id is event-level and normalises optional 0x / uppercase spelling",
    [
      settlementTxId({ rail: "polygon-amoy-usdc", txHash: "0xABCDEF0000000000000000000000000000000000000000000000000000000001", kind: "payment", chainId: 80002, logIndex: 7 }),
      settlementTxId({ rail: "polygon-amoy-usdc", txHash: "abcdef0000000000000000000000000000000000000000000000000000000001", kind: "payment", chainId: "80002", logIndex: 7 }),
    ],
    [
      "evm:80002:abcdef0000000000000000000000000000000000000000000000000000000001:7",
      "evm:80002:abcdef0000000000000000000000000000000000000000000000000000000001:7",
    ]);
  rec("settlement-sb1-solana-instruction-txid", "settlement", "§9.5.8 SB-1", "Solana settlement-tx-id is instruction-level",
    settlementTxId({ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "devnet", signature: SOLANA_SIGNATURE_64B, instructionIndex: 2 }),
    `solana:devnet:${SOLANA_SIGNATURE_64B}:2`);
  rec("settlement-sb1-solana-signature-alias-error", "settlement", "§9.5.8 SB-1", "Solana txHash and optional signature must name the same transaction signature",
    throwResult(() => settlementTxId({
      rail: "solana-devnet-usdc",
      txHash: SOLANA_SIGNATURE_64B,
      kind: "payment",
      cluster: "devnet",
      signature: SOLANA_OTHER_SIGNATURE_64B,
      instructionIndex: 2,
    }, "pay-solana-spl"), /signature must match txHash/),
    "throws");
  rec("settlement-sb1-solana-invalid-signature-error", "settlement", "§9.5.8 SB-1", "Solana signatures must be base58 and decode to exactly 64 bytes",
    [
      throwResult(() => settlementTxId({ rail: "solana-devnet-usdc", txHash: "not-base58-0OIl", kind: "payment", cluster: "devnet", signature: "not-base58-0OIl", instructionIndex: 2 }, "pay-solana-spl"), /decode to exactly 64 bytes/),
      throwResult(() => settlementTxId({ rail: "solana-devnet-usdc", txHash: "z".repeat(89), kind: "payment", cluster: "devnet", signature: "z".repeat(89), instructionIndex: 2 }, "pay-solana-spl"), /decode to exactly 64 bytes/),
      throwResult(() => settlementTxId({ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_63B, kind: "payment", cluster: "devnet", signature: SOLANA_SIGNATURE_63B, instructionIndex: 2 }, "pay-solana-spl"), /decode to exactly 64 bytes/),
      throwResult(() => settlementTxId({ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_65B, kind: "payment", cluster: "devnet", signature: SOLANA_SIGNATURE_65B, instructionIndex: 2 }, "pay-solana-spl"), /decode to exactly 64 bytes/),
    ],
    ["throws", "throws", "throws", "throws"]);
  rec("settlement-sb1-solana-cluster-alias-error", "settlement", "§9.5.8 SB-1", "Solana cluster aliases such as mainnet-beta are rejected instead of normalised",
    throwResult(() => settlementTxId({ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "mainnet-beta", signature: SOLANA_SIGNATURE_64B, instructionIndex: 2 }, "pay-solana-spl"), /cluster is required/),
    "throws");
  rec("settlement-sb1-mixed-coordinate-family-error", "settlement", "§9.5.8 SB-1", "settlement refs carrying both EVM and Solana coordinates are rejected instead of guessed",
    throwResult(() => settlementTxId({
      rail: "solana-devnet-usdc",
      txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      kind: "payment",
      chainId: 80002,
      logIndex: 0,
      cluster: "devnet",
      signature: SOLANA_SIGNATURE_64B,
      instructionIndex: 2,
    }, "pay-solana-spl"), /must not be mixed/),
    "throws");
  rec("settlement-sb2-malformed-event-ref-error", "settlement", "§9.5.8 SB-1/SB-2", "malformed event-level settlement refs return ERROR instead of minting a distinct consumed-set key",
    verifySettlementTxUniqueness([paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }] },
    }).evidence]).decision,
    "error");
  rec("settlement-sb2-evm-missing-event-coordinates-error", "settlement", "§9.5.8 SB-1/SB-2", "EVM/x402 settlement refs without chainId+logIndex return ERROR instead of falling back to a legacy key",
    verifySettlementTxUniqueness([paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }] },
    }).evidence]).decision,
    "error");
  rec("settlement-sb2-solana-signature-alias-error", "settlement", "§9.5.8 SB-1/SB-2", "Solana signature aliases return ERROR instead of splitting one instruction into multiple keys",
    verifySettlementTxUniqueness([paymentCase({
      evidence: {
        phase: "pay-solana-spl",
        paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "devnet", signature: SOLANA_OTHER_SIGNATURE_64B, instructionIndex: 0 }],
      },
      result: {
        txRefs: [{ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "devnet", signature: SOLANA_OTHER_SIGNATURE_64B, instructionIndex: 0 }],
      },
    }).evidence]).decision,
    "error");
  rec("settlement-sb2-solana-malformed-ref-error", "settlement", "§9.5.8 SB-1/SB-2", "Malformed Solana refs return ERROR instead of minting consumed-set keys",
    [
      verifySettlementTxUniqueness([paymentCase({ evidence: { phase: "pay-solana-spl", paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: "not-base58-0OIl", kind: "payment", cluster: "devnet", signature: "not-base58-0OIl", instructionIndex: 0 }] } }).evidence]).decision,
      verifySettlementTxUniqueness([paymentCase({ evidence: { phase: "pay-solana-spl", paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: "z".repeat(89), kind: "payment", cluster: "devnet", signature: "z".repeat(89), instructionIndex: 0 }] } }).evidence]).decision,
      verifySettlementTxUniqueness([paymentCase({ evidence: { phase: "pay-solana-spl", paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_63B, kind: "payment", cluster: "devnet", signature: SOLANA_SIGNATURE_63B, instructionIndex: 0 }] } }).evidence]).decision,
      verifySettlementTxUniqueness([paymentCase({ evidence: { phase: "pay-solana-spl", paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_65B, kind: "payment", cluster: "devnet", signature: SOLANA_SIGNATURE_65B, instructionIndex: 0 }] } }).evidence]).decision,
      verifySettlementTxUniqueness([paymentCase({ evidence: { phase: "pay-solana-spl", paymentTxRefs: [{ rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "mainnet-beta", signature: SOLANA_SIGNATURE_64B, instructionIndex: 0 }] } }).evidence]).decision,
    ],
    ["error", "error", "error", "error", "error"]);
  rec("settlement-sb2-evm-chainid-nonminimal-error", "settlement", "§9.5.8 SB-1/SB-2", "EVM chainId string spelling must be minimal decimal, so leading-zero aliases return ERROR",
    verifySettlementTxUniqueness([paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: "080002", logIndex: 0 }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: "080002", logIndex: 0 }] },
    }).evidence]).decision,
    "error");
  rec("settlement-sb2-duplicate-txid-cross-job-fail", "settlement", "§9.5.8 SB-2", "consumer-scoped SB-2: one settlement-tx-id counted under two jobIds → FAIL",
    verifySettlementTxUniqueness([sb2Base.evidence, sb2CrossJob.evidence]), {
      decision: "fail",
      conflict: {
        settlementTxId: settlementTxId(sb2Base.evidence.paymentTxRefs![0]!),
        first: { jobId: sb2Base.evidence.jobId, phaseIndex: sb2Base.evidence.phaseIndex },
        second: { jobId: sb2CrossJob.evidence.jobId, phaseIndex: sb2CrossJob.evidence.phaseIndex },
      },
      consumed: [{ settlementTxId: settlementTxId(sb2Base.evidence.paymentTxRefs![0]!), jobId: sb2Base.evidence.jobId, phaseIndex: sb2Base.evidence.phaseIndex }],
    });
  rec("settlement-sb2-same-job-cross-phase-fail", "settlement", "§9.5.8 SB-2", "consumer-scoped SB-2: one settlement-tx-id counted under two phaseIndex values for the same job → FAIL",
    verifySettlementTxUniqueness([sb2Base.evidence, sb2CrossPhase.evidence]).decision, "fail");
  rec("settlement-sb2-same-obligation-idempotent-pass", "settlement", "§9.5.8 SB-2", "consumer-scoped SB-2: repeated evidence for the same (settlement-tx-id, jobId, phaseIndex) is idempotent → PASS",
    verifySettlementTxUniqueness([sb2Base.evidence, sb2Base.evidence]), {
      decision: "pass",
      consumed: [{ settlementTxId: settlementTxId(sb2Base.evidence.paymentTxRefs![0]!), jobId: sb2Base.evidence.jobId, phaseIndex: sb2Base.evidence.phaseIndex }],
    });
  rec("settlement-sb2-separate-consumer-views-pass", "settlement", "§9.5.8 SB-2", "SB-2 scope is the consumer's own reconciliation set; separate one-record views each pass",
    [verifySettlementTxUniqueness([sb2Base.evidence]).decision, verifySettlementTxUniqueness([sb2CrossJob.evidence]).decision], ["pass", "pass"]);

  rec("settlement-attestationref-hash-mismatch-fail", "settlement", "§9.5.1 PC-3", "result.attestationRef contentHash not equal evidenceHash(evidence) → FAIL",
    decide(paymentCase({ refreshHash: false, evidence: { paymentAmount: { amount: "6", currency: "USDC" } } })), "fail");

  rec("settlement-failure-no-reason-fail", "settlement", "§9.7", "failure evidence without non-empty reason → FAIL",
    decide(paymentCase({
      result: { ok: false, errorClass: "permanent" },
      evidence: { outcome: "failure", reason: undefined, settlementFinality: undefined },
    })), "fail");

  const wrong = keypairFromSeed("f5".repeat(32));
  rec("settlement-wrong-signer-key-fail", "settlement", "§9.7", "resolved key is well-formed but not the signing key → FAIL",
    decide({ ...settlementPayment, resolveKey: () => wrong.publicKeyRaw }), "fail");

  rec("settlement-malformed-key-error", "settlement", "§9.7", "resolved signer key is not 32 bytes → ERROR",
    decide({ ...settlementPayment, resolveKey: () => new Uint8Array([1, 2, 3]) }), "error");

  rec("settlement-unresolvable-key-indeterminate", "settlement", "§9.7", "signer key cannot be resolved → INDETERMINATE",
    decide({ ...settlementPayment, resolveKey: () => undefined }), "indeterminate");

  rec("settlement-phase-rail-mismatch-fail", "settlement", "§9.4.1/§9.14", "evidence.phase (pay-solana-spl) ≠ pinned rail.phaseHandler (pay-evm-erc20) → FAIL",
    decide(paymentCase({ evidence: { phase: "pay-solana-spl" } })), "fail");

  rec("settlement-txrefs-mismatch-fail", "settlement", "§9.5.1 PC-1/PC-3", "handler-return txRefs ≠ signed evidence.paymentTxRefs → FAIL (signature covers paymentTxRefs only)",
    decide(paymentCase({ result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xUNSIGNED", kind: "payment" }] } })), "fail");

  rec("settlement-malformed-evm-event-ref-fail", "settlement", "§9.5.8 SB-1", "pay-evm-erc20 success evidence with malformed event txHash → FAIL",
    decide(paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }] },
    })), "fail");

  const prefixedEvmEventRef = paymentCase({
    evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }] },
    result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }] },
  });
  rec("settlement-prefixed-evm-event-ref-fail-error", "settlement", "§9.5.8 SB-1/SB-2", "EVM event txHash with a legacy chain prefix is malformed: verifier FAIL, SB-2 ERROR",
    {
      settlement: decide(prefixedEvmEventRef),
      uniqueness: verifySettlementTxUniqueness([prefixedEvmEventRef.evidence]).decision,
    },
    { settlement: "fail", uniqueness: "error" });

  rec("settlement-missing-evm-event-coordinates-fail", "settlement", "§9.5.8 SB-1", "pay-evm-erc20 success evidence without chainId+logIndex event coordinates → FAIL",
    decide(paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }] },
    })), "fail");

  rec("settlement-event-chainid-rail-mismatch-fail", "settlement", "§9.5.8 SB-1", "pay-evm-erc20 event chainId must match the selected rail chainId → FAIL",
    decide(paymentCase({
      evidence: { paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 1, logIndex: 0 }] },
      result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 1, logIndex: 0 }] },
    })), "fail");

  rec("settlement-event-railid-mismatch-fail", "settlement", "§9.5.8 SB-1", "payment txRef.rail must match the selected railId even when event coordinates match → FAIL",
    decide(paymentCase({
      evidence: { paymentTxRefs: [{ rail: "other-polygon-rail", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }] },
      result: { txRefs: [{ rail: "other-polygon-rail", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }] },
    })), "fail");

  const solanaWrongClusterTxRef = { rail: "solana-devnet-usdc", txHash: SOLANA_SIGNATURE_64B, kind: "payment", cluster: "mainnet", signature: SOLANA_SIGNATURE_64B, instructionIndex: 0 } as const;
  rec("settlement-event-cluster-rail-mismatch-fail", "settlement", "§9.5.8 SB-1", "pay-solana-spl event cluster must match the selected rail cluster → FAIL",
    decide(paymentCase({
      evidence: {
        phase: "pay-solana-spl",
        settlementFinality: { model: "commitment-level", finalityCommitmentLevel: "confirmed", finalityObservedAt: 1_780_014_505_000 },
        paymentTxRefs: [solanaWrongClusterTxRef],
      },
      result: { txRefs: [solanaWrongClusterTxRef] },
      paymentInput: (input) => ({
        ...input,
        rail: {
          railVersion: 1,
          railId: "solana-devnet-usdc",
          railType: "solana-spl",
          asset: { kind: "spl", cluster: "devnet", mint: "Es9vMFrzaCERexampleMint", symbol: "USDC", decimals: 6 },
          network: { kind: "solana", cluster: "devnet" },
          phaseHandler: "pay-solana-spl",
          parameters: { commitmentLevel: "confirmed" },
          availability: "mocked",
          governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
          signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-solana-rail-signature" },
        },
      }),
    })), "fail");

  rec("settlement-noncanonical-amount-fail", "settlement", "§14.4 CD-1", "non-canonical PriceTerm.amount (\"1.50\") → FAIL (CD-1 minimal-form)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "1.50", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "1.50", currency: "USDC" } }) })), "fail");

  rec("settlement-nonpositive-amount-fail", "settlement", "§9.3", "non-positive PriceTerm.amount (\"0\") → FAIL (amount MUST be > 0)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "0", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "0", currency: "USDC" } }) })), "fail");

  rec("settlement-wrong-attestation-kind-fail", "settlement", "§9.5.1 PC-3", "attestationRef.kind ≠ dacs-4-evidence (mislabelled as dacs-5-bundle) → FAIL",
    decide(paymentCase({ result: { attestationRef: { ...settlementPayment.result.attestationRef!, kind: "dacs-5-bundle" } } })), "fail");

  // signer ≠ authorized orchestrator: signed by an attacker DID whose key resolves, but not the expected orchestrator.
  const attacker = keypairFromSeed("99".repeat(32));
  const { signature: _attackerSig, ...attackerUnsigned } = settlementPayment.evidence;
  const attackerEvidence: SettlementEvidence = {
    ...attackerUnsigned,
    signature: { algorithm: "ed25519", signer: "did:attacker:x", value: signArtifact("dacs-evidence:v1:", attackerUnsigned as unknown as Record<string, unknown>, attacker.privateKey, ["signature"]) },
  };
  rec("settlement-non-orchestrator-signer-fail", "settlement", "§9.7", "evidence signed by a non-orchestrator claim (key resolves) ≠ expected orchestrator → FAIL",
    decide({ result: refreshRef(settlementPayment.result, attackerEvidence), evidence: attackerEvidence, paymentInput: settlementPayment.paymentInput, resolveKey: (c) => (c === "did:attacker:x" ? attacker.publicKeyRaw : resolve(c)) }), "fail");

  rec("settlement-success-missing-paymenttxrefs-fail", "settlement", "§9.5.2", "success payment evidence omitting paymentTxRefs → FAIL (audit value)",
    decide(paymentCase({ result: { txRefs: undefined }, evidence: { paymentTxRefs: undefined } })), "fail");

  rec("settlement-success-missing-paymentamount-fail", "settlement", "§9.7", "success payment evidence omitting paymentAmount → FAIL (actual settled amount required)",
    decide(paymentCase({ evidence: { paymentAmount: undefined } })), "fail");

  const { signature: _delMissingSig, ...delMissingUnsigned } = settlementDelivery.evidence;
  const deliveryMissingDeliverable = signSettlement({ ...delMissingUnsigned, deliverableContentHash: undefined, deliverableAnchor: undefined });
  rec("settlement-delivery-missing-deliverable-fail", "settlement", "§9.6", "deliver-storage-program success omitting deliverableContentHash/anchor → FAIL",
    decide({ result: refreshRef(settlementDelivery.result, deliveryMissingDeliverable), evidence: deliveryMissingDeliverable }), "fail");

  const deliveryBadHash = signSettlement({ ...delMissingUnsigned, deliverableContentHash: "not-a-hash" });
  rec("settlement-delivery-malformed-contenthash-fail", "settlement", "§9.6", "delivery deliverableContentHash not 64-hex (\"not-a-hash\") → FAIL (content-addressing)",
    decide({ result: refreshRef(settlementDelivery.result, deliveryBadHash), evidence: deliveryBadHash }), "fail");

  rec("settlement-storage-anchored-as-entitlement-fail", "settlement", "§9.6", "deliver-storage-program anchored at dacs4:entitlement namespace → FAIL (phase-specific anchor)",
    decide({ result: { ...settlementDelivery.result, attestationRef: { ...settlementDelivery.result.attestationRef!, id: `dacs4:entitlement:${settlementDelivery.evidence.jobId}:0` } }, evidence: settlementDelivery.evidence }), "fail");

  rec("settlement-negative-fee-fail", "settlement", "§9.7", "negative paymentFee (\"-1\") → FAIL (a fee may be 0, never negative)",
    decide(paymentCase({ evidence: { paymentFee: { amount: "-1", currency: "USDC" } } })), "fail");

  rec("settlement-underpayment-vs-agreement-fail", "settlement", "§9.5.1/PIPE-5", "paymentInput.amount (1 USDC) ≠ agreement.terms.price (5 USDC) → FAIL (underpayment)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "1", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "1", currency: "USDC" } }) })), "fail");

  rec("settlement-incoherent-rail-type-handler-fail", "settlement", "§9.4.3 RD-5", "rail railType evm-erc20 with phaseHandler pay-solana-spl → FAIL (incoherent rail)",
    decide(paymentCase({ evidence: { phase: "pay-solana-spl" }, paymentInput: (i) => ({ ...i, rail: { ...i.rail, phaseHandler: "pay-solana-spl" } }) })), "fail");

  rec("settlement-rail-network-mismatch-fail", "settlement", "§9.4.3 RD-5", "evm-erc20 rail with a solana network → FAIL (railType↔asset/network coherence)",
    decide(paymentCase({ paymentInput: (i) => ({ ...i, rail: { ...i.rail, network: { kind: "solana", cluster: "mainnet" } } }) })), "fail");

  rec("settlement-htlc-finality-params-pass", "settlement", "§9.5.4 HTLC-7", "HTLC rail pins timelockSourceSec/timelockDestSec/sourceFinalitySec/safetyWindowSec and satisfies source-margin inequality → PASS",
    decide(htlcPaymentCase()), "pass");

  const { sourceFinalitySec: _sourceFinalitySec, ...missingSourceFinality } = htlcParameters;
  rec("settlement-htlc-missing-source-finality-fail", "settlement", "§9.5.4 HTLC-7", "HTLC rail missing required sourceFinalitySec → FAIL",
    decide(htlcPaymentCase(missingSourceFinality)), "fail");

  const { safetyWindowSec: _safetyWindowSec, ...missingSafetyWindow } = htlcParameters;
  rec("settlement-htlc-missing-safety-window-fail", "settlement", "§9.5.4 HTLC-7", "HTLC rail missing required safetyWindowSec → FAIL",
    decide(htlcPaymentCase(missingSafetyWindow)), "fail");

  rec("settlement-htlc-insufficient-margin-fail", "settlement", "§9.5.4 HTLC-7", "HTLC source timelock not greater than dest timelock + source finality + safety → FAIL",
    decide(htlcPaymentCase({ ...htlcParameters, timelockSourceSec: 3_300 })), "fail");

  const anchorPendingTank = liquidityTankPaymentCase();
  const { attestationRef: _anchorPendingRef, ...anchorPendingResult } = anchorPendingTank.result;
  rec("settlement-cross-chain-anchor-pending-pass", "settlement", "§9.5.1 PC-7", "cross-chain payment with irreversible foreign-chain value movement may return ok:true + txRefs while SR-2 anchoring is pending",
    decide({ ...anchorPendingTank, result: anchorPendingResult }), "pass");

  // POSITIVE goldens locking the deliberate conformance-scope interpretation (RD-5 = kinds only; SIG-5 open-world) —
  // documented so it's auditable and not silently re-litigated by a later review round.
  rec("settlement-cross-chainid-matching-kind-pass", "settlement", "§9.4.3 RD-5", "rail with matching KINDS but asset.chainId≠network.chainId → PASS (RD-5 binds kinds, not chainId-equality)",
    decide(paymentCase({ paymentInput: (i) => ({ ...i, rail: { ...i.rail, asset: { kind: "erc20", chainId: 1, contract: "0x0000000000000000000000000000000000000001", symbol: "USDC", decimals: 6 }, network: { kind: "evm", chainId: 80002, rpcAttestation: "evm-rpc" } } }) })), "pass");

  const { signature: _delPaySig, ...delPayUnsigned } = settlementDelivery.evidence;
  const deliveryWithExtraPayment = signSettlement({ ...delPayUnsigned, paymentAmount: { amount: "5", currency: "USDC" } });
  rec("settlement-delivery-extra-payment-field-pass", "settlement", "§7.7 SIG-5", "delivery evidence carrying a non-settlementFinality payment field → PASS (SIG-5 preserve-unknown / open-world)",
    decide({ result: refreshRef(settlementDelivery.result, deliveryWithExtraPayment), evidence: deliveryWithExtraPayment }), "pass");

  golden["settlement"] = {
    status: "golden — reference-verifier-accepted + byte-stable",
    fixture: "conformance/fixtures/settlement-evidence-payment-success.json",
    deliveryFixture: "conformance/fixtures/settlement-evidence-delivery-success.json",
    jobId: settlementPayment.evidence.jobId,
    deliveryJobId: settlementDelivery.evidence.jobId,
    evidenceHash: settlementPayment.evidenceHash,
    deliveryEvidenceHash: settlementDelivery.evidenceHash,
    decisions: {
      paymentPass: "pass",
      deliveryPass: "pass",
      currencyMismatchNotRejected: "fail",
      successPaymentMissingFinality: "fail",
      deliveryWithFinality: "fail",
      okTrueWithErrorClass: "fail",
      okFalseNoErrorClass: "fail",
      wrongAnchor: "fail",
      sb2DuplicateTxidCrossJob: "fail",
      sb2SameJobCrossPhase: "fail",
      sb2SameObligationIdempotent: "pass",
      sb2SeparateConsumerViews: "pass",
      attestationRefHashMismatch: "fail",
      failureNoReason: "fail",
      wrongSignerKey: "fail",
      malformedKey: "error",
      unresolvableKey: "indeterminate",
      phaseRailMismatch: "fail",
      txRefsMismatch: "fail",
      nonCanonicalAmount: "fail",
      nonPositiveAmount: "fail",
      wrongAttestationKind: "fail",
      nonOrchestratorSigner: "fail",
      successMissingPaymentTxRefs: "fail",
      successMissingPaymentAmount: "fail",
      deliveryMissingDeliverable: "fail",
      deliveryMalformedContentHash: "fail",
      storageAnchoredAsEntitlement: "fail",
      negativeFee: "fail",
      underpaymentVsAgreement: "fail",
      incoherentRailTypeHandler: "fail",
      railNetworkMismatch: "fail",
      htlcFinalityParams: "pass",
      htlcMissingSourceFinality: "fail",
      htlcMissingSafetyWindow: "fail",
      htlcInsufficientMargin: "fail",
      crossChainAnchorPending: "pass",
      crossChainIdMatchingKindPass: "pass",
      deliveryExtraPaymentFieldPass: "pass",
    },
    seeds: settlementPayment.seeds,
    publicKeys: settlementPayment.publicKeys,
  };
}

// ── §14.5 — DACS-5 Verify ───────────────────────────────────────────────────
{
  // §10.4.2: the consumer knows the session's expected parties (from the agreement it audits) — anchoring binds to these.
  const VERIFY_EXPECTED = { buyer: VERIFY_BUYER_CLAIM, seller: VERIFY_SELLER_CLAIM };
  const lookupShape = (jobId: string, fetch: (address: string) => unknown): { buyer: boolean; seller: boolean } => {
    const found = twoSidedLookup(jobId, fetch);
    return { buyer: found.buyer !== undefined, seller: found.seller !== undefined };
  };
  const consumeShape = (jobId: string, fetch: (address: string) => unknown): Record<string, unknown> => {
    const result = consumeBundles(jobId, fetch, verifySession.resolveKey, VERIFY_EXPECTED);
    return {
      verdict: result.verdict,
      buyerDecision: result.buyer?.decision,
      sellerDecision: result.seller?.decision,
      buyerOutcome: result.buyer?.bundle.outcome,
      sellerOutcome: result.seller?.bundle.outcome,
      buyerHash: result.buyer === undefined ? undefined : bundleHash(result.buyer.bundle),
      sellerHash: result.seller === undefined ? undefined : bundleHash(result.seller.bundle),
      abortedBySelfRole: result.abortedBySelfRole,
      abortedByOtherRole: result.abortedByOtherRole,
    };
  };
  // §10.5.1: reputation fixtures are session bundles the BUYER is a party to (each anchoredByRole="buyer" — its own copy).
  const reps = verifySession.reputationBundles;
  const reputation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  const substrateOnly = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer",
    reps.filter((b) => b.outcome === "failed-substrate"),
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  // §10.4.3(a): a bundle whose embedded jobId ≠ the looked-up jobId is ignored (cross-session replay/misreturn).
  const crossSessionFetch = makeBundleFetch("DACS-VERIFY-L3-OTHER-JOB", verifySession.divergentBuyer);
  const crossSessionVerdict = consumeBundles("DACS-VERIFY-L3-OTHER-JOB", crossSessionFetch, verifySession.resolveKey, VERIFY_EXPECTED).verdict;
  // §10.4.2/§10.11: a seller-signed bundle placed at the BUYER address is rejected (role-signature binding) → absent.
  const misanchoredVerdict = consumeBundles(VERIFY_MISANCHORED_JOB_ID, verifySession.fetchMisanchored, verifySession.resolveKey, VERIFY_EXPECTED).verdict;
  // §10.4.2: a present side whose role signature does NOT verify (here the buyer claim resolves to the seller's key) is
  // not classified present → absent; unverifiable storage data must not drive abort provenance.
  const wrongBuyerKey = new Uint8Array(Buffer.from(verifySession.publicKeys[VERIFY_SELLER_CLAIM]!, "base64url"));
  const unverifiedSigVerdict = consumeBundles(VERIFY_ONE_SIDED_JOB_ID, verifySession.fetchOneSided, (claim) => (claim === VERIFY_BUYER_CLAIM ? wrongBuyerKey : verifySession.resolveKey(claim)), VERIFY_EXPECTED).verdict;
  // §10.5.1 two-sided reconciliation: ONE jobId, buyer-victim copy (aborted-by-other) + seller-withdrawer copy
  // (aborted-by-self). Scoring the VICTIM (buyer) over BOTH copies → self_copy wins → exactly ONE aborted-by-other,
  // counted once (counterpartyDisputeRate 1, completionRate 0); the second copy does NOT double-count.
  const reconcilePair = [verifySession.reconcileVictimBuyer, verifySession.reconcileWithdrawerSeller];
  const noDoubleCount = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reconcilePair, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // Scoring the WITHDRAWER (seller) over both copies → self_copy is the seller's own aborted-by-self → the aborter
  // takes the hit, not the victim (counterpartyDisputeRate 0).
  const reconcileWithdrawer = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", reconcilePair, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.11 suppression / perspective_flip: scoring the WITHDRAWER (seller) over ONLY the victim's buyer-anchored copy
  // → no seller self_copy → perspective_flip(aborted-by-other)=aborted-by-self → the withdrawer still takes the hit.
  const perspectiveFlipOnly = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", [verifySession.reconcileVictimBuyer], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 guard (i): a single-signed terminal failed-counterparty copy is dropped before it can perspective_flip.
  const baseCompleted = reps.find((b) => b.outcome === "completed")!;
  const singleSignedCounterparty = {
    ...verifySession.divergentSeller,
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000,
    signatures: verifySession.divergentSeller.signatures.filter((signature) => signature.party === VERIFY_SELLER_CLAIM),
  };
  const singleSignedDropped = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [baseCompleted, singleSignedCounterparty], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 guard (ii): contradictory self/counterparty copies are excluded from all metrics, not trusted by self-copy.
  const divergentExcluded = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [
    baseCompleted,
    { ...verifySession.divergentBuyer, finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000 },
    { ...verifySession.divergentSeller, finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000 },
  ], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 guard (iii): orchestrator copies are evidence-only noise; the buyer/seller counterparty copy is the only flip source.
  const orchestratorNoise = {
    ...verifySession.divergentBuyer,
    jobId: verifySession.reconcileVictimBuyer.jobId,
    finalisedAt: verifySession.reconcileVictimBuyer.finalisedAt,
    anchoredByRole: "orchestrator" as const,
  };
  const orchestratorIgnored = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", [orchestratorNoise, verifySession.reconcileVictimBuyer], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 (R4-B): a party scored over only COUNTERPARTY-anchored bundles IS scored via perspective_flip — NOT
  // excluded (the pre-R4-B anchoredBy-only narrowing was the defect). The buyer-anchored reputation set scored for the
  // SELLER flips each outcome to the seller's perspective: failed-counterparty→failed-perm, aborted-by-other→aborted-by-self.
  const sellerPerspective = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 (L3217): finalisedAt window is closed-interval INCLUSIVE on both ends — a bundle at windowStart==windowEnd is scoped.
  const boundaryInclusive = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START + 1_000, VERIFY_REPUTATION_WINDOW_START + 1_000, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 rating aggregation + de-duplication (L3285/L3344): rating-a/rating-b share (seller, jobId, buyer) →
  // last-writer-wins by ratedAt (value 5 over 3); rating-self is rater==buyer (scored party) → excluded (no self-rating).
  const ratingDerivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [verifySession.ratingBundle], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT, { resolveRating: verifySession.resolveRating });
  // §10.5.1 observedTransactionalVolume (L3327): sum agreement.terms.price by currency over reconciled bundles whose
  // agreementRef resolves (resolver returns 5 usdc per agreement; 5 in-window reps → 25 usdc).
  const volumeDerivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT, { resolveAgreement: verifySession.resolveAgreement });
  // §10.5.1/§10.4.2 trust boundary: role_of_party is the EXTERNALLY-KNOWN partyRole, NOT self-declared `parties`. A
  // buyer-anchored aborted-by-self bundle that adversarially relabels the buyer's claim as "seller" must still be read
  // literally (self_copy keyed on anchoredByRole) — the abort stays on the buyer; it must NOT flip to a counterparty fault.
  const abortSelfBundle = reps.find((b) => b.outcome === "aborted-by-self")!;
  const relabelledAbort = { ...abortSelfBundle, parties: abortSelfBundle.parties.map((p) => ({ ...p, role: (p.primaryClaim === VERIFY_BUYER_CLAIM ? "seller" : "buyer") as "buyer" | "seller" })) };
  const relabelDefeated = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [relabelledAbort], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  // §10.5.1 mixed-role window: the SAME claim (VERIFY_BUYER_CLAIM) is the buyer in REP-ABORT-SELF and genuinely the
  // SELLER in MIXEDROLE-B — there it is the seller-role party AND the seller-anchored signer of a REAL signed bundle
  // (verifySession.mixedRoleSellerBundle, which PASSES verifyBundle), not a mutated-signature copy. The PER-JOB role
  // binding reads BOTH aborted-by-self copies literally; a single derivation-wide role would miss the off-role
  // self_copy and perspective_flip it into a spurious counterparty fault.
  const mixedRoleResolve = (jobId: string): "buyer" | "seller" => (jobId === VERIFY_MIXEDROLE_JOB_ID ? "seller" : "buyer");
  const mixedRole = deriveReputation(VERIFY_BUYER_CLAIM, mixedRoleResolve, [abortSelfBundle, verifySession.mixedRoleSellerBundle], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  const reputationByHash = new Map(reps.map((bundle) => [bundleHash(bundle), bundle]));
  const reputationRerun = deriveReputation(
    VERIFY_BUYER_CLAIM,
    () => "buyer",
    reputation.bundleRefs.map((ref) => reputationByHash.get(ref.contentHash)!),
    reputation.windowStart,
    reputation.windowEnd,
    reputation.computedAt,
  );

  rec("verify-address-buyer", "verify", "§10.4.2", "buyer bundle address is stor-{sha256(jobId + \"-bundle-buyer\")}",
    bundleAddress("job-1", "buyer"), "stor-c7bc689288bad9d6f448ca14c9aa949a4c9574a317f4a591c7f9486f4f7a6b8f");
  rec("verify-address-role-specific", "verify", "§10.4.2", "buyer/seller/orchestrator addresses are role-specific",
    [
      bundleAddress("job-1", "buyer") !== bundleAddress("job-1", "seller"),
      bundleAddress("job-1", "seller") !== bundleAddress("job-1", "orchestrator"),
    ],
    [true, true]);
  rec("cf4-dacs5-rating-address", "verify", "§6.3.4 CF-4", "dacs5 rating address encodes a colon-bearing rater ClaimReference",
    ratingAddress("job-abc", "cci-xm:evm:mainnet:0x1234"), "dacs5:rating:job-abc:cci-xm%3Aevm%3Amainnet%3A0x1234");
  rec("verify-lookup-both", "verify", "§10.4.3(a)", "two-sided lookup fetches both expected addresses",
    lookupShape(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchDivergent), { buyer: true, seller: true });
  rec("verify-lookup-one", "verify", "§10.4.3(a)", "two-sided lookup preserves a one-sided fetch result",
    lookupShape(VERIFY_ONE_SIDED_JOB_ID, verifySession.fetchOneSided), { buyer: true, seller: false });
  rec("verify-lookup-none", "verify", "§10.4.3(a)", "two-sided lookup returns no sides when both addresses are absent",
    lookupShape("DACS-VERIFY-L3-ABSENT", verifySession.fetchAbsent), { buyer: false, seller: false });

  rec("verify-consume-absent", "verify", "§10.4.3(a)", "no bundles at either expected address → absent",
    consumeShape("DACS-VERIFY-L3-ABSENT", verifySession.fetchAbsent), { verdict: "absent" });
  rec("verify-consume-unified", "verify", "§10.4.3(c)", "both present and bundleHash-equal → unified",
    {
      verdict: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchUnified, verifySession.resolveKey, VERIFY_EXPECTED).verdict,
      equalHashes: bundleHash(verifySession.divergentBuyer) === bundleHash(verifySession.divergentBuyer),
      buyerDecision: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchUnified, verifySession.resolveKey, VERIFY_EXPECTED).buyer?.decision,
      sellerDecision: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchUnified, verifySession.resolveKey, VERIFY_EXPECTED).seller?.decision,
    },
    { verdict: "unified", equalHashes: true, buyerDecision: "pass", sellerDecision: "pass" });
  rec("verify-consume-one-sided", "verify", "§10.4.3(b)/§10.11", "one present side → missing side aborted-by-self; present side aborted-by-other",
    consumeShape(VERIFY_ONE_SIDED_JOB_ID, verifySession.fetchOneSided),
    {
      verdict: "one-sided",
      buyerDecision: "pass",
      buyerOutcome: "aborted-by-other",
      buyerHash: bundleHash(verifySession.oneSidedBuyer),
      abortedBySelfRole: "seller",
      abortedByOtherRole: "buyer",
    });
  rec("verify-consume-divergent", "verify", "§10.4.3(d)", "canonically divergent bundles are retained for per-party policy",
    {
      verdict: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchDivergent, verifySession.resolveKey, VERIFY_EXPECTED).verdict,
      buyerDecision: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchDivergent, verifySession.resolveKey, VERIFY_EXPECTED).buyer?.decision,
      sellerDecision: consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchDivergent, verifySession.resolveKey, VERIFY_EXPECTED).seller?.decision,
      distinctHashes: bundleHash(verifySession.divergentBuyer) !== bundleHash(verifySession.divergentSeller),
      notOutcomeEnum: !["completed", "failed-perm", "failed-counterparty", "failed-substrate", "aborted-by-self", "aborted-by-other"].includes(consumeBundles(VERIFY_DIVERGENT_JOB_ID, verifySession.fetchDivergent, verifySession.resolveKey, VERIFY_EXPECTED).verdict),
    },
    { verdict: "divergent", buyerDecision: "pass", sellerDecision: "pass", distinctHashes: true, notOutcomeEnum: true });

  rec("verify-st-draft-vet-legal", "verify", "§10.3.1 ST-1", "draft → vet-pending is legal",
    isLegalTransition("draft", "vet-pending"), true);
  rec("verify-st-vet-abort-legal", "verify", "§10.3.1 ST-1", "vet-pending → aborted-by-self is legal",
    isLegalTransition("vet-pending", "aborted-by-self"), true);
  rec("verify-st-settle-final-legal", "verify", "§10.3.1 ST-1", "settle-completed → finalised is legal",
    isLegalTransition("settle-completed", "finalised"), true);
  rec("verify-st-paused-resume-legal", "verify", "§10.3.1 ST-7", "substrate-failure-paused may resume to a pending phase",
    isLegalTransition("substrate-failure-paused", "commit-pending"), true);
  rec("verify-st-negotiate-after-commit-illegal", "verify", "§10.3.1 ST-1", "commit-completed → negotiate-pending is illegal",
    isLegalTransition("commit-completed", "negotiate-pending"), false);
  rec("verify-st-terminal-forward-illegal", "verify", "§10.3.1 ST-6", "finalised → rate-pending is illegal",
    isLegalTransition("finalised", "rate-pending"), false);
  rec("verify-st-paused-final-illegal", "verify", "§10.3.1 ST-7", "substrate-failure-paused → finalised is illegal",
    isLegalTransition("substrate-failure-paused", "finalised"), false);
  rec("verify-st-settle-asymmetric-legal", "verify", "§10.3.1 ST-8", "settle-pending → settle-asymmetric (HTLC-9 dest-revealed-source-unclaimed open state) is legal",
    isLegalTransition("settle-pending", "settle-asymmetric"), true);
  rec("verify-st-asymmetric-resolve-legal", "verify", "§10.3.1 ST-8", "settle-asymmetric resolves forward: → settle-completed (htlc-claim in window) or → settle-failed (window expiry)",
    [isLegalTransition("settle-asymmetric", "settle-completed"), isLegalTransition("settle-asymmetric", "settle-failed")], [true, true]);
  rec("verify-st-asymmetric-pause-resume-legal", "verify", "§10.3.1 ST-8/R6-6", "settle-asymmetric may pause while anchoring the :resolved record and resume to settle-asymmetric",
    [isLegalTransition("settle-asymmetric", "substrate-failure-paused"), isLegalTransition("substrate-failure-paused", "settle-asymmetric")], [true, true]);
  rec("verify-st-asymmetric-nonterminal", "verify", "§10.3.1 ST-6/ST-8", "settle-asymmetric is non-terminal: no direct → finalised, and no bundle outcome until it resolves",
    [isLegalTransition("settle-asymmetric", "finalised"), stateToOutcome("settle-asymmetric")], [false, null]);

  rec("verify-outcome-finalised", "verify", "§10.3.1", "finalised → completed",
    stateToOutcome("finalised"), "completed");
  rec("verify-outcome-permanent-transient", "verify", "§10.3.1", "permanent and exhausted transient failures → failed-perm",
    [stateToOutcome("vet-failed", "permanent"), stateToOutcome("negotiate-failed", "transient")], ["failed-perm", "failed-perm"]);
  rec("verify-outcome-counterparty-atomicity", "verify", "§10.3.1", "counterparty and settlement-atomicity failures → failed-counterparty",
    [stateToOutcome("commit-failed", "counterparty"), stateToOutcome("settle-failed", "settlement-atomicity")], ["failed-counterparty", "failed-counterparty"]);
  rec("verify-outcome-failed-substrate", "verify", "§10.3.1", "failed-substrate → failed-substrate",
    stateToOutcome("failed-substrate"), "failed-substrate");
  rec("verify-outcome-aborts", "verify", "§10.3.1", "abort terminals map directly",
    [stateToOutcome("aborted-by-self"), stateToOutcome("aborted-by-other")], ["aborted-by-self", "aborted-by-other"]);
  rec("verify-outcome-invalid-null", "verify", "§10.3.1", "non-terminal or unmapped phase error has no bundle outcome",
    [stateToOutcome("settle-pending"), stateToOutcome("settle-failed", "substrate")], [null, null]);

  rec("verify-reputation-denominator", "verify", "§10.5.1", "failed-substrate is excluded from party_fault_denom",
    {
      bundleCount: reputation.bundleCount,
      completionRate: reputation.metrics.completionRate,
      counterpartyAdjustedCompletionRate: reputation.metrics.counterpartyAdjustedCompletionRate,
      counterpartyDisputeRate: reputation.metrics.counterpartyDisputeRate,
      transactionCountByCurrency: reputation.metrics.transactionCountByCurrency,
      bundleRefs: reputation.bundleRefs.length,
    },
    { bundleCount: 5, completionRate: 0.25, counterpartyAdjustedCompletionRate: 0.5, counterpartyDisputeRate: 0.5, transactionCountByCurrency: [], bundleRefs: 5 });
  rec("verify-reputation-null-not-zero", "verify", "§10.5.1", "denominator zero returns null metrics, never zero",
    {
      bundleCount: substrateOnly.bundleCount,
      completionRate: substrateOnly.metrics.completionRate,
      counterpartyAdjustedCompletionRate: substrateOnly.metrics.counterpartyAdjustedCompletionRate,
      counterpartyDisputeRate: substrateOnly.metrics.counterpartyDisputeRate,
      completionIsZero: substrateOnly.metrics.completionRate === 0,
      counterpartyAdjustedIsZero: substrateOnly.metrics.counterpartyAdjustedCompletionRate === 0,
      disputeIsZero: substrateOnly.metrics.counterpartyDisputeRate === 0,
      transactionCountByCurrency: substrateOnly.metrics.transactionCountByCurrency,
    },
    { bundleCount: 1, completionRate: null, counterpartyAdjustedCompletionRate: null, counterpartyDisputeRate: null, completionIsZero: false, counterpartyAdjustedIsZero: false, disputeIsZero: false, transactionCountByCurrency: [] });
  rec("verify-reputation-window", "verify", "§10.5.1", "window filtering excludes out-of-window bundles from scoped count",
    deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_END + 1, VERIFY_REPUTATION_WINDOW_END + 2_000, VERIFY_REPUTATION_COMPUTED_AT).bundleCount,
    1);
  rec("verify-reputation-determinism-receipt", "verify", "§10.5.3", "windowingBasis is recorded and bundleRefs are ascending contentHash; re-derivation from bundleRefs reproduces metrics + count",
    {
      windowingBasis: reputation.windowingBasis,
      sortedBundleRefs: reputation.bundleRefs.map((ref) => ref.contentHash).join("|") === [...reputation.bundleRefs.map((ref) => ref.contentHash)].sort().join("|"),
      rerunMetrics: reputationRerun.metrics,
      rerunBundleCount: reputationRerun.bundleCount,
    },
    {
      windowingBasis: "finalisedAt",
      sortedBundleRefs: true,
      rerunMetrics: reputation.metrics,
      rerunBundleCount: reputation.bundleCount,
    });
  rec("verify-reputation-ratings-volume-l3-null", "verify", "§10.5.1", "L3 leaves rating/volume resolution unset without a resolver",
    {
      averageBuyerRating: reputation.metrics.averageBuyerRating,
      averageSellerRating: reputation.metrics.averageSellerRating,
      observedTransactionalVolume: reputation.metrics.observedTransactionalVolume,
      transactionCountByCurrency: reputation.metrics.transactionCountByCurrency,
    },
    { averageBuyerRating: null, averageSellerRating: null, observedTransactionalVolume: [], transactionCountByCurrency: [] });
  rec("verify-lookup-cross-session-jobid-ignored", "verify", "§10.4.3(a)", "a fetched bundle whose embedded jobId ≠ the looked-up jobId is ignored → absent (cross-session replay/misreturn)",
    crossSessionVerdict, "absent");
  rec("verify-reputation-no-double-count", "verify", "§10.5.1", "two-sided reconciliation: victim scored over BOTH copies of one abort → self_copy wins → exactly one aborted-by-other, counted once (no double-count)",
    { bundleCount: noDoubleCount.bundleCount, bundleRefs: noDoubleCount.bundleRefs.length, completionRate: noDoubleCount.metrics.completionRate, counterpartyAdjustedCompletionRate: noDoubleCount.metrics.counterpartyAdjustedCompletionRate, counterpartyDisputeRate: noDoubleCount.metrics.counterpartyDisputeRate },
    { bundleCount: 1, bundleRefs: 1, completionRate: 0, counterpartyAdjustedCompletionRate: null, counterpartyDisputeRate: 1 });
  rec("verify-reputation-reconcile-withdrawer", "verify", "§10.5.1/§10.11", "the WITHDRAWER scored over both copies → its own aborted-by-self self_copy → the aborter takes the hit (no counterparty fault)",
    { bundleCount: reconcileWithdrawer.bundleCount, completionRate: reconcileWithdrawer.metrics.completionRate, counterpartyDisputeRate: reconcileWithdrawer.metrics.counterpartyDisputeRate },
    { bundleCount: 1, completionRate: 0, counterpartyDisputeRate: 0 });
  rec("verify-reputation-perspective-flip", "verify", "§10.5.1/§10.11", "withdrawer scored over ONLY the victim's counterparty-anchored copy → perspective_flip(aborted-by-other)=aborted-by-self → withdrawer still takes the hit",
    { bundleCount: perspectiveFlipOnly.bundleCount, completionRate: perspectiveFlipOnly.metrics.completionRate, counterpartyDisputeRate: perspectiveFlipOnly.metrics.counterpartyDisputeRate },
    { bundleCount: 1, completionRate: 0, counterpartyDisputeRate: 0 });
  rec("verify-reputation-single-signed-non-abort-dropped", "verify", "§10.5.1", "guard (i): a single-signed seller-anchored failed-counterparty copy is dropped before perspective_flip can depress the buyer's score",
    {
      verifyBundleDecision: verifyBundle(singleSignedCounterparty, verifySession.resolveKey),
      bundleCount: singleSignedDropped.bundleCount,
      completionRate: singleSignedDropped.metrics.completionRate,
      counterpartyDisputeRate: singleSignedDropped.metrics.counterpartyDisputeRate,
      bundleRefs: singleSignedDropped.bundleRefs.map((ref) => ref.id),
    },
    {
      verifyBundleDecision: "fail",
      bundleCount: 1,
      completionRate: 1,
      counterpartyDisputeRate: 0,
      bundleRefs: [baseCompleted.jobId],
    });
  rec("verify-reputation-divergence-excluded", "verify", "§10.5.1/§10.4.3(d)", "guard (ii): contradictory self/counterparty copies are excluded from BOTH numerator and party_fault_denom",
    {
      bundleCount: divergentExcluded.bundleCount,
      completionRate: divergentExcluded.metrics.completionRate,
      counterpartyDisputeRate: divergentExcluded.metrics.counterpartyDisputeRate,
      bundleRefs: divergentExcluded.bundleRefs.map((ref) => ref.id),
    },
    { bundleCount: 1, completionRate: 1, counterpartyDisputeRate: 0, bundleRefs: [baseCompleted.jobId] });
  rec("verify-reputation-orchestrator-ignored", "verify", "§10.5.1", "guard (iii): orchestrator-anchored copies are evidence-only and never chosen as the counterparty perspective",
    {
      bundleCount: orchestratorIgnored.bundleCount,
      completionRate: orchestratorIgnored.metrics.completionRate,
      counterpartyDisputeRate: orchestratorIgnored.metrics.counterpartyDisputeRate,
      bundleRefs: orchestratorIgnored.bundleRefs.map((ref) => ref.id),
    },
    { bundleCount: 1, completionRate: 0, counterpartyDisputeRate: 0, bundleRefs: [verifySession.reconcileVictimBuyer.jobId] });
  rec("verify-reputation-seller-perspective-flip", "verify", "§10.5.1", "R4-B fix: a party scored over only counterparty-anchored bundles IS scored via perspective_flip, NOT excluded (pre-R4-B anchoredBy-only narrowing was the defect)",
    { bundleCount: sellerPerspective.bundleCount, completionRate: sellerPerspective.metrics.completionRate, counterpartyDisputeRate: sellerPerspective.metrics.counterpartyDisputeRate },
    { bundleCount: 5, completionRate: 0.25, counterpartyDisputeRate: 0.25 });
  rec("verify-reputation-rating-dedup", "verify", "§10.5.1", "ratings via resolver: (rater,jobId,targetRole) de-dup last-writer-wins by ratedAt (5 over 3) + no self-rating → averageBuyerRating 5",
    { averageBuyerRating: ratingDerivation.metrics.averageBuyerRating, averageSellerRating: ratingDerivation.metrics.averageSellerRating },
    { averageBuyerRating: 5, averageSellerRating: null });
  rec("verify-reputation-volume-grouped", "verify", "§10.5.1", "observedTransactionalVolume and transactionCountByCurrency aggregate completed sessions by currency",
    {
      observedTransactionalVolume: volumeDerivation.metrics.observedTransactionalVolume,
      transactionCountByCurrency: volumeDerivation.metrics.transactionCountByCurrency,
    },
    {
      observedTransactionalVolume: [{ amount: "5", currency: "usdc" }],
      transactionCountByCurrency: [{ currency: "usdc", count: 1 }],
    });
  rec("verify-reputation-relabel-attack-defeated", "verify", "§10.5.1/§10.4.2", "role_of_party is the externally-known binding, not self-declared `parties`: a buyer bundle that relabels its own claim still reads aborted-by-self literally (NOT flipped to a counterparty fault)",
    { bundleCount: relabelDefeated.bundleCount, counterpartyDisputeRate: relabelDefeated.metrics.counterpartyDisputeRate, completionRate: relabelDefeated.metrics.completionRate },
    { bundleCount: 1, counterpartyDisputeRate: 0, completionRate: 0 });
  rec("verify-reputation-mixed-role-window", "verify", "§10.5.1", "per-job role binding: a party that is buyer in one session and seller in another reads BOTH self-aborts literally — no spurious counterparty fault from a derivation-wide role; the off-role copy is a real signed seller-anchored bundle that verifies (honest fixture, not a mutated copy)",
    { bundleCount: mixedRole.bundleCount, counterpartyDisputeRate: mixedRole.metrics.counterpartyDisputeRate, completionRate: mixedRole.metrics.completionRate, mixedRoleFixtureVerifies: verifySession.decisions.mixedRoleSellerBundle },
    { bundleCount: 2, counterpartyDisputeRate: 0, completionRate: 0, mixedRoleFixtureVerifies: "pass" });
  rec("verify-one-sided-role-signature-binding", "verify", "§10.4.2/§10.11", "a bundle at the BUYER address NOT signed by the expected buyer claim is rejected → absent (anchoring binds to the externally-known party, NOT to self-declared/relabelled `parties` roles)",
    misanchoredVerdict, "absent");
  rec("verify-one-sided-unverified-signature-absent", "verify", "§10.4.2/§10.11", "a present side whose role signature does NOT verify (wrong/forged key) is not classified present → absent (no abort provenance from unverifiable storage)",
    unverifiedSigVerdict, "absent");
  rec("verify-reputation-window-boundary-inclusive", "verify", "§10.5.1", "the finalisedAt window is closed-interval inclusive on BOTH ends — a bundle at exactly windowStart==windowEnd is scoped",
    { bundleCount: boundaryInclusive.bundleCount, completionRate: boundaryInclusive.metrics.completionRate }, { bundleCount: 1, completionRate: 1 });

  golden["verify"] = {
    status: "golden — reference-verifier-accepted + byte-stable",
    fixtures: {
      divergentBuyer: "conformance/fixtures/attestation-bundle-0004.json",
      divergentSeller: "conformance/fixtures/attestation-bundle-0004-seller.json",
      oneSided: "conformance/fixtures/session-bundle-one-sided.json",
      reputationSet: "conformance/fixtures/session-bundles-reputation.json",
    },
    jobIds: {
      divergent: VERIFY_DIVERGENT_JOB_ID,
      oneSided: VERIFY_ONE_SIDED_JOB_ID,
      reputation: verifySession.reputationBundles.map((bundle) => bundle.jobId),
    },
    decisions: verifySession.decisions,
    verdicts: {
      absent: "absent",
      unified: "unified",
      oneSided: "one-sided",
      divergent: "divergent",
    },
    reputation: {
      windowStart: VERIFY_REPUTATION_WINDOW_START,
      windowEnd: VERIFY_REPUTATION_WINDOW_END,
      windowingBasis: reputation.windowingBasis,
      computedAt: VERIFY_REPUTATION_COMPUTED_AT,
      bundleCount: reputation.bundleCount,
      metrics: reputation.metrics,
      bundleRefs: reputation.bundleRefs,
    },
    consistencyChecks: {
      crossSessionJobIdIgnored: crossSessionVerdict,
      reconcileVictimBundleCount: noDoubleCount.bundleCount,
      reconcileVictimDisputeRate: noDoubleCount.metrics.counterpartyDisputeRate,
      sellerPerspectiveBundleCount: sellerPerspective.bundleCount,
      sellerPerspectiveDisputeRate: sellerPerspective.metrics.counterpartyDisputeRate,
      ratingDedupAverageBuyer: ratingDerivation.metrics.averageBuyerRating,
      volumeGrouped: volumeDerivation.metrics.observedTransactionalVolume,
      transactionCountGrouped: volumeDerivation.metrics.transactionCountByCurrency,
      misanchoredRoleSignatureRejected: misanchoredVerdict,
      unverifiedSignatureRejected: unverifiedSigVerdict,
      windowBoundaryInclusiveCount: boundaryInclusive.bundleCount,
    },
    seeds: verifySession.seeds,
    publicKeys: verifySession.publicKeys,
  };
}

// ── report + emit ────────────────────────────────────────────────────────────
const RESET = "\x1b[0m", GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m";
let passed = 0;
const byArea = new Map<string, Case[]>();
for (const c of cases) (byArea.get(c.area) ?? byArea.set(c.area, []).get(c.area)!).push(c);
const goldenN = cases.filter((c) => statusOf(c.area) === "golden").length;
const candidateN = cases.length - goldenN;

console.log(`\nDACS v0.1 conformance — ${goldenN} golden + ${candidateN} candidate (proposed / non-normative)\n`);
for (const [area, list] of byArea) {
  console.log(`  ${area}`);
  for (const c of list) {
    const ok = eq(c.got, c.want);
    if (ok) passed++;
    const mark = ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
    console.log(`    ${mark} ${c.id} ${DIM}${c.spec}${RESET}`);
    if (!ok) console.log(`        ${RED}got ${stable(c.got)} · want ${stable(c.want)}${RESET}`);
  }
}
const allPass = passed === cases.length;
console.log(`\n  ${allPass ? GREEN : RED}${passed}/${cases.length} passed${RESET} ${DIM}(${goldenN} golden · ${candidateN} candidate)${RESET}\n`);

if (EMIT) {
  const vectorsDir = join(HERE, "vectors");
  mkdirSync(vectorsDir, { recursive: true });
  const manifest = {
    dacsVersion: "0.1",
    generator: "github.com/mj-deving/dacs-verify",
    note: "Proposed / non-normative. Run: bun conformance/run.ts",
    surfaces: {
      golden: `${goldenN} vectors — 7 canonicalize + 5 decimal + 5 signing + 16 dacs1 + 2 addressing + 4 bundle + 17 dispute/disclosure (8 dispute + 9 disclosure) + 61 settlement + 47 verify + 32 vet + 11 negotiate + 12 governance; byte-stable and reference-verifier-accepted.`,
      candidate: `${candidateN} vectors.`,
    },
    cases: cases.map((c) => ({ id: c.id, area: c.area, spec: c.spec, summary: c.summary, status: statusOf(c.area), reason: reasonOf(c.area), want: c.want })),
  };
  const fixturesDir = join(HERE, "fixtures");
  mkdirSync(fixturesDir, { recursive: true });
  writeFileSync(join(fixturesDir, "attestation-bundle-0004.json"), JSON.stringify(bundle0004.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "attestation-bundle-0004-seller.json"), JSON.stringify(bundle0004Seller.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "attestation-bundle-htlc9.json"), JSON.stringify(bundleHtlc9.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "session-bundle-one-sided.json"), JSON.stringify(verifySession.oneSidedBuyer, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "session-bundles-reputation.json"), JSON.stringify({
    windowStart: VERIFY_REPUTATION_WINDOW_START,
    windowEnd: VERIFY_REPUTATION_WINDOW_END,
    computedAt: VERIFY_REPUTATION_COMPUTED_AT,
    partyPrimaryClaim: VERIFY_BUYER_CLAIM,
    bundles: verifySession.reputationBundles,
    publicKeys: verifySession.publicKeys,
    seeds: verifySession.seeds,
  }, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "settlement-evidence-payment-success.json"), JSON.stringify({
    result: settlementPayment.result,
    evidence: settlementPayment.evidence,
    paymentInput: settlementPayment.paymentInput,
    evidenceHash: settlementPayment.evidenceHash,
    publicKeys: settlementPayment.publicKeys,
    seeds: settlementPayment.seeds,
  }, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "settlement-evidence-delivery-success.json"), JSON.stringify({
    result: settlementDelivery.result,
    evidence: settlementDelivery.evidence,
    evidenceHash: settlementDelivery.evidenceHash,
    publicKeys: settlementDelivery.publicKeys,
    seeds: settlementDelivery.seeds,
  }, null, 2) + "\n");
  writeFileSync(join(HERE, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(vectorsDir, "golden.json"), JSON.stringify(golden, null, 2) + "\n");
  console.log(`  ${DIM}emitted MANIFEST.json + vectors/golden.json${RESET}\n`);
}

process.exit(allPass ? 0 : 1);
