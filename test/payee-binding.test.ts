import { expect, test } from "bun:test";
import { DOMAIN_SEPARATOR_REGISTRY, isRegisteredSeparator, verifyArtifactSignatureWithSeparator } from "../src/signing.ts";
import { buildPayeeBindingVectorSet } from "../src/dacs4/payeeBindingVectors.ts";
import { evaluatePrePayGate, verifyAgreementArtifact, type AgreementArtifact, type BindingContext, type ListingFixture, type PaymentPhaseInput } from "../src/dacs4/payeeBinding.ts";

test("§7.7 registry includes PayeeBoundAgreementDocument", () => {
  expect(DOMAIN_SEPARATOR_REGISTRY["dacs-3-payee-bound-agreement"]).toBe("dacs-payee-bound-agreement:v1:");
  expect(isRegisteredSeparator("dacs-payee-bound-agreement:v1:")).toBe(true);
});

test("PB vector set covers artifact compatibility and payee binding gates", () => {
  const set = buildPayeeBindingVectorSet();
  expect(set.count).toBe(set.vectors.length);
  expect(set.vectors.length).toBeGreaterThanOrEqual(20);
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-reader-refuses-payee-bound");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-reader-refuses-both-discriminators");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-reader-refuses-neither-discriminator");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-payoutbindings-reject");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-commit-agreement-with-payee-bound-rejects");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-signature-domain-rejects-payee-bound");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-missing-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-duplicate-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-wrong-rail-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-extra-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).not.toContain("pb2-no-satisfiable-tier-refuses");
});

test("PB vector agreement signatures are self-contained with public keys", () => {
  const set = buildPayeeBindingVectorSet();
  expect(Object.keys(set.publicKeys).length).toBeGreaterThanOrEqual(3);
  expect(new Set(Object.values(set.publicKeys)).size).toBe(Object.values(set.publicKeys).length);

  for (const vector of set.vectors) {
    const agreement = vector.agreement as
      | { signatures?: { party: string; value: string }[] }
      | undefined;
    if (!Array.isArray(agreement?.signatures)) continue;
    expect(vector.artifactHash).toMatch(/^[0-9a-f]{64}$/);

    for (const signature of agreement.signatures) {
      expect(set.publicKeys[signature.party]).toBeString();
    }

    if (typeof vector.signatureDomain !== "string") continue;

    const signatureResults = agreement.signatures.map((signature) => verifyArtifactSignatureWithSeparator({
      separator: vector.signatureDomain as "dacs-agreement:v1:" | "dacs-payee-bound-agreement:v1:",
      doc: agreement,
      publicKeyRaw: Buffer.from(set.publicKeys[signature.party]!, "base64url"),
      signatureRaw: Buffer.from(signature.value, "base64"),
      signatureFields: ["signatures"],
    }).ok);
    const failedAt = (vector.want as { failedAt?: string }).failedAt;
    expect(signatureResults.every(Boolean)).toBe(failedAt !== "signatures");
  }
});

test("PB phase payee bundle hashes match the agreement party they claim", () => {
  const set = buildPayeeBindingVectorSet();
  for (const vector of set.vectors) {
    const agreement = vector.agreement as { parties?: { primaryClaim?: string; bundleHash?: string }[] } | undefined;
    const bundleByClaim = new Map((agreement?.parties ?? []).map((party) => [party.primaryClaim, party.bundleHash]));
    const phaseInputs = [
      ...((vector.phaseInputs as { payee?: { primaryClaim?: string; bundleHash?: string } }[] | undefined) ?? []),
      ...((vector.phaseInput as { payee?: { primaryClaim?: string; bundleHash?: string } } | undefined) ? [vector.phaseInput as { payee?: { primaryClaim?: string; bundleHash?: string } }] : []),
    ];
    for (const phaseInput of phaseInputs) {
      const claim = phaseInput.payee?.primaryClaim;
      if (claim === undefined || !bundleByClaim.has(claim)) continue;
      expect(phaseInput.payee?.bundleHash).toBe(bundleByClaim.get(claim));
    }
  }
});

test("PB vector LEI fixture claims use 20-character identifiers", () => {
  const set = buildPayeeBindingVectorSet();
  const claims = new Set<string>();
  for (const vector of set.vectors) {
    const agreement = vector.agreement as { parties?: { primaryClaim?: string }[] } | undefined;
    for (const party of agreement?.parties ?? []) if (party.primaryClaim?.startsWith("cci-lei:")) claims.add(party.primaryClaim);
    const phaseInput = vector.phaseInput as { payee?: { primaryClaim?: string } } | undefined;
    if (phaseInput?.payee?.primaryClaim?.startsWith("cci-lei:")) claims.add(phaseInput.payee.primaryClaim);
  }
  for (const claim of claims) {
    expect(claim.slice("cci-lei:".length)).toMatch(/^[A-Z0-9]{20}$/);
  }
});

test("artifact-shape failures classify as permanent and tier-2 unresolved stays non-payment", () => {
  const set = buildPayeeBindingVectorSet();
  const missing = set.vectors.find((v) => v.name === "pb1-missing-payoutbinding-permanent");
  expect(missing?.expected).toBe("fail");
  expect((missing?.want as { errorClass?: string }).errorClass).toBe("permanent");

  const unresolved = set.vectors.find((v) => v.name === "pb2-tier2-applicable-unresolvable-pauses-no-tier3");
  expect(unresolved?.expected).toBe("indeterminate");
  expect((unresolved?.want as { maySubmitPayment?: boolean }).maySubmitPayment).toBe(false);
  expect((unresolved?.want as { mustNotUseTier3?: boolean }).mustNotUseTier3).toBe(true);
  expect((unresolved?.want as { recordedVerifyResultEquals?: { reason?: string } }).recordedVerifyResultEquals?.reason).toBe("linked-claim-anchor-unavailable");

  const sb3 = set.vectors.find((v) => v.name === "pb3-sb3-absent-fallback-not-imported");
  expect(sb3?.expected).toBe("indeterminate");
  expect((sb3?.want as { maySubmitPayment?: boolean }).maySubmitPayment).toBe(false);
  expect((sb3?.want as { mustNotApplySb3Fallback?: boolean }).mustNotApplySb3Fallback).toBe(true);
});

test("PB gates require both the buyer's and the seller's signature", () => {
  const set = buildPayeeBindingVectorSet();
  const commit = set.vectors.find((v) => v.name === "agreement-current-reader-accepts-payee-bound")!;
  const pay = set.vectors.find((v) => v.name === "pb1-agreement-bound-destination-matches")!;
  const keep = (artifact: AgreementArtifact, parties: string[]): AgreementArtifact => ({
    ...artifact,
    signatures: artifact.signatures.filter((signature) => parties.some((p) => signature.party.includes(p))),
  });
  for (const parties of [["BUYER"], ["SELLER"], []]) {
    const committed = verifyAgreementArtifact(keep(commit.agreement as AgreementArtifact, parties), commit.listing as ListingFixture, "commit-payee-bound-agreement", "current");
    expect(committed.ok).toBe(false);
    expect(committed.failedAt).toBe("signatures");
    expect(committed.errorClass).toBe("permanent");

    const gate = evaluatePrePayGate(keep(pay.agreement as AgreementArtifact, parties), pay.listing as ListingFixture, pay.phaseInput as PaymentPhaseInput, pay.bindingContext as BindingContext);
    expect(gate.maySubmitPayment).toBe(false);
    expect(gate.bindingTier).toBeUndefined();
  }
  const both = verifyAgreementArtifact(commit.agreement as AgreementArtifact, commit.listing as ListingFixture, "commit-payee-bound-agreement", "current");
  expect(both.ok).toBe(true);
});
