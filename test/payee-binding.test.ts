import { expect, test } from "bun:test";
import { DOMAIN_SEPARATOR_REGISTRY, isRegisteredSeparator } from "../src/signing.ts";
import { buildPayeeBindingVectorSet } from "../src/dacs4/payeeBindingVectors.ts";

test("§7.7 registry includes PayeeBoundAgreementDocument", () => {
  expect(DOMAIN_SEPARATOR_REGISTRY["dacs-3-payee-bound-agreement"]).toBe("dacs-payee-bound-agreement:v1:");
  expect(isRegisteredSeparator("dacs-payee-bound-agreement:v1:")).toBe(true);
});

test("PB vector set covers artifact compatibility and payee binding gates", () => {
  const set = buildPayeeBindingVectorSet();
  expect(set.count).toBe(set.vectors.length);
  expect(set.vectors.length).toBeGreaterThanOrEqual(20);
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-reader-refuses-payee-bound");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-commit-agreement-with-payee-bound-rejects");
  expect(set.vectors.map((v) => v.name)).toContain("agreement-legacy-signature-domain-rejects-payee-bound");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-missing-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-duplicate-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-wrong-rail-payoutbinding-permanent");
  expect(set.vectors.map((v) => v.name)).toContain("pb1-extra-payoutbinding-permanent");
});

test("artifact-shape failures classify as permanent and tier-2 unresolved stays non-payment", () => {
  const set = buildPayeeBindingVectorSet();
  const missing = set.vectors.find((v) => v.name === "pb1-missing-payoutbinding-permanent");
  expect(missing?.expected).toBe("fail");
  expect((missing?.want as { errorClass?: string }).errorClass).toBe("permanent");

  const unresolved = set.vectors.find((v) => v.name === "pb2-tier2-applicable-unresolvable-pauses-no-tier3");
  expect(unresolved?.expected).toBe("indeterminate");
  expect((unresolved?.want as { maySubmitPayment?: boolean }).maySubmitPayment).toBe(false);
  expect((unresolved?.want as { recordedVerifyResultEquals?: { reason?: string } }).recordedVerifyResultEquals?.reason).toBe("linked-claim-anchor-unavailable");
});
