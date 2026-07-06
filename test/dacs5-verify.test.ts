import { test, expect } from "bun:test";

import {
  TERMINAL_STATES,
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

const fixtures = buildSessionBundleFixtures();
// §10.5.1: reputation fixtures are session bundles the buyer is a party to (each anchoredByRole="buyer" — its own copy).
const reps = fixtures.reputationBundles;
// §10.4.2: the consumer's externally-known expected parties for the session under audit.
const VERIFY_EXPECTED = { buyer: VERIFY_BUYER_CLAIM, seller: VERIFY_SELLER_CLAIM };

test("bundleAddress is deterministic and role-specific", () => {
  expect(bundleAddress("job-1", "buyer")).toBe("stor-c7bc689288bad9d6f448ca14c9aa949a4c9574a317f4a591c7f9486f4f7a6b8f");
  expect(bundleAddress("job-1", "seller")).toBe("stor-4bc62bd044c59f54946ca1baaf9bf943464c352f1d7aea1bdc74c9abbde784d9");
  expect(bundleAddress("job-1", "buyer")).toBe(bundleAddress("job-1", "buyer"));
  expect(bundleAddress("job-1", "buyer")).not.toBe(bundleAddress("job-1", "seller"));
});

test("ratingAddress CF-4-encodes the rater claim segment", () => {
  expect(ratingAddress("job-1", "cci-xm:evm:mainnet:0x1234")).toBe("dacs5:rating:job-1:cci-xm%3Aevm%3Amainnet%3A0x1234");
});

test("twoSidedLookup returns both, one, or no expected-side bundles", () => {
  expect(Object.keys(twoSidedLookup(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchDivergent)).sort()).toEqual(["buyer", "seller"]);
  expect(twoSidedLookup(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided)).toEqual({ buyer: fixtures.oneSidedBuyer });
  expect(twoSidedLookup("DACS-VERIFY-L3-ABSENT", fixtures.fetchAbsent)).toEqual({});
});

test("consumeBundles classifies canonically equal bundles as unified", () => {
  const result = consumeBundles(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchUnified, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("unified");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller?.decision).toBe("pass");
  expect(bundleHash(result.buyer!.bundle)).toBe(bundleHash(result.seller!.bundle));
});

test("R5-1 §10.4.1: bundleHash excludes anchoredByRole — two copies differing ONLY in role are canonically equal and both verify", () => {
  const buyerCopy = fixtures.divergentBuyer; // anchoredByRole: "buyer"
  const sellerCopy = { ...buyerCopy, anchoredByRole: "seller" as const };
  // Excluded from the hashed canonical form → identical hash despite the differing per-copy field.
  expect(bundleHash(sellerCopy)).toBe(bundleHash(buyerCopy));
  // And the buyer copy's signatures (over the anchoredByRole-excluded scope) verify on the seller-anchored copy unchanged.
  expect(verifyBundle(sellerCopy, fixtures.resolveKey)).toBe("pass");
});

test("R5-1 §10.4.2: twoSidedLookup rejects a copy whose anchoredByRole mismatches the address it was fetched from", () => {
  const buyerCopy = fixtures.divergentBuyer; // anchoredByRole: "buyer"
  // Forgery property: since anchoredByRole is no longer hashed, this mis-roled copy STILL passes bundleHash + verifyBundle.
  // The §10.4.2 address cross-check is the ONLY thing standing between it and acceptance at the seller address.
  expect(verifyBundle(buyerCopy, fixtures.resolveKey)).toBe("pass");
  // Place the buyer-roled copy at the SELLER address — the cross-check must drop it (not consume it), so the seller side is absent.
  const misRoledFetch = makeBundleFetch(VERIFY_DIVERGENT_JOB_ID, undefined, buyerCopy);
  expect(twoSidedLookup(VERIFY_DIVERGENT_JOB_ID, misRoledFetch)).toEqual({});
});

test("consumeBundles classifies one-sided bundles by §10.11 roles", () => {
  const result = consumeBundles(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("one-sided");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller).toBeUndefined();
  expect(result.abortedBySelfRole).toBe("seller");
  expect(result.abortedByOtherRole).toBe("buyer");
});

test("consumeBundles keeps divergent bundles for per-party policy", () => {
  const result = consumeBundles(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchDivergent, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("divergent");
  expect(result.verdict).not.toBe("disputed");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller?.decision).toBe("pass");
  expect(bundleHash(result.buyer!.bundle)).not.toBe(bundleHash(result.seller!.bundle));
});

test("consumeBundles returns absent when neither expected side is present", () => {
  expect(consumeBundles("DACS-VERIFY-L3-ABSENT", fixtures.fetchAbsent, fixtures.resolveKey, VERIFY_EXPECTED)).toEqual({ verdict: "absent" });
});

test("isLegalTransition accepts table entries and ST-7 substrate resume", () => {
  expect(isLegalTransition("draft", "vet-pending")).toBe(true);
  expect(isLegalTransition("settle-completed", "finalised")).toBe(true);
  expect(isLegalTransition("substrate-failure-paused", "commit-pending")).toBe(true);
  expect(isLegalTransition("substrate-failure-paused", "failed-substrate")).toBe(true);
});

test("isLegalTransition rejects non-table and backward transitions", () => {
  expect(isLegalTransition("commit-completed", "negotiate-pending")).toBe(false);
  expect(isLegalTransition("finalised", "rate-pending")).toBe(false);
  expect(isLegalTransition("substrate-failure-paused", "finalised")).toBe(false);
  expect(isLegalTransition("rate-completed", "settle-pending")).toBe(false);
});

test("TERMINAL_STATES is exactly ST-6", () => {
  expect([...TERMINAL_STATES].sort()).toEqual([
    "aborted-by-other",
    "aborted-by-self",
    "commit-failed",
    "failed-substrate",
    "finalised",
    "negotiate-failed",
    "settle-failed",
    "vet-failed",
  ]);
});

test("stateToOutcome maps terminal states and errorClass partitions", () => {
  expect(stateToOutcome("finalised")).toBe("completed");
  expect(stateToOutcome("failed-substrate")).toBe("failed-substrate");
  expect(stateToOutcome("aborted-by-self")).toBe("aborted-by-self");
  expect(stateToOutcome("aborted-by-other")).toBe("aborted-by-other");
  expect(stateToOutcome("vet-failed", "permanent")).toBe("failed-perm");
  expect(stateToOutcome("negotiate-failed", "transient")).toBe("failed-perm");
  expect(stateToOutcome("commit-failed", "counterparty")).toBe("failed-counterparty");
  expect(stateToOutcome("settle-failed", "settlement-atomicity")).toBe("failed-counterparty");
  expect(stateToOutcome("settle-failed", "substrate")).toBeNull();
  expect(stateToOutcome("settle-pending")).toBeNull();
  expect(stateToOutcome("settle-asymmetric")).toBeNull(); // ST-8: non-terminal, no bundle outcome
});

test("ST-8: settle-asymmetric is a legal non-terminal cross-chain open state", () => {
  // §10.3.1 ST-8 (R4-A): settle-pending may enter settle-asymmetric on the HTLC-9 condition; it resolves forward
  // to settle-completed (htlc-claim in window) or settle-failed (window expiry), and is itself non-terminal.
  expect(isLegalTransition("settle-pending", "settle-asymmetric")).toBe(true);
  expect(isLegalTransition("settle-asymmetric", "settle-completed")).toBe(true);
  expect(isLegalTransition("settle-asymmetric", "settle-failed")).toBe(true);
  expect(isLegalTransition("settle-asymmetric", "substrate-failure-paused")).toBe(true);
  expect(isLegalTransition("substrate-failure-paused", "settle-asymmetric")).toBe(true);
  expect(isLegalTransition("settle-asymmetric", "finalised")).toBe(false); // must resolve via settle-completed first
  expect(TERMINAL_STATES.has("settle-asymmetric")).toBe(false);
});

test("deriveReputation excludes failed-substrate from party fault denominator", () => {
  const derivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer",
    reps,
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(derivation.bundleCount).toBe(5);
  expect(derivation.metrics.completionRate).toBe(0.25);
  expect(derivation.metrics.counterpartyAdjustedCompletionRate).toBe(0.5);
  expect(derivation.metrics.counterpartyDisputeRate).toBe(0.5);
  expect(derivation.metrics.averageBuyerRating).toBeNull();
  expect(derivation.metrics.averageSellerRating).toBeNull();
  expect(derivation.metrics.observedTransactionalVolume).toEqual([]);
  expect(derivation.metrics.transactionCountByCurrency).toEqual([]);
  expect(derivation.bundleRefs).toHaveLength(5);
  expect(derivation.windowingBasis).toBe("finalisedAt");
  expect(derivation.bundleRefs.map((ref) => ref.contentHash)).toEqual(
    [...derivation.bundleRefs.map((ref) => ref.contentHash)].sort(),
  );
});

test("deriveReputation returns null metrics, not zero, when denominator is zero", () => {
  const onlySubstrate = reps.filter((b) => b.outcome === "failed-substrate");
  const derivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer",
    onlySubstrate,
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(derivation.bundleCount).toBe(1);
  expect(derivation.metrics.completionRate).toBeNull();
  expect(derivation.metrics.counterpartyAdjustedCompletionRate).toBeNull();
  expect(derivation.metrics.counterpartyDisputeRate).toBeNull();
  expect(derivation.metrics.transactionCountByCurrency).toEqual([]);
  expect(derivation.metrics.completionRate).not.toBe(0);
  expect(derivation.metrics.counterpartyAdjustedCompletionRate).not.toBe(0);
  expect(derivation.metrics.counterpartyDisputeRate).not.toBe(0);
});

test("deriveReputation filters by window and scoped party", () => {
  const outside = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer",
    reps,
    VERIFY_REPUTATION_WINDOW_END + 1,
    VERIFY_REPUTATION_WINDOW_END + 2_000,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(outside.bundleCount).toBe(1);
  expect(outside.metrics.completionRate).toBe(1);

  const empty = deriveReputation("did:demos:not-present", () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(empty.bundleCount).toBe(0);
  expect(empty.metrics.completionRate).toBeNull();
  expect(empty.metrics.counterpartyDisputeRate).toBeNull();
});

test("consumeBundles rejects a bundle whose role-party did not sign it (role-signature binding)", () => {
  // §10.4.2/§10.11: a seller-signed bundle placed at the buyer address is not the buyer's bundle → absent, not a
  // flipped one-sided provenance.
  expect(consumeBundles(VERIFY_MISANCHORED_JOB_ID, fixtures.fetchMisanchored, fixtures.resolveKey, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("deriveReputation window is closed-interval inclusive on both ends", () => {
  // §10.5.1 (L3217): a bundle at exactly windowStart==windowEnd is scoped (pins the window-edge off-by-one).
  const at = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START + 1000, VERIFY_REPUTATION_WINDOW_START + 1000, VERIFY_REPUTATION_COMPUTED_AT);
  expect(at.bundleCount).toBe(1);
  expect(at.metrics.completionRate).toBe(1);
});

test("consumeBundles rejects a present side whose role signature does not verify", () => {
  // §10.4.2/§10.11: a one-sided buyer bundle whose buyer claim resolves to the wrong key does not verify → not present.
  const sellerKey = new Uint8Array(Buffer.from(fixtures.publicKeys[VERIFY_SELLER_CLAIM]!, "base64url"));
  const wrongKeyResolve = (claim: string): Uint8Array | null | undefined => (claim === VERIFY_BUYER_CLAIM ? sellerKey : fixtures.resolveKey(claim));
  expect(consumeBundles(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided, wrongKeyResolve, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("twoSidedLookup ignores a fetched bundle whose embedded jobId differs (cross-session)", () => {
  // §10.4.3(a): the address is jobId-derived; a bundle for another session returned here is ignored.
  const fetch = makeBundleFetch("DACS-VERIFY-L3-OTHER", fixtures.divergentBuyer); // divergentBuyer.jobId = DACS-VERIFY-0004
  expect(twoSidedLookup("DACS-VERIFY-L3-OTHER", fetch)).toEqual({});
  expect(consumeBundles("DACS-VERIFY-L3-OTHER", fetch, fixtures.resolveKey, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("deriveReputation two-sided reconciliation: victim scored over both copies counts the abort once (no double-count)", () => {
  // §10.5.1: ONE jobId with victim's aborted-by-other copy + withdrawer's aborted-by-self copy. Scoring the victim
  // (buyer) → its own copy is the self_copy (read literally) → exactly ONE aborted-by-other, not two.
  const pair = [fixtures.reconcileVictimBuyer, fixtures.reconcileWithdrawerSeller];
  const victim = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", pair, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(victim.bundleCount).toBe(1);
  expect(victim.metrics.completionRate).toBe(0);
  expect(victim.metrics.counterpartyAdjustedCompletionRate).toBeNull();
  expect(victim.metrics.counterpartyDisputeRate).toBe(1); // the single aborted-by-other, counted once
});

test("deriveReputation perspective_flip: the withdrawer takes the abort hit (§10.11 guarantee, R4-B)", () => {
  const pair = [fixtures.reconcileVictimBuyer, fixtures.reconcileWithdrawerSeller];
  // Withdrawer (seller) scored over both copies → its own aborted-by-self self_copy → aborter takes the hit.
  const withdrawerBoth = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", pair, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(withdrawerBoth.bundleCount).toBe(1);
  expect(withdrawerBoth.metrics.counterpartyDisputeRate).toBe(0); // self-abort is not counterparty fault
  // §10.11 suppression: only the victim's counterparty-anchored copy exists → perspective_flip(aborted-by-other)
  // = aborted-by-self → the withdrawer still takes the hit, NOT the victim.
  const withdrawerFlip = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", [fixtures.reconcileVictimBuyer], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(withdrawerFlip.bundleCount).toBe(1);
  expect(withdrawerFlip.metrics.counterpartyDisputeRate).toBe(0);
});

test("deriveReputation drops a single-signed non-abort counterparty copy before perspective_flip", () => {
  // §10.5.1 guard (i): a lone seller-anchored failed-counterparty copy is NOT a valid reputation input for the buyer.
  const completed = reps.find((b) => b.outcome === "completed")!;
  const singleSignedCounterparty = {
    ...fixtures.divergentSeller,
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000,
    signatures: fixtures.divergentSeller.signatures.filter((signature) => signature.party === VERIFY_SELLER_CLAIM),
  };
  expect(verifyBundle(singleSignedCounterparty, fixtures.resolveKey)).toBe("fail");
  const scored = deriveReputation(
    VERIFY_BUYER_CLAIM,
    () => "buyer",
    [completed, singleSignedCounterparty],
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(scored.bundleCount).toBe(1);
  expect(scored.metrics.completionRate).toBe(1);
  expect(scored.metrics.counterpartyDisputeRate).toBe(0);
  expect(scored.bundleRefs.map((ref) => ref.id)).toEqual([completed.jobId]);
});

test("deriveReputation excludes canonically divergent self/counterparty copies from both numerator and denominator", () => {
  // §10.5.1 guard (ii): contradictory completed vs failed-counterparty copies are a §10.4.3(d) dispute → excluded.
  const completed = reps.find((b) => b.outcome === "completed")!;
  const divergentBuyer = { ...fixtures.divergentBuyer, finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000 };
  const divergentSeller = { ...fixtures.divergentSeller, finalisedAt: VERIFY_REPUTATION_WINDOW_START + 9_000 };
  const scored = deriveReputation(
    VERIFY_BUYER_CLAIM,
    () => "buyer",
    [completed, divergentBuyer, divergentSeller],
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(scored.bundleCount).toBe(1);
  expect(scored.metrics.completionRate).toBe(1);
  expect(scored.metrics.counterpartyDisputeRate).toBe(0);
  expect(scored.bundleRefs.map((ref) => ref.id)).toEqual([completed.jobId]);
});

test("deriveReputation ignores orchestrator-anchored copies when selecting a counterparty perspective", () => {
  // §10.5.1 guard (iii): the buyer copy drives the seller's score; an orchestrator copy is evidence-only noise.
  const orchestratorNoise = {
    ...fixtures.divergentBuyer,
    jobId: fixtures.reconcileVictimBuyer.jobId,
    finalisedAt: fixtures.reconcileVictimBuyer.finalisedAt,
    anchoredByRole: "orchestrator" as const,
  };
  const scored = deriveReputation(
    VERIFY_SELLER_CLAIM,
    () => "seller",
    [orchestratorNoise, fixtures.reconcileVictimBuyer],
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(scored.bundleCount).toBe(1);
  expect(scored.metrics.completionRate).toBe(0);
  expect(scored.metrics.counterpartyDisputeRate).toBe(0);
  expect(scored.bundleRefs.map((ref) => ref.id)).toEqual([fixtures.reconcileVictimBuyer.jobId]);
});

test("deriveReputation R4-B: a party scored over only counterparty-anchored bundles IS scored via perspective_flip", () => {
  // The pre-R4-B model scoped by anchoredBy==party and would have returned bundleCount 0 here (the defect). The
  // corrected model scores the seller over the buyer-anchored set via perspective_flip.
  const seller = deriveReputation(VERIFY_SELLER_CLAIM, () => "seller", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(seller.bundleCount).toBe(5);
  expect(seller.metrics.completionRate).toBe(0.25);
  expect(seller.metrics.counterpartyDisputeRate).toBe(0.25);
});

test("deriveReputation rating aggregation de-duplicates by (rater, jobId, targetRole) and excludes self-ratings", () => {
  // §10.5.1: rating-a (value 3) and rating-b (value 5) share (seller, jobId, buyer) → last-writer-wins by ratedAt
  // (rating-b later → 5); rating-self is rater==buyer (scored party) → excluded. averageBuyerRating == 5.
  const derivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [fixtures.ratingBundle], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT, { resolveRating: fixtures.resolveRating });
  expect(derivation.metrics.averageBuyerRating).toBe(5);
  expect(derivation.metrics.averageSellerRating).toBeNull();
  // Without a resolver the metric is null (no signal), never a partial aggregate.
  const noResolver = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [fixtures.ratingBundle], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(noResolver.metrics.averageBuyerRating).toBeNull();
});

test("deriveReputation observedTransactionalVolume and transactionCountByCurrency use completed sessions", () => {
  // §10.5.1: only the completed in-window reconciled bundle contributes transaction volume/count.
  const derivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT, { resolveAgreement: fixtures.resolveAgreement });
  expect(derivation.metrics.observedTransactionalVolume).toEqual([{ amount: "5", currency: "usdc" }]);
  expect(derivation.metrics.transactionCountByCurrency).toEqual([{ currency: "usdc", count: 1 }]);
});

test("deriveReputation ignores self-declared party roles — a relabelled bundle cannot flip its own abort (trust boundary)", () => {
  // §10.5.1/§10.4.2: role_of_party is the externally-known partyRole, not the bundle's untrusted `parties` labels. A
  // buyer-anchored aborted-by-self bundle that relabels the buyer's claim as "seller" must STILL read aborted-by-self
  // literally (self_copy keyed on anchoredByRole) — the buyer keeps the hit. Pre-fix (role from `parties`) it would have
  // missed the self_copy and perspective_flip'd aborted-by-self → aborted-by-other, letting the buyer escape the abort.
  const abortSelf = reps.find((b) => b.outcome === "aborted-by-self")!; // buyer-anchored
  const relabelled = { ...abortSelf, parties: abortSelf.parties.map((p) => ({ ...p, role: (p.primaryClaim === VERIFY_BUYER_CLAIM ? "seller" : "buyer") as "buyer" | "seller" })) };
  const scored = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", [relabelled], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(scored.bundleCount).toBe(1);
  expect(scored.metrics.counterpartyDisputeRate).toBe(0); // would be 1 under the pre-fix parties-derived role (flip)
  expect(scored.metrics.completionRate).toBe(0);
});

test("deriveReputation role binding is PER-JOB — a party that is buyer in one session and seller in another", () => {
  // §10.5.1: the SAME claim is the buyer in REP-ABORT-SELF and GENUINELY the seller in MIXEDROLE-B — there it is the
  // seller-role party AND the seller-anchored signer of a REAL signed bundle (fixtures.mixedRoleSellerBundle), not a
  // mutated-signature copy. A PER-JOB resolvePartyRole reads BOTH aborted-by-self copies literally → no fault. A single
  // derivation-wide role would miss the off-role self_copy and perspective_flip it into a counterparty fault.
  const abortSelf = reps.find((b) => b.outcome === "aborted-by-self")!; // VERIFY_BUYER_CLAIM is the buyer here
  const sellerSide = fixtures.mixedRoleSellerBundle;            // VERIFY_BUYER_CLAIM is genuinely the seller here
  // HONEST FIXTURE: derive() assumes verified inputs (§10.4.3), so the off-role copy must itself pass verifyBundle.
  expect(verifyBundle(sellerSide, fixtures.resolveKey)).toBe("pass");
  expect(sellerSide.jobId).toBe(VERIFY_MIXEDROLE_JOB_ID);
  expect(sellerSide.anchoredByRole).toBe("seller");
  expect(sellerSide.parties.find((p) => p.primaryClaim === VERIFY_BUYER_CLAIM)?.role).toBe("seller");
  const resolve = (jobId: string): "buyer" | "seller" => (jobId === VERIFY_MIXEDROLE_JOB_ID ? "seller" : "buyer");
  const mixed = deriveReputation(VERIFY_BUYER_CLAIM, resolve, [abortSelf, sellerSide], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(mixed.bundleCount).toBe(2);
  expect(mixed.metrics.counterpartyDisputeRate).toBe(0); // both self-aborts read literally; pre-fix scalar role → 0.5
  expect(mixed.metrics.completionRate).toBe(0);
});

test("deriveReputation determinism receipt is reproducible from sorted bundleRefs", () => {
  const derivation = deriveReputation(VERIFY_BUYER_CLAIM, () => "buyer", reps, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  const byHash = new Map(reps.map((bundle) => [bundleHash(bundle), bundle]));
  const rerun = deriveReputation(
    VERIFY_BUYER_CLAIM,
    () => "buyer",
    derivation.bundleRefs.map((ref) => byHash.get(ref.contentHash)!),
    derivation.windowStart,
    derivation.windowEnd,
    derivation.computedAt,
  );
  expect(derivation.windowingBasis).toBe("finalisedAt");
  expect(rerun.metrics).toEqual(derivation.metrics);
  expect(rerun.bundleCount).toBe(derivation.bundleCount);
  expect(rerun.bundleRefs).toEqual(derivation.bundleRefs);
});

test("verifyBundle rejects a bundle missing the required anchoredByRole field", () => {
  // §10.4 (L3085): anchoredByRole is REQUIRED + signed. A pre-R4-B bundle without it is structurally unsupported.
  const { anchoredByRole, ...withoutRole } = fixtures.reconcileVictimBuyer;
  void anchoredByRole;
  expect(fixtures.reconcileVictimBuyer.anchoredByRole).toBe("buyer");
  expect(verifyBundle(withoutRole as unknown as typeof fixtures.reconcileVictimBuyer, fixtures.resolveKey)).toBe("fail");
});
