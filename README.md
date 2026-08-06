# dacs-verify

[![CI](https://github.com/mj-deving/dacs-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/mj-deving/dacs-verify/actions/workflows/ci.yml)

**An independent, third-party reference verifier for [DACS](https://github.com/DACS-Agent-commerce/DACS-Standard) (Demos Agent Commerce Standards) v0.1 — and a working prototype of the proposed DACS-X dispute / execution-verification follow-on (§11.2.1).**

> Implement the spec, and every place the implementation can't reproduce a byte-exact result becomes a precise, §-referenced observation back to the standard. MIT. TypeScript / bun. Read-only — no substrate writes, no wallet, no private keys held by the verifier.

## What it covers (verifier foundation)

| Module | Spec | What it does |
|---|---|---|
| `canonicalize.ts` | RFC 8785 JCS, §7.1, §7.2 | Canonical JSON; **enforces §7.1** (throws on non-safe-integer JSON numbers — they must be decimal strings). |
| `hash.ts` | §7.2 | sha256 content hash over the signed scope. |
| `decimal.ts` | CD-1 §8.5.1, §9.3 | Canonical decimal for `PriceTerm.amount`; positivity. |
| `signing.ts` | §7.7 (SIG-1..4) | Closed domain-separator registry; signed-bytes builder; Ed25519 verify; cross-artifact-replay resistance. |
| `dacs1.ts` | §6.3 | Claim-scheme parse, `find_claim`/`match` (incl. the §6.3.3 tier-laundering guard), listing addressing + validation order. |
| `dacs5/bundle.ts` | §10.4 / §10.4.1 | Full `AttestationBundle` verification — JCS-sans-signatures hash, `dacs-bundle:v1:` domain-separated signatures, required-signer rule (buyer+seller, +distinct orchestrator; aborted bundles single-signed per §10.11, never unsigned), 4-value decision. |
| `report.ts` | CONTRIBUTING | Emits observations in the `§ + file + alternate-interpretation` format. |

## DACS-X dispute prototype (§11.2.1) — the primary deliverable

§11.2.1 names **DACS-X (dispute / execution-verification)** as an anticipated follow-on but leaves it unspecified — and it's the agent-commerce field's deepest gap (only Virtuals' Evaluator and A402's adaptor-signature atomicity solve it natively today). `src/dacsx/` is a **working prototype** that shows the whole dispute lifecycle is composable from the primitives DACS *already* has — no new cryptography:

| Module | What it does |
|---|---|
| `dacsx/separators.ts` | SIG-4 `dacs-x-*` extension separators in a **separate** registry — never pollutes the spec's frozen §7.7 set; provenance stays honest by construction. |
| `dacsx/types.ts` | `DisputeRecord` (dispute-open), `ArbitrationRule`, `DisputeOutcome`, remedies. Fractional values are CD-1 decimal **strings** (§7.1). |
| `dacsx/dispute.ts` | Verify the dispute-open signature + bundle pinning; **arbitrator credentialing reuses DACS-1/2 `matchRequirement`**; rule-ref binding blocks post-hoc arbitrator swaps; outcome signature + remedy validation; reputation reweight. |
| `dacsx/flow.ts` | End-to-end `verifyDisputeFlow(...)` → the spec's 4-value decision (`pass`/`fail`/`indeterminate`/`error`). |

The load-bearing design point: **arbitrator legitimacy binds at *agreement* time** (a content-hashed `rule-ref`, §8.4.3 pattern), not at dispute time — so the losing party can't reject the arbitrator after the fact. The reputation reweight is **non-destructive** (preserves the prior weight, derives an effective weight, carries the outcome hash) so the record shows *why* a weight changed; whether the ratified DACS-5 wants destructive supersede or an append-only event log is an open question.

`examples/` holds a demo **issuer kit** (the only place a private key ever lives — the verifier in `src/` never signs) and runnable scenarios that produce byte-stable, **illustrative** vectors in `vectors/dacs-x/` — non-normative candidates for §14 dispute fixtures, **not** conformance vectors for a ratified spec.

**The HTLC-9 asymmetric state (§9.5.4 / §9.8).** Settlement specifies `dest-revealed-source-unclaimed` (the payee was paid on the *destination* chain but the *source* claim failed) and defers closure to dispute or manual intervention. The current verifier models that boundary in the §14.4 settlement vectors and §14.5 DACS-5 verify vectors, where `settle-asymmetric` remains a legal non-terminal state until resolved.

> **Proposed & non-normative.** DACS-X is not part of DACS v0.1. The `dacs-x-*` separator namespace and these artifact shapes presuppose design choices the steward owns. The prototype exists to make a §11.2.1 discussion concrete — not to assert a standard. The tests verify the prototype's internal self-consistency, **not** conformance to any ratified DACS-X (none exists yet).

## Run

```bash
bun test                          # unit tests
bun examples/attestation-bundle-0004.ts
bun examples/dispute-scenario.ts  # end-to-end §10.4.3 dispute → arbitrated → reputation reweighted; emits vectors
bun conformance/run.ts            # golden conformance vectors
bunx tsc --noEmit                 # strict typecheck
```

`conformance/` is a byte-stable, reference-verifier-accepted vector set (`MANIFEST.json` + `vectors/golden.json`) — every case is emitted deterministically and re-checked against this verifier, so two conformant implementations cannot disagree on the pinned outputs. The §10.4 dispute/disclosure cases pin the full `DACS-VERIFY-0004` AttestationBundle fixture (and a divergent seller-side fixture for the §10.4.3(d) two-sided case).

## Conformance observations encoded as executable tests (`test/`)

These are spec-consistency checks the implementation surfaced. Each is encoded as a test; treat them as questions for the standard, not assertions of fault.

- **§6.3.1 vs §6.3.3** — a `cci-lei:` claim never satisfies a `lei` requirement under exact-scheme equality (a scheme-naming inconsistency).
- **§7.7** — separators used in the spec body (`dacs-auto-accept-commitment:v1:`, `dacs-session-binding:v1:`, …) are absent from the "closed" §7.7 registry and aren't `x-`prefixed (SIG-4).
- **§6.3.4** — the spec's `stor-`+sha256(logical) native-address rule yields 64-hex; verify against the substrate's actual addressing before relying on it.

## License

[MIT](./LICENSE).
