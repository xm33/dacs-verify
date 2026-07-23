import { describe, expect, test } from "bun:test";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { buildSignedBytes } from "../src/signing.ts";
import {
  resolveBundleBindingSide,
  type BundleBindingDecision,
  type BundleBindingResolutionInput,
} from "../conformance/bundle-binding-resolver.ts";

const VECTOR_PATH = new URL("../conformance/vectors/bundle-binding-v0.1.json", import.meta.url);
const VECTOR_SHA256 = "c0f7547e5dfea96232c3c761022ed194795a00bcf661e71f4ca807bec98f9461";

interface BundleBindingVector {
  readonly name: string;
  readonly expected: BundleBindingDecision;
  readonly request: BundleBindingResolutionInput["request"];
  readonly bindings: readonly unknown[];
  readonly anchored: Readonly<Record<string, unknown>>;
  readonly want: {
    readonly expected: BundleBindingDecision;
    readonly resolvedNativeAddress?: string;
    readonly faultedParty?: "buyer" | "seller" | "orchestrator" | "none";
  };
}

interface BundleBindingVectorSet {
  readonly set: string;
  readonly count: number;
  readonly publicKeys: Readonly<Record<string, string>>;
  readonly seeds: Readonly<Record<"buyer" | "seller", string>>;
  readonly vectors: readonly BundleBindingVector[];
}

const vectorBytes = await Bun.file(VECTOR_PATH).bytes();
const vectorSet = JSON.parse(new TextDecoder().decode(vectorBytes)) as BundleBindingVectorSet;
type FixtureSigner = "buyer" | "seller" | "orchestrator";
const ORCHESTRATOR_CLAIM = "did:demos:orchestrator";

function fixturePrivateKey(signer: FixtureSigner) {
  const seed = signer === "orchestrator"
    ? Buffer.alloc(32, 3)
    : Buffer.from(vectorSet.seeds[signer], "hex");
  return createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}

const orchestratorPublicKey = new Uint8Array(Buffer.from(
  createPublicKey(fixturePrivateKey("orchestrator")).export({ format: "jwk" }).x!,
  "base64url",
));
const resolveKey = (claim: string): Uint8Array | undefined => {
  if (claim === ORCHESTRATOR_CLAIM) return orchestratorPublicKey;
  const encoded = vectorSet.publicKeys[claim];
  return encoded === undefined ? undefined : new Uint8Array(Buffer.from(encoded, "base64url"));
};
const authorizedParties = {
  buyer: "did:demos:buyer",
  seller: "did:demos:seller",
} as const;

function signatureValue(separator: string, artifactHash: string, signer: FixtureSigner): string {
  return sign(null, buildSignedBytes(separator, artifactHash), fixturePrivateKey(signer))
    .toString("base64url");
}

function signBinding(
  source: Record<string, unknown>,
  signer: "buyer" | "seller",
): Record<string, unknown> {
  const signerClaim = `did:demos:${signer}`;
  const artifactHash = sha256Hex(canonicalize(withoutSignature(source, "signature")));
  const signature = signatureValue("dacs-bundle-binding:v1:", artifactHash, signer);
  return {
    ...source,
    signer: signerClaim,
    signature: { algorithm: "ed25519", signer: signerClaim, value: signature },
  };
}

function addBundleSignature(
  source: Record<string, unknown>,
  signer: FixtureSigner,
  separator = "dacs-fault-bundle:v1:",
): Record<string, unknown> {
  const artifactHash = sha256Hex(canonicalize(withoutSignature(source, "signatures", "anchoredByRole")));
  const signatures = Array.isArray(source.signatures) ? source.signatures : [];
  return {
    ...source,
    signatures: [...signatures, {
      party: signer === "orchestrator" ? ORCHESTRATOR_CLAIM : `did:demos:${signer}`,
      algorithm: "ed25519",
      value: signatureValue(separator, artifactHash, signer),
    }],
  };
}

function signedBundleMutation(
  source: Record<string, unknown>,
  mutate: (bundle: Record<string, unknown>) => void,
): Record<string, unknown> {
  const mutated = structuredClone(source);
  mutated.signatures = [];
  mutate(mutated);
  return addBundleSignature(addBundleSignature(mutated, "buyer"), "seller");
}

function bindingForBundle(
  source: Record<string, unknown>,
  bundle: Record<string, unknown>,
): Record<string, unknown> {
  return signBinding({
    ...withoutSignature(source, "signature"),
    bundleContentHash: sha256Hex(canonicalize(withoutSignature(bundle, "signatures", "anchoredByRole"))),
  }, "seller");
}

describe("DACS-Standard PR #248 BundleBinding independent cross-run", () => {
  test("pins the exact candidate vector artifact", () => {
    expect(sha256Hex(vectorBytes)).toBe(VECTOR_SHA256);
    expect(vectorSet.set).toBe("bundle-binding-v0.1");
    expect(vectorSet.count).toBe(9);
    expect(vectorSet.vectors).toHaveLength(vectorSet.count);
  });

  for (const vector of vectorSet.vectors) {
    test(`${vector.name}: ${vector.expected}`, () => {
      expect(vector.want.expected).toBe(vector.expected);
      const actual = resolveBundleBindingSide({ ...vector, authorizedParties }, resolveKey);
      expect(actual.decision).toBe(vector.expected);
      if (vector.want.resolvedNativeAddress !== undefined) {
        expect(actual.resolvedNativeAddress).toBe(vector.want.resolvedNativeAddress);
      }
      if (vector.want.faultedParty !== undefined) {
        expect(actual.faultedParty).toBe(vector.want.faultedParty);
      }
    });
  }

  test("an outsider's exhausted signer budget is inert beside an authorized resolution", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const logicalAddress = (valid.bindings[0] as Record<string, unknown>).logicalAddress;
    const outsiderBindings = Array.from({ length: 9 }, (_, index) => signBinding({
      bindingVersion: "1",
      jobId: valid.request.jobId,
      role: valid.request.role,
      logicalAddress,
      nativeAddress: `stor-${sha256Hex(`outsider-native-${index}`).slice(0, 40)}`,
      bundleContentHash: sha256Hex(`outsider-bundle-${index}`),
      signer: "did:demos:buyer",
    }, "buyer"));
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: [...outsiderBindings, ...valid.bindings],
      anchored: valid.anchored,
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.resolvedNativeAddress).toBe(valid.want.resolvedNativeAddress);
  });

  test("the fetch budget counts one native address once across hash variants", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const original = valid.bindings[0] as Record<string, unknown>;
    const variants = Array.from({ length: 8 }, (_, index) => signBinding({
      ...withoutSignature(original, "signature"),
      bundleContentHash: sha256Hex(`same-address-variant-${index}`),
    }, "seller"));
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: [...variants, original],
      anchored: valid.anchored,
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.resolvedNativeAddress).toBe(valid.want.resolvedNativeAddress);
  });

  test("a binding cannot assign its own signer to the requested role", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const original = valid.bindings[0] as Record<string, unknown>;
    const attackerBinding = signBinding({
      ...withoutSignature(original, "signature"),
      signer: "did:demos:buyer",
    }, "buyer");
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: [attackerBinding],
      anchored: valid.anchored,
    }, resolveKey);
    expect(actual.decision).toBe("fail");
    expect(actual.code).toBe("invalid-binding");
  });

  test("canonical collapse retains the strongest signature standing", () => {
    const divergent = vectorSet.vectors.find(
      (vector) => vector.name === "bb-equal-standing-divergence",
    )!;
    const originalBinding = divergent.bindings[0] as Record<string, unknown>;
    const originalNative = originalBinding.nativeAddress as string;
    const originalBundle = divergent.anchored[originalNative] as Record<string, unknown>;
    const fullNative = "stor-ffffffffffffffffffffffffffffffffffffffff";
    const fullBinding = signBinding({
      ...withoutSignature(originalBinding, "signature"),
      nativeAddress: fullNative,
    }, "seller");
    const actual = resolveBundleBindingSide({
      request: divergent.request,
      authorizedParties,
      bindings: [...divergent.bindings, fullBinding],
      anchored: { ...divergent.anchored, [fullNative]: addBundleSignature(originalBundle, "buyer") },
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.resolvedNativeAddress).toBe(fullNative);
  });

  test("signed bundles with malformed required context are rejected", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const originalBinding = valid.bindings[0] as Record<string, unknown>;
    const nativeAddress = originalBinding.nativeAddress as string;
    const originalBundle = valid.anchored[nativeAddress] as Record<string, unknown>;
    const mutations: readonly ((bundle: Record<string, unknown>) => void)[] = [
      (bundle) => { delete bundle.listingRef; },
      (bundle) => { bundle.agreementRef = {}; },
      (bundle) => { bundle.cancellation = {}; },
      (bundle) => { bundle.vetRecords = [{}]; },
      (bundle) => { bundle.settlementEvidence = [{}]; },
      (bundle) => { bundle.amendments = [{}]; },
      (bundle) => { bundle.ratingRefs = [{}]; },
      (bundle) => {
        bundle.phaseSummary = [{ ...(bundle.phaseSummary as Record<string, unknown>[])[0], txRefs: [{}] }];
      },
      (bundle) => {
        bundle.phaseSummary = [{
          ...(bundle.phaseSummary as Record<string, unknown>[])[0], attestationRef: {},
        }];
      },
    ];
    for (const mutate of mutations) {
      const bundle = signedBundleMutation(originalBundle, mutate);
      const binding = bindingForBundle(originalBinding, bundle);
      const actual = resolveBundleBindingSide({
        request: valid.request,
        authorizedParties,
        bindings: [binding],
        anchored: { [nativeAddress]: bundle },
      }, resolveKey);
      expect(actual.decision).toBe("fail");
      expect(actual.code).toBe("invalid-bundle");
    }
  });

  test("accepts every current DACS ChainTxRef variant in a signed bundle", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const originalBinding = valid.bindings[0] as Record<string, unknown>;
    const nativeAddress = originalBinding.nativeAddress as string;
    const originalBundle = valid.anchored[nativeAddress] as Record<string, unknown>;
    const txRefs = [
      { kind: "evm", chainId: 1, txHash: "0x01" },
      { kind: "solana", cluster: "mainnet", signature: "solana-signature" },
      { kind: "demos", txHash: "demos-tx", blockNumber: 42 },
      { kind: "storage-program", address: "stor-native", writeTxHash: "storage-write" },
      {
        kind: "ap2",
        mandateId: "mandate-1",
        providerRef: "provider-1",
        protocolVersion: "1",
        receiptAttestation: { kind: "ap2-receipt", id: "receipt-1", contentHash: "a".repeat(64) },
      },
      {
        kind: "x402",
        httpResource: "https://example.test/resource",
        paymentReceiptHash: "b".repeat(64),
        settlementTxHash: "0x02",
        chainId: 8453,
        protocolVersion: "2",
      },
      { kind: "htlc-lock", chainId: 1, contractAddress: "0xlock", lockTxHash: "0x03" },
      { kind: "htlc-reveal", chainId: 2, contractAddress: "0xreveal", revealTxHash: "0x04" },
      { kind: "htlc-claim", chainId: 1, contractAddress: "0xclaim", claimTxHash: "0x05" },
      { kind: "htlc-refund", chainId: 2, contractAddress: "0xrefund", refundTxHash: "0x06" },
      {
        kind: "liquidity-tank",
        bridgeId: "bridge-1",
        sourceChainId: 1,
        destChainId: 2,
        lockTxHash: "0x07",
        releaseTxHash: "0x08",
        recoveryDeadline: 1_800_000_000_000,
      },
    ];
    const bundle = signedBundleMutation(originalBundle, (mutated) => {
      mutated.phaseSummary = [{
        ...(mutated.phaseSummary as Record<string, unknown>[])[0],
        txRefs,
      }];
    });
    const binding = bindingForBundle(originalBinding, bundle);
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: [binding],
      anchored: { [nativeAddress]: bundle },
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.code).toBe("resolved");
  });

  test("resolves a legacy AttestationBundle with role-relative fault attribution", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const originalBinding = valid.bindings[0] as Record<string, unknown>;
    const nativeAddress = originalBinding.nativeAddress as string;
    const originalBundle = valid.anchored[nativeAddress] as Record<string, unknown>;
    const legacyBase = structuredClone(originalBundle);
    delete legacyBase.faultBundleVersion;
    delete legacyBase.faultedParty;
    legacyBase.bundleVersion = "1";
    legacyBase.outcome = "failed-perm";
    legacyBase.signatures = [];
    const legacyBundle = addBundleSignature(
      addBundleSignature(legacyBase, "buyer", "dacs-bundle:v1:"),
      "seller",
      "dacs-bundle:v1:",
    );
    const binding = bindingForBundle(originalBinding, legacyBundle);
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: [binding],
      anchored: { [nativeAddress]: legacyBundle },
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.code).toBe("resolved");
    expect(actual.faultedParty).toBe("seller");
  });

  test("preserves ambiguous counterparty attribution for a three-party legacy bundle", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const originalBinding = valid.bindings[0] as Record<string, unknown>;
    const nativeAddress = originalBinding.nativeAddress as string;
    const originalBundle = valid.anchored[nativeAddress] as Record<string, unknown>;
    const legacyBase = structuredClone(originalBundle);
    delete legacyBase.faultBundleVersion;
    delete legacyBase.faultedParty;
    legacyBase.bundleVersion = "1";
    legacyBase.outcome = "failed-counterparty";
    legacyBase.parties = [
      ...(legacyBase.parties as Record<string, unknown>[]),
      { role: "orchestrator", bundleHash: "c".repeat(64), primaryClaim: ORCHESTRATOR_CLAIM },
    ];
    legacyBase.signatures = [];
    const legacyBundle = addBundleSignature(addBundleSignature(
      addBundleSignature(legacyBase, "buyer", "dacs-bundle:v1:"),
      "seller",
      "dacs-bundle:v1:",
    ), "orchestrator", "dacs-bundle:v1:");
    const binding = bindingForBundle(originalBinding, legacyBundle);
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties: { ...authorizedParties, orchestrator: ORCHESTRATOR_CLAIM },
      bindings: [binding],
      anchored: { [nativeAddress]: legacyBundle },
    }, resolveKey);
    expect(actual.decision).toBe("pass");
    expect(actual.code).toBe("resolved");
    expect(actual).not.toHaveProperty("faultedParty");
  });

  test("non-canonical fetched values reject without escaping the resolver", () => {
    const valid = vectorSet.vectors.find((vector) => vector.name === "bb-valid-resolution")!;
    const originalBinding = valid.bindings[0] as Record<string, unknown>;
    const nativeAddress = originalBinding.nativeAddress as string;
    const originalBundle = valid.anchored[nativeAddress] as Record<string, unknown>;
    const actual = resolveBundleBindingSide({
      request: valid.request,
      authorizedParties,
      bindings: valid.bindings,
      anchored: { [nativeAddress]: { ...originalBundle, extension: Number.POSITIVE_INFINITY } },
    }, resolveKey);
    expect(actual.decision).toBe("fail");
    expect(actual.code).toBe("invalid-bundle");
  });
});
