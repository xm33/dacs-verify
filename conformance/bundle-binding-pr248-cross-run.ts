import { sha256Hex } from "../src/hash.ts";
import {
  resolveBundleBindingSide,
  type BundleBindingDecision,
  type BundleBindingResolutionInput,
} from "./bundle-binding-resolver.ts";

const DACS_STANDARD_HEAD = "49206cba7c031ab132a86147caba4444ac86fa0c";
const VECTOR_PATH = new URL("./vectors/bundle-binding-v0.1.json", import.meta.url);
const VECTOR_SHA256 = "c0f7547e5dfea96232c3c761022ed194795a00bcf661e71f4ca807bec98f9461";

interface Vector {
  readonly name: string;
  readonly expected: BundleBindingDecision;
  readonly request: BundleBindingResolutionInput["request"];
  readonly bindings: readonly unknown[];
  readonly anchored: Readonly<Record<string, unknown>>;
}

interface VectorSet {
  readonly set: string;
  readonly count: number;
  readonly publicKeys: Readonly<Record<string, string>>;
  readonly vectors: readonly Vector[];
}

const vectorBytes = await Bun.file(VECTOR_PATH).bytes();
if (sha256Hex(vectorBytes) !== VECTOR_SHA256) throw new Error("bundle-binding vector provenance mismatch");
const set = JSON.parse(new TextDecoder().decode(vectorBytes)) as VectorSet;
if (set.set !== "bundle-binding-v0.1" || set.count !== 9 || set.vectors.length !== set.count) {
  throw new Error("bundle-binding vector set shape mismatch");
}
const resolveKey = (claim: string): Uint8Array | undefined => {
  const encoded = set.publicKeys[claim];
  return encoded === undefined ? undefined : new Uint8Array(Buffer.from(encoded, "base64url"));
};
const authorizedParties = {
  buyer: "did:demos:buyer",
  seller: "did:demos:seller",
} as const;
const rows = set.vectors.map((vector) => {
  const result = resolveBundleBindingSide({ ...vector, authorizedParties }, resolveKey);
  return Object.freeze({
    name: vector.name,
    expected: vector.expected,
    actual: result.decision,
    code: result.code,
    match: result.decision === vector.expected,
  });
});
const report = Object.freeze({
  schema: "dacs-verify/bundle-binding-cross-run/v1",
  implementation: "mj-deving/dacs-verify",
  dacsStandardHead: DACS_STANDARD_HEAD,
  vendoredVectorPath: "conformance/vectors/bundle-binding-v0.1.json",
  sourceVectorPath: "conformance/vectors/security/bundle-binding-v0.1.json",
  vectorSha256: VECTOR_SHA256,
  matched: rows.filter((row) => row.match).length,
  total: rows.length,
  rows,
});
console.log(JSON.stringify(report, null, 2));
if (report.matched !== report.total) process.exitCode = 1;
