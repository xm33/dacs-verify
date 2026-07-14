import { readFileSync } from "node:fs";
import { join } from "node:path";

import { inspectEvidence, type EvidenceInspectionInput } from "../src/inspector.ts";
import { keypairFromSeed } from "./issuer-kit.ts";

const defaultFixturePath = join(import.meta.dir, "..", "conformance", "fixtures", "attestation-bundle-0004.json");
const inputPath = process.argv[2] ?? defaultFixturePath;
const raw = JSON.parse(readFileSync(inputPath, "utf8")) as unknown;

const buyer = keypairFromSeed("a1".repeat(32));
const seller = keypairFromSeed("c3".repeat(32));

function looksLikeEnvelope(value: unknown): value is EvidenceInspectionInput {
  return Boolean(value && typeof value === "object" && "artifactType" in value && "artifact" in value && "source" in value);
}

function withoutEmbeddedKeys(value: EvidenceInspectionInput): EvidenceInspectionInput {
  const { publicKeys: _untrusted, ...input } = value;
  return input;
}

const input: EvidenceInspectionInput = looksLikeEnvelope(raw)
  ? withoutEmbeddedKeys(raw)
  : {
      artifactType: "dacs-5-attestation-bundle",
      source: {
        kind: "fixture",
        label: "DACS-VERIFY-0004 bundle fixture",
        url: inputPath,
      },
      artifact: raw,
      expectations: {
        jobId: "DACS-VERIFY-0004",
        expectedDecision: "pass",
      },
      publicKeys: {
        "did:demos:buyer": Buffer.from(buyer.publicKeyRaw).toString("hex"),
        "did:demos:seller": Buffer.from(seller.publicKeyRaw).toString("hex"),
      },
    };

console.log(JSON.stringify(inspectEvidence(input), null, 2));
