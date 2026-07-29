import { expect, test } from "bun:test";
import type { ImageAttestationV1, ImageIdentityV1 } from "../src/domain/build";
import { imageId } from "../src/domain/identity";
import type { CanonicalPath, ProviderEvidence, Sha256 } from "../src/domain/model";
import type { ImageEvidenceReport } from "../src/application/image-evidence";
import { verifyImageAttestation } from "../src/application/verify-attestation";

const hash = "1".repeat(64);
const otherHash = "2".repeat(64);
const revision = "3".repeat(40);
const path = "/fixture" as CanonicalPath;
const sha = hash as Sha256;

function fixture(): {
  attestation: ImageAttestationV1;
  evidence: ImageEvidenceReport;
  provider: ProviderEvidence;
} {
  const identity: ImageIdentityV1 = {
    schemaVersion: 1,
    leanToolchain: "leanprover/lean4:v4.32.0",
    leanCompilerGithash: revision,
    mathlibRevision: revision,
    canonicalManifestHash: hash,
    packageSourceTreeHash: hash,
    buildRelevantConfigHash: hash,
    targetPlatform: "darwin-arm64-test",
  };
  const currentImageId = imageId(identity);
  const attestation: ImageAttestationV1 = {
    schemaVersion: 1,
    imageId: currentImageId,
    providerId: "fixture",
    status: "sealed",
    identity,
    provider: { registrySha256: hash, overridesSha256: hash },
    dependencyTreeHash: hash,
    artifactTreeHash: hash,
    artifactCount: 1,
    artifactPolicy: { missingRoots: ["Cli"] },
    sealedAt: "2026-07-23T00:00:00.000Z",
  };
  const evidence: ImageEvidenceReport = {
    schemaVersion: 1,
    mode: "image-evidence",
    status: "complete",
    providerId: "fixture",
    imageId: currentImageId,
    identity,
    sourceTree: {
      schema: "leanbun-source-tree-v1",
      treeHash: hash,
      entryCount: 1,
      fileCount: 1,
      byteCount: 1,
      missingRoots: [],
    },
    configTree: {
      schema: "leanbun-build-config-v1",
      treeHash: hash,
      fileCount: 1,
      missingCount: 0,
    },
    dependencyTreeHash: hash,
    artifactTree: {
      schema: "leanbun-artifact-tree-v1",
      treeHash: hash,
      entryCount: 1,
      fileCount: 1,
      byteCount: 1,
      missingRoots: ["Cli"],
    },
    diagnostics: [],
  };
  const provider: ProviderEvidence = {
    id: "fixture",
    toolchain: identity.leanToolchain,
    state: "matched",
    packageRoot: path,
    cacheRoot: path,
    registry: { path, sha256: sha },
    overrides: { path, sha256: sha },
    packageCount: 1,
  };
  return { attestation, evidence, provider };
}

test("build-time attestation verification requires every canonical field", () => {
  const { attestation, evidence, provider } = fixture();
  expect(verifyImageAttestation(attestation, evidence, provider)).toEqual({
    verified: true,
    mismatches: [],
  });

  const artifactDrift = verifyImageAttestation(
    attestation,
    { ...evidence, artifactTree: { ...evidence.artifactTree!, treeHash: otherHash } },
    provider,
  );
  expect(artifactDrift.verified).toBeFalse();
  expect(artifactDrift.mismatches).toContain("artifactTreeHash");

  const providerDrift = verifyImageAttestation(attestation, evidence, {
    ...provider,
    overrides: { ...provider.overrides, sha256: otherHash as Sha256 },
  });
  expect(providerDrift.verified).toBeFalse();
  expect(providerDrift.mismatches).toContain("provider.overridesSha256");
});
