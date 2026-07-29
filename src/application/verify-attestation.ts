import type { ImageAttestationV1 } from "../domain/build";
import { imageId } from "../domain/identity";
import type { ProviderEvidence } from "../domain/model";
import type { ImageEvidenceReport } from "./image-evidence";

export interface AttestationVerification {
  verified: boolean;
  mismatches: readonly string[];
}

export function verifyImageAttestation(
  attestation: ImageAttestationV1,
  evidence: ImageEvidenceReport,
  provider: ProviderEvidence | undefined,
): AttestationVerification {
  const mismatches: string[] = [];
  if (evidence.status !== "complete") mismatches.push("evidence.status");
  if (evidence.imageId !== attestation.imageId) mismatches.push("imageId");
  if (imageId(attestation.identity) !== attestation.imageId) mismatches.push("identity.imageId");
  if (JSON.stringify(evidence.identity) !== JSON.stringify(attestation.identity)) {
    mismatches.push("identity");
  }
  if (evidence.dependencyTreeHash !== attestation.dependencyTreeHash) {
    mismatches.push("dependencyTreeHash");
  }
  if (evidence.artifactTree?.treeHash !== attestation.artifactTreeHash) {
    mismatches.push("artifactTreeHash");
  }
  if (evidence.artifactTree?.fileCount !== attestation.artifactCount) {
    mismatches.push("artifactCount");
  }
  if (
    JSON.stringify(evidence.artifactTree?.missingRoots ?? []) !==
    JSON.stringify(attestation.artifactPolicy.missingRoots)
  ) {
    mismatches.push("artifactPolicy.missingRoots");
  }
  if (provider?.state !== "matched") mismatches.push("provider.state");
  if (provider?.id !== attestation.providerId) mismatches.push("provider.id");
  if (provider?.registry.sha256 !== attestation.provider.registrySha256) {
    mismatches.push("provider.registrySha256");
  }
  if (provider?.overrides.sha256 !== attestation.provider.overridesSha256) {
    mismatches.push("provider.overridesSha256");
  }
  return { verified: mismatches.length === 0, mismatches };
}
