import { canonicalizeDirectory } from "../adapters/filesystem";
import {
  AttestationStoreError,
  storeImageAttestation,
} from "../adapters/attestation-store";
import {
  inspectDependencyProvider,
  type DependencyProviderConfig,
} from "../adapters/dependency-library";
import type { ImageAttestationV1 } from "../domain/build";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { CanonicalPath } from "../domain/model";
import { buildImageEvidence, type ImageEvidenceReport } from "./image-evidence";

export interface ImageSealReport {
  schemaVersion: 1;
  mode: "image-seal";
  status: "sealed" | "already-sealed" | "blocked";
  imageId?: string;
  path?: CanonicalPath;
  attestationSha256?: string;
  attestation?: ImageAttestationV1;
  evidence: ImageEvidenceReport;
  diagnostics: readonly Diagnostic[];
}

function normalizedRoots(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right)),
  );
}

function equalStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export async function sealImage(
  config: DependencyProviderConfig,
  options: {
    stateRoot: string;
    allowedMissingArtifactRoots?: readonly string[];
    now?: () => Date;
  },
): Promise<ImageSealReport> {
  const evidence = await buildImageEvidence(config, "full");
  const diagnostics = [...evidence.diagnostics];
  if (
    evidence.status !== "complete" ||
    evidence.identity === undefined ||
    evidence.imageId === undefined ||
    evidence.dependencyTreeHash === undefined ||
    evidence.artifactTree === undefined
  ) {
    diagnostics.push(
      diagnostic(
        "ATTESTATION_SEAL_FAILED",
        "error",
        "complete canonical image evidence is required before sealing",
      ),
    );
    return { schemaVersion: 1, mode: "image-seal", status: "blocked", evidence, diagnostics };
  }

  const actualMissing = normalizedRoots(evidence.artifactTree.missingRoots);
  const allowedMissing = normalizedRoots(options.allowedMissingArtifactRoots ?? []);
  if (!equalStrings(actualMissing, allowedMissing)) {
    diagnostics.push(
      diagnostic(
        "ATTESTATION_POLICY_REJECTED",
        "error",
        "missing artifact roots require an exact explicit allowlist",
        [
          `actual=${actualMissing.join(",") || "<none>"}`,
          `allowed=${allowedMissing.join(",") || "<none>"}`,
        ],
      ),
    );
    return {
      schemaVersion: 1,
      mode: "image-seal",
      status: "blocked",
      imageId: evidence.imageId,
      evidence,
      diagnostics,
    };
  }

  try {
    const provider = await inspectDependencyProvider(config);
    diagnostics.push(...provider.diagnostics);
    if (
      provider.evidence.state !== "matched" ||
      provider.evidence.registry.sha256 !== evidence.identity.canonicalManifestHash ||
      provider.evidence.overrides.sha256 === undefined ||
      provider.diagnostics.some(
        (value) => value.severity === "error" || value.code === "PACKAGE_DIRTY",
      )
    ) {
      diagnostics.push(
        diagnostic(
          "ATTESTATION_SEAL_FAILED",
          "error",
          "provider changed or became unverifiable after canonical evidence collection",
        ),
      );
      return {
        schemaVersion: 1,
        mode: "image-seal",
        status: "blocked",
        imageId: evidence.imageId,
        evidence,
        diagnostics,
      };
    }

    const stateRoot = await canonicalizeDirectory(options.stateRoot);
    const attestation: ImageAttestationV1 = {
      schemaVersion: 1,
      imageId: evidence.imageId,
      providerId: config.id,
      status: "sealed",
      identity: evidence.identity,
      provider: {
        registrySha256: provider.evidence.registry.sha256,
        overridesSha256: provider.evidence.overrides.sha256,
      },
      dependencyTreeHash: evidence.dependencyTreeHash,
      artifactTreeHash: evidence.artifactTree.treeHash,
      artifactCount: evidence.artifactTree.fileCount,
      artifactPolicy: { missingRoots: actualMissing },
      sealedAt: (options.now ?? (() => new Date()))().toISOString(),
    };
    const stored = await storeImageAttestation(stateRoot, attestation);
    diagnostics.push(
      diagnostic(
        "ATTESTATION_SEALED",
        "info",
        stored.status === "sealed"
          ? "image attestation was atomically sealed and read back"
          : "matching sealed image attestation already exists",
        [stored.path, `sha256=${stored.sha256}`],
      ),
    );
    return {
      schemaVersion: 1,
      mode: "image-seal",
      status: stored.status,
      imageId: stored.document.imageId,
      path: stored.path,
      attestationSha256: stored.sha256,
      attestation: stored.document,
      evidence,
      diagnostics,
    };
  } catch (error) {
    const code =
      error instanceof AttestationStoreError ? error.code : "ATTESTATION_SEAL_FAILED";
    diagnostics.push(
      diagnostic(code, "error", "image attestation seal transaction failed", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return {
      schemaVersion: 1,
      mode: "image-seal",
      status: "blocked",
      imageId: evidence.imageId,
      evidence,
      diagnostics,
    };
  }
}
