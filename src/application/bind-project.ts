import { loadImageAttestation } from "../adapters/binding";
import { BindingStoreError, storeProjectBinding } from "../adapters/binding-store";
import {
  inspectDependencyProvider,
  type DependencyProviderConfig,
} from "../adapters/dependency-library";
import { canonicalizeDirectory } from "../adapters/filesystem";
import type { ProjectBindingV1 } from "../domain/build";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import { imageId, projectId, validBuildTarget } from "../domain/identity";
import type { CanonicalPath, InspectReport } from "../domain/model";
import { buildImageEvidence, type ImageEvidenceReport } from "./image-evidence";
import { inspectProject } from "./inspect-project";

export interface ProjectBindReport {
  schemaVersion: 1;
  mode: "project-bind";
  status: "bound" | "already-bound" | "blocked";
  project: CanonicalPath;
  imageId: string;
  allowedTargets: readonly string[];
  path?: CanonicalPath;
  bindingSha256?: string;
  binding?: ProjectBindingV1;
  inspection: InspectReport;
  imageEvidence?: ImageEvidenceReport;
  diagnostics: readonly Diagnostic[];
}

function canonicalTargets(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right)),
  );
}

function inspectionBlocked(inspection: InspectReport): boolean {
  return (
    inspection.diagnostics.some(
      (value) => value.severity === "error" || value.code === "PACKAGE_DIRTY",
    ) ||
    inspection.overrides.state !== "registered" ||
    inspection.provider?.state !== "matched" ||
    inspection.manifest.sha256 === undefined ||
    inspection.project.toolchain.status !== "ok" ||
    inspection.project.toolchain.stability !== "stable"
  );
}

function sameInspection(left: InspectReport, right: InspectReport): boolean {
  return (
    left.project.path === right.project.path &&
    left.manifest.sha256 === right.manifest.sha256 &&
    left.project.toolchain.status === "ok" &&
    right.project.toolchain.status === "ok" &&
    left.project.toolchain.value === right.project.toolchain.value &&
    left.provider?.id === right.provider?.id &&
    left.provider?.registry.sha256 === right.provider?.registry.sha256 &&
    left.provider?.overrides.sha256 === right.provider?.overrides.sha256
  );
}

export async function bindProject(
  projectInput: string,
  requestedImageId: string,
  targets: readonly string[],
  providerConfig: DependencyProviderConfig,
  options: { stateRoot: string; now?: () => Date },
): Promise<ProjectBindReport> {
  const allowedTargets = canonicalTargets(targets);
  const inspection = await inspectProject({
    project: projectInput,
    provider: "dependency-library",
    hashMode: "sha256",
    artifactMode: "none",
  });
  const project = inspection.project.path;
  const currentToolchain =
    inspection.project.toolchain.status === "ok"
      ? inspection.project.toolchain.value
      : undefined;
  const diagnostics = [...inspection.diagnostics];
  const base = {
    schemaVersion: 1 as const,
    mode: "project-bind" as const,
    project,
    imageId: requestedImageId,
    allowedTargets,
    inspection,
  };

  if (
    targets.length === 0 ||
    allowedTargets.length !== targets.length ||
    !allowedTargets.every(validBuildTarget)
  ) {
    diagnostics.push(
      diagnostic(
        "BINDING_POLICY_REJECTED",
        "error",
        "binding requires a non-empty, duplicate-free list of valid build targets",
      ),
    );
    return { ...base, status: "blocked", diagnostics };
  }
  if (inspectionBlocked(inspection)) {
    diagnostics.push(
      diagnostic(
        "BINDING_WRITE_FAILED",
        "error",
        "project or provider inspection did not establish stable bind evidence",
      ),
    );
    return { ...base, status: "blocked", diagnostics };
  }

  try {
    const stateRoot = await canonicalizeDirectory(options.stateRoot);
    const loaded = await loadImageAttestation(stateRoot, requestedImageId);
    if (loaded.status !== "valid") {
      diagnostics.push(
        diagnostic(
          loaded.status === "missing" ? "ATTESTATION_MISSING" : "ATTESTATION_INVALID",
          "error",
          "requested sealed image attestation is unavailable or invalid",
          [loaded.path, ...(loaded.status === "invalid" ? [loaded.message] : [])],
        ),
      );
      return { ...base, status: "blocked", diagnostics };
    }

    const imageEvidence = await buildImageEvidence(providerConfig, "full");
    diagnostics.push(...imageEvidence.diagnostics);
    const evidenceProvider = await inspectDependencyProvider(providerConfig);
    diagnostics.push(...evidenceProvider.diagnostics);
    const attestation = loaded.document;
    const actualMissing = imageEvidence.artifactTree?.missingRoots ?? [];
    const evidenceMatches =
      imageEvidence.status === "complete" &&
      imageEvidence.imageId === requestedImageId &&
      imageId(attestation.identity) === requestedImageId &&
      JSON.stringify(imageEvidence.identity) === JSON.stringify(attestation.identity) &&
      imageEvidence.dependencyTreeHash === attestation.dependencyTreeHash &&
      imageEvidence.artifactTree?.treeHash === attestation.artifactTreeHash &&
      imageEvidence.artifactTree?.fileCount === attestation.artifactCount &&
      JSON.stringify(actualMissing) === JSON.stringify(attestation.artifactPolicy.missingRoots) &&
      evidenceProvider.evidence.state === "matched" &&
      evidenceProvider.evidence.id === inspection.provider?.id &&
      evidenceProvider.evidence.registry.sha256 === attestation.provider.registrySha256 &&
      evidenceProvider.evidence.overrides.sha256 === attestation.provider.overridesSha256 &&
      attestation.providerId === inspection.provider?.id &&
      attestation.provider.registrySha256 === inspection.provider?.registry.sha256 &&
      attestation.provider.overridesSha256 === inspection.provider?.overrides.sha256 &&
      attestation.identity.leanToolchain === currentToolchain;
    if (!evidenceMatches) {
      diagnostics.push(
        diagnostic(
          "ATTESTATION_UNVERIFIED",
          "error",
          "sealed image does not match independently recomputed provider and artifact evidence",
        ),
      );
      return { ...base, status: "blocked", imageEvidence, diagnostics };
    }

    const finalInspection = await inspectProject({
      project,
      provider: "dependency-library",
      hashMode: "sha256",
      artifactMode: "none",
    });
    const finalAttestation = await loadImageAttestation(stateRoot, requestedImageId);
    if (
      inspectionBlocked(finalInspection) ||
      !sameInspection(inspection, finalInspection) ||
      finalAttestation.status !== "valid" ||
      finalAttestation.sha256 !== loaded.sha256
    ) {
      diagnostics.push(
        diagnostic(
          "BINDING_WRITE_FAILED",
          "error",
          "project, provider, or attestation changed during bind verification",
        ),
      );
      return { ...base, status: "blocked", imageEvidence, diagnostics };
    }

    const timestamp = (options.now ?? (() => new Date()))().toISOString();
    const binding: ProjectBindingV1 = {
      schemaVersion: 1,
      projectId: projectId(project),
      projectPath: project,
      imageId: requestedImageId,
      providerId: attestation.providerId,
      boundAt: timestamp,
      manifestSha256: inspection.manifest.sha256!,
      toolchain: currentToolchain!,
      policyVersion: 1,
      allowedTargets,
      lastVerifiedAt: timestamp,
    };
    const stored = await storeProjectBinding(project, binding);
    diagnostics.push(
      diagnostic(
        "PROJECT_BOUND",
        "info",
        stored.status === "bound"
          ? "project binding was atomically written and read back"
          : "matching project binding already exists",
        [stored.path, `sha256=${stored.sha256}`],
      ),
    );
    return {
      ...base,
      status: stored.status,
      path: stored.path,
      bindingSha256: stored.sha256,
      binding: stored.document,
      imageEvidence,
      diagnostics,
    };
  } catch (error) {
    const code = error instanceof BindingStoreError ? error.code : "BINDING_WRITE_FAILED";
    diagnostics.push(
      diagnostic(code, "error", "project bind transaction failed", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return { ...base, status: "blocked", diagnostics };
  }
}
