import { release } from "node:os";
import { canonicalizeDirectory } from "../adapters/filesystem";
import { loadImageAttestation, loadProjectBinding } from "../adapters/binding";
import { dependencyProviderFromEnvironment } from "../adapters/dependency-library";
import { inspectProject } from "./inspect-project";
import { buildImageEvidence, type ImageEvidenceReport } from "./image-evidence";
import { verifyImageAttestation } from "./verify-attestation";
import {
  evaluateBuildAuthorization,
  type BuildAuthorizationFacts,
  type ImageAttestationV1,
  type ProjectBindingV1,
} from "../domain/build";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import { imageId, projectId, validBuildTarget } from "../domain/identity";
import type { CanonicalPath, InspectReport } from "../domain/model";

export interface BuildPreflightReport {
  schemaVersion: 1;
  mode: "build-preflight" | "build-verification";
  buildExecution: "not-attempted";
  project: CanonicalPath;
  target: string;
  status: "approved" | "denied";
  binding: {
    state: "missing" | "invalid" | "valid";
    path: string;
    document?: ProjectBindingV1;
  };
  attestation: {
    state: "not-requested" | "missing" | "invalid" | "valid-unverified" | "valid-verified";
    path?: string;
    document?: ImageAttestationV1;
  };
  inspection: InspectReport;
  imageEvidence?: ImageEvidenceReport;
  diagnostics: readonly Diagnostic[];
}

function currentTargetPlatform(): string {
  return `${process.platform}-${process.arch}-${release()}`;
}

function inspectionStable(inspection: InspectReport): boolean {
  return (
    !inspection.diagnostics.some(
      (value) => value.severity === "error" || value.code === "PACKAGE_DIRTY",
    ) && inspection.provider?.state === "matched"
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

export async function preflightBuild(
  projectInput: string,
  target: string,
  options: { stateRoot?: string; verifyAttestation?: boolean } = {},
): Promise<BuildPreflightReport> {
  const inspection = await inspectProject({
    project: projectInput,
    provider: "dependency-library",
    hashMode: "sha256",
    artifactMode: "none",
  });
  const project = inspection.project.path;
  const binding = await loadProjectBinding(project);
  const facts: BuildAuthorizationFacts = {
    bindingPresent: binding.status !== "missing",
    bindingValid: binding.status === "valid",
    projectIdMatches: false,
    projectPathMatches: false,
    manifestMatches: false,
    toolchainMatches: false,
    providerMatches: false,
    targetValid: validBuildTarget(target),
    targetApproved: false,
    attestationPresent: false,
    attestationValid: false,
    attestationSealed: false,
    imageIdMatches: false,
    attestationVerified: false,
    inspectionPassed: inspectionStable(inspection),
  };

  let attestationState: BuildPreflightReport["attestation"] = { state: "not-requested" };
  let imageEvidence: ImageEvidenceReport | undefined;
  const verificationDiagnostics: Diagnostic[] = [];
  if (binding.status === "valid") {
    facts.projectIdMatches = binding.document.projectId === projectId(project);
    facts.projectPathMatches = binding.document.projectPath === project;
    facts.manifestMatches = binding.document.manifestSha256 === inspection.manifest.sha256;
    facts.toolchainMatches =
      inspection.project.toolchain.status === "ok" &&
      binding.document.toolchain === inspection.project.toolchain.value;
    facts.providerMatches = binding.document.providerId === inspection.provider?.id;
    facts.targetApproved = binding.document.allowedTargets.includes(target);

    const stateRootValue = options.stateRoot ?? process.env.LEANBUN_STATE_ROOT;
    if (stateRootValue !== undefined) {
      try {
        const stateRoot = await canonicalizeDirectory(stateRootValue);
        const attestation = await loadImageAttestation(stateRoot, binding.document.imageId);
        if (attestation.status === "missing") {
          attestationState = { state: "missing", path: attestation.path };
        } else if (attestation.status === "invalid") {
          facts.attestationPresent = true;
          attestationState = { state: "invalid", path: attestation.path };
        } else {
          facts.attestationPresent = true;
          facts.attestationValid = true;
          facts.attestationSealed = attestation.document.status === "sealed";
          const mathlib = inspection.packages.find((value) => value.name === "mathlib");
          const expectedCompiler = process.env.LEANBUN_PROVIDER_LEAN_GITHASH;
          const identityMatchesCurrentProvider =
            attestation.document.providerId === inspection.provider?.id &&
            attestation.document.provider.registrySha256 === inspection.provider?.registry.sha256 &&
            attestation.document.provider.overridesSha256 === inspection.provider?.overrides.sha256 &&
            attestation.document.identity.leanToolchain === inspection.provider?.toolchain &&
            attestation.document.identity.leanCompilerGithash === expectedCompiler &&
            attestation.document.identity.mathlibRevision === mathlib?.providerRevision &&
            attestation.document.identity.canonicalManifestHash ===
              inspection.provider?.registry.sha256 &&
            attestation.document.identity.targetPlatform === currentTargetPlatform();
          facts.imageIdMatches =
            identityMatchesCurrentProvider &&
            imageId(attestation.document.identity) === attestation.document.imageId &&
            attestation.document.imageId === binding.document.imageId;
          attestationState = {
            state: "valid-unverified",
            path: attestation.path,
            document: attestation.document,
          };
          if (
            options.verifyAttestation === true &&
            facts.imageIdMatches &&
            facts.targetValid &&
            facts.targetApproved &&
            facts.projectIdMatches &&
            facts.projectPathMatches &&
            facts.manifestMatches &&
            facts.toolchainMatches &&
            facts.providerMatches &&
            facts.inspectionPassed
          ) {
            const providerConfig = dependencyProviderFromEnvironment();
            if (providerConfig === undefined) {
              verificationDiagnostics.push(
                diagnostic(
                  "ATTESTATION_REVERIFICATION_FAILED",
                  "error",
                  "dependency provider is not configured for build-time re-verification",
                ),
              );
            } else {
              imageEvidence = await buildImageEvidence(providerConfig, "full");
              verificationDiagnostics.push(...imageEvidence.diagnostics);
              const verification = verifyImageAttestation(
                attestation.document,
                imageEvidence,
                inspection.provider,
              );
              const finalInspection = await inspectProject({
                project,
                provider: "dependency-library",
                hashMode: "sha256",
                artifactMode: "none",
              });
              const [finalBinding, finalAttestation] = await Promise.all([
                loadProjectBinding(project),
                loadImageAttestation(stateRoot, binding.document.imageId),
              ]);
              const stableTransaction =
                inspectionStable(finalInspection) &&
                sameInspection(inspection, finalInspection) &&
                finalBinding.status === "valid" &&
                finalBinding.sha256 === binding.sha256 &&
                finalAttestation.status === "valid" &&
                finalAttestation.sha256 === attestation.sha256;
              if (verification.verified && stableTransaction) {
                facts.attestationVerified = true;
                attestationState = {
                  state: "valid-verified",
                  path: attestation.path,
                  document: attestation.document,
                };
                verificationDiagnostics.push(
                  diagnostic(
                    "ATTESTATION_REVERIFIED",
                    "info",
                    "dependency and artifact trees were independently reverified",
                    [
                      `dependencyTreeHash=${attestation.document.dependencyTreeHash}`,
                      `artifactTreeHash=${attestation.document.artifactTreeHash}`,
                    ],
                  ),
                );
              } else {
                verificationDiagnostics.push(
                  diagnostic(
                    "ATTESTATION_REVERIFICATION_FAILED",
                    "error",
                    "build-time evidence differs or changed during re-verification",
                    [
                      ...verification.mismatches.map((value) => `mismatch=${value}`),
                      `stableTransaction=${stableTransaction}`,
                    ],
                  ),
                );
              }
            }
          }
        }
      } catch (error) {
        attestationState = {
          state: "invalid",
          path: stateRootValue,
        };
      }
    }
  }

  const authorization = evaluateBuildAuthorization(facts);
  const diagnostics = [
    ...authorization.diagnostics,
    ...verificationDiagnostics,
    diagnostic(
      "LAKE_BUILD_NOT_ATTEMPTED",
      "info",
      authorization.status === "approved"
        ? "build-time evidence verified, but no executable permit was issued and Lake was not run"
        : "preflight did not execute Lake build or issue a build authorization",
    ),
  ];
  return {
    schemaVersion: 1,
    mode: options.verifyAttestation === true ? "build-verification" : "build-preflight",
    buildExecution: "not-attempted",
    project,
    target,
    status: authorization.status,
    binding: {
      state: binding.status,
      path: binding.path,
      ...(binding.status === "valid" ? { document: binding.document } : {}),
    },
    attestation: attestationState,
    inspection,
    ...(imageEvidence === undefined ? {} : { imageEvidence }),
    diagnostics,
  };
}
