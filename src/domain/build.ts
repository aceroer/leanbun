import { diagnostic, type Diagnostic } from "./diagnostics";

export interface ImageIdentityV1 {
  schemaVersion: 1;
  leanToolchain: string;
  leanCompilerGithash: string;
  mathlibRevision: string;
  canonicalManifestHash: string;
  packageSourceTreeHash: string;
  buildRelevantConfigHash: string;
  targetPlatform: string;
}

export interface ProjectBindingV1 {
  schemaVersion: 1;
  projectId: string;
  projectPath: string;
  imageId: string;
  providerId: string;
  boundAt: string;
  manifestSha256: string;
  toolchain: string;
  policyVersion: 1;
  allowedTargets: readonly string[];
  lastVerifiedAt: string;
}

export interface ImageAttestationV1 {
  schemaVersion: 1;
  imageId: string;
  providerId: string;
  status: "sealed";
  identity: ImageIdentityV1;
  provider: {
    registrySha256: string;
    overridesSha256: string;
  };
  dependencyTreeHash: string;
  artifactTreeHash: string;
  artifactCount: number;
  artifactPolicy: {
    missingRoots: readonly string[];
  };
  sealedAt: string;
}

export interface ControlledBuildExecutionOutcomeV1 {
  buildExecution: "completed" | "failed" | "reused";
  lakeExitCode?: number;
  projectProtectedRecordsStable?: boolean;
  dependencyArtifactAfter?: string;
  dependencyArtifactCount?: number;
  bindingStable?: boolean;
  attestationStable?: boolean;
  inspectionStable?: boolean;
  terminationReason?: "exit" | "timeout" | "signal";
  triggerSignal?: "SIGINT" | "SIGTERM" | "ABORT";
  processGroupId?: number;
  terminationEscalated?: boolean;
  processGroupReaped?: boolean;
  failureStage?: "sandbox-execution" | "post-build-verification" | "reuse-verification" | "recovery" | "internal";
  failureMessage?: string;
  reuseEvidence?: ProjectBuildReuseEvidenceV1;
  reusedFromExecutionId?: string;
}

export interface ProjectBuildReuseEvidenceV1 {
  schemaVersion: 1;
  projectInput: {
    schema: "leanbun-project-input-tree-v1";
    treeHash: string;
    entryCount: number;
    fileCount: number;
    byteCount: number;
  };
  projectOutput: {
    schema: "leanbun-project-output-tree-v1";
    treeHash: string;
    entryCount: number;
    fileCount: number;
    byteCount: number;
  };
}

/**
 * Operational evidence for one approved build attempt. It is deliberately not
 * referenced by ProjectBindingV1 or BuildAuthorizationFacts, so it cannot be
 * replayed as build authorization.
 */
export interface ControlledBuildExecutionRecordV1 {
  schemaVersion: 1;
  recordType: "controlled-build-execution";
  executionId: string;
  status: "running" | "completed" | "failed" | "reused";
  projectId: string;
  projectPath: string;
  target: string;
  imageId: string;
  bindingSha256: string;
  attestationSha256: string;
  profileSha256?: string;
  reusePolicySha256?: string;
  dependencyArtifactBefore: string;
  buildLockKey?: string;
  coordinatorPid?: number;
  projectProtectedBefore?: string;
  projectProtectedRecordCount?: number;
  startedAt: string;
  finishedAt: string | null;
  outcome: ControlledBuildExecutionOutcomeV1 | null;
}

export interface BuildExecutionLockV1 {
  schemaVersion: 1;
  recordType: "build-execution-lock";
  key: string;
  executionId: string;
  projectId: string;
  projectPath: string;
  imageId: string;
  target: string;
  coordinatorPid: number;
  acquiredAt: string;
}

export interface BuildAuthorizationFacts {
  bindingPresent: boolean;
  bindingValid: boolean;
  projectIdMatches: boolean;
  projectPathMatches: boolean;
  manifestMatches: boolean;
  toolchainMatches: boolean;
  providerMatches: boolean;
  targetValid: boolean;
  targetApproved: boolean;
  attestationPresent: boolean;
  attestationValid: boolean;
  attestationSealed: boolean;
  imageIdMatches: boolean;
  attestationVerified: boolean;
  inspectionPassed: boolean;
}

export interface BuildAuthorization {
  status: "approved" | "denied";
  diagnostics: readonly Diagnostic[];
}

export function evaluateBuildAuthorization(facts: BuildAuthorizationFacts): BuildAuthorization {
  const diagnostics: Diagnostic[] = [];
  if (!facts.inspectionPassed) {
    diagnostics.push(
      diagnostic("BUILD_INSPECTION_FAILED", "error", "filesystem/provider inspection did not pass"),
    );
  }
  if (!facts.targetValid) {
    diagnostics.push(diagnostic("TARGET_INVALID", "error", "requested target syntax is invalid"));
  }
  if (!facts.bindingPresent) {
    diagnostics.push(diagnostic("BINDING_MISSING", "error", "project binding is missing"));
  } else if (!facts.bindingValid) {
    diagnostics.push(diagnostic("BINDING_INVALID", "error", "project binding is invalid"));
  } else {
    if (
      !facts.projectIdMatches ||
      !facts.projectPathMatches ||
      !facts.manifestMatches ||
      !facts.toolchainMatches ||
      !facts.providerMatches
    ) {
      diagnostics.push(
        diagnostic("BINDING_DRIFTED", "error", "project evidence differs from its binding"),
      );
    }
    if (facts.targetValid && !facts.targetApproved) {
      diagnostics.push(
        diagnostic("TARGET_NOT_APPROVED", "error", "requested target is not in the binding allowlist"),
      );
    }
  }
  if (facts.bindingPresent && facts.bindingValid) {
    if (!facts.attestationPresent) {
      diagnostics.push(diagnostic("ATTESTATION_MISSING", "error", "image attestation is missing"));
    } else if (!facts.attestationValid || !facts.attestationSealed || !facts.imageIdMatches) {
      diagnostics.push(
        diagnostic("ATTESTATION_INVALID", "error", "image attestation is invalid or does not match"),
      );
    } else if (!facts.attestationVerified) {
      diagnostics.push(
        diagnostic(
          "ATTESTATION_UNVERIFIED",
          "error",
          "dependency and artifact tree attestation has not been independently reverified",
        ),
      );
    }
  }
  if (diagnostics.some((value) => value.severity === "error")) {
    diagnostics.push(
      diagnostic("BUILD_NOT_AUTHORIZED", "error", "Lake build authorization was not issued"),
    );
    return { status: "denied", diagnostics };
  }
  return { status: "approved", diagnostics };
}
