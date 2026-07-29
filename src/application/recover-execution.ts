import { loadImageAttestation, loadProjectBinding } from "../adapters/binding";
import { dependencyProviderFromEnvironment } from "../adapters/dependency-library";
import {
  finalizeExecutionRecord,
  loadExecutionRecord,
  type StoredExecutionRecord,
} from "../adapters/execution-record-store";
import { loadBuildLock, releaseBuildLock, type StoredBuildLock } from "../adapters/build-lock-store";
import { canonicalizeDirectory, isWithin } from "../adapters/filesystem";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import { projectId } from "../domain/identity";
import type { CanonicalPath } from "../domain/model";
import { auditProjectWorkingDirectoryProcesses } from "../adapters/process";
import { snapshotTree } from "../../scripts/nonmutation-snapshot";
import { buildImageEvidence } from "./image-evidence";
import { inspectProject } from "./inspect-project";
import { hashProtectedProjectRecords, protectedProjectRecords } from "./lake-build-probe";
import { verifyImageAttestation } from "./verify-attestation";

export type CoordinatorProcessState = "active" | "absent" | "unknown";

export interface ExecutionRecoveryReport {
  schemaVersion: 1;
  mode: "stale-running-recovery";
  status: "recovered" | "lock-released" | "blocked";
  executionId: string;
  executionKind?: "lake-build" | "reuse";
  project?: CanonicalPath;
  target?: string;
  coordinatorPid?: number;
  coordinatorState?: CoordinatorProcessState;
  buildLockKey?: string;
  buildLockPath?: CanonicalPath;
  buildLockReleased?: boolean;
  projectProcessState?: "clear" | "active" | "unknown";
  projectProcesses?: readonly { pid: number; command: string; cwd: string }[];
  evidenceStatus?: "stable" | "drifted";
  projectProtectedRecordsStable?: boolean;
  dependencyArtifactsStable?: boolean;
  bindingStable?: boolean;
  attestationStable?: boolean;
  inspectionStable?: boolean;
  dependencyArtifactBefore?: string;
  dependencyArtifactAfter?: string;
  dependencyArtifactCount?: number;
  executionRecord?: {
    status: "failed";
    path: CanonicalPath;
    sha256: string;
  };
  diagnostics: readonly Diagnostic[];
}

export function coordinatorProcessState(pid: number): CoordinatorProcessState {
  try {
    process.kill(pid, 0);
    return "active";
  } catch (error) {
    const code = typeof error === "object" && error !== null && "code" in error
      ? String(error.code)
      : undefined;
    if (code === "ESRCH") return "absent";
    if (code === "EPERM") return "active";
    return "unknown";
  }
}

export function recoveryEvidenceStable(facts: {
  projectProtectedRecordsStable: boolean;
  dependencyArtifactsStable: boolean;
  bindingStable: boolean;
  attestationStable: boolean;
  inspectionStable: boolean;
}): boolean {
  return Object.values(facts).every((value) => value === true);
}

function recordReference(record: StoredExecutionRecord): NonNullable<ExecutionRecoveryReport["executionRecord"]> {
  return { status: "failed", path: record.path, sha256: record.sha256 };
}

export async function recoverStaleExecution(
  executionId: string,
  options: { developmentRoot: string; stateRoot: string },
): Promise<ExecutionRecoveryReport> {
  const diagnostics: Diagnostic[] = [];
  const base = { schemaVersion: 1 as const, mode: "stale-running-recovery" as const, executionId };
  const [developmentRoot, stateRoot] = await Promise.all([
    canonicalizeDirectory(options.developmentRoot),
    canonicalizeDirectory(options.stateRoot),
  ]);
  const stored = await loadExecutionRecord(stateRoot, executionId);
  const record = stored.document;
  const executionKind = record.reusePolicySha256 === undefined ? "lake-build" as const : "reuse" as const;
  if (record.buildLockKey === undefined || record.coordinatorPid === undefined) {
    diagnostics.push(
      diagnostic("EXECUTION_RECOVERY_BLOCKED", "error", "execution record lacks build-lock recovery identity"),
    );
    return { ...base, status: "blocked", executionKind, target: record.target, diagnostics };
  }
  const buildLock = await loadBuildLock(stateRoot, record.buildLockKey);
  const lockMatches = (lock: StoredBuildLock | undefined): lock is StoredBuildLock =>
    lock !== undefined &&
    lock.document.key === record.buildLockKey &&
    lock.document.executionId === record.executionId &&
    lock.document.projectId === record.projectId &&
    lock.document.projectPath === record.projectPath &&
    lock.document.imageId === record.imageId &&
    lock.document.target === record.target &&
    lock.document.coordinatorPid === record.coordinatorPid;
  if (buildLock !== undefined && !lockMatches(buildLock)) {
    diagnostics.push(
      diagnostic("BUILD_LOCK_CONFLICT", "error", "build lock does not match the execution record", [
        `key=${record.buildLockKey}`,
        `owner=${buildLock.document.executionId}`,
      ]),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      buildLockKey: record.buildLockKey,
      buildLockPath: buildLock.path,
      buildLockReleased: false,
      diagnostics,
    };
  }
  if (
    record.status === "running" && (
    record.projectProtectedBefore === undefined ||
    record.projectProtectedRecordCount === undefined)
  ) {
    diagnostics.push(
      diagnostic("EXECUTION_RECOVERY_BLOCKED", "error", "running record lacks recovery evidence"),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      buildLockKey: record.buildLockKey,
      ...(buildLock === undefined ? {} : { buildLockPath: buildLock.path }),
      buildLockReleased: false,
      diagnostics,
    };
  }
  const coordinatorState = coordinatorProcessState(record.coordinatorPid);
  if (coordinatorState !== "absent") {
    diagnostics.push(
      diagnostic(
        coordinatorState === "active" ? "EXECUTION_COORDINATOR_ACTIVE" : "EXECUTION_RECOVERY_BLOCKED",
        "error",
        coordinatorState === "active"
          ? "record coordinator process is still active; recovery was not attempted"
          : "record coordinator process state is unknown; recovery was not attempted",
        [`pid=${record.coordinatorPid}`],
      ),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      ...(buildLock === undefined ? {} : { buildLockPath: buildLock.path }),
      buildLockReleased: false,
      diagnostics,
    };
  }
  const project = await canonicalizeDirectory(record.projectPath);
  if (!isWithin(developmentRoot, project) || project !== record.projectPath) {
    diagnostics.push(
      diagnostic("EXECUTION_RECOVERY_BLOCKED", "error", "record project is outside the development root or changed canonical path"),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      project,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      ...(buildLock === undefined ? {} : { buildLockPath: buildLock.path }),
      buildLockReleased: false,
      diagnostics,
    };
  }
  const processAudit = await auditProjectWorkingDirectoryProcesses(project);
  if (processAudit.status !== "complete" || processAudit.processes.length > 0) {
    const projectProcessState = processAudit.status === "complete" ? "active" : "unknown";
    diagnostics.push(
      diagnostic(
        projectProcessState === "active" ? "EXECUTION_PROJECT_PROCESS_ACTIVE" : "EXECUTION_RECOVERY_BLOCKED",
        "error",
        projectProcessState === "active"
          ? "a process still has the recorded project as its working directory"
          : "project working-directory process audit was inconclusive",
        projectProcessState === "active"
          ? processAudit.processes.map((value) => `pid=${value.pid} command=${value.command} cwd=${value.cwd}`)
          : [processAudit.message ?? "unknown lsof failure"],
      ),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      project,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      ...(buildLock === undefined ? {} : { buildLockPath: buildLock.path }),
      buildLockReleased: false,
      projectProcessState,
      projectProcesses: processAudit.processes,
      diagnostics,
    };
  }
  if (record.status !== "running") {
    const released = await releaseBuildLock(stateRoot, {
      key: record.buildLockKey,
      executionId: record.executionId,
      projectId: record.projectId,
      imageId: record.imageId,
    });
    diagnostics.push(
      diagnostic("BUILD_LOCK_RELEASED", "info", "terminal execution build lock is absent after explicit recovery audit", [
        `executionId=${executionId}`,
        `release=${released.status}`,
      ]),
    );
    return {
      ...base,
      status: "lock-released",
      executionKind,
      project,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      buildLockPath: released.path,
      buildLockReleased: true,
      projectProcessState: "clear",
      projectProcesses: [],
      diagnostics,
    };
  }
  if (buildLock === undefined) {
    diagnostics.push(
      diagnostic("EXECUTION_RECOVERY_BLOCKED", "error", "running execution has no matching build lock", [
        `key=${record.buildLockKey}`,
      ]),
    );
    return {
      ...base,
      status: "blocked",
      executionKind,
      project,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      buildLockReleased: false,
      projectProcessState: "clear",
      projectProcesses: [],
      diagnostics,
    };
  }
  const provider = dependencyProviderFromEnvironment();
  if (provider === undefined) {
    diagnostics.push(diagnostic("EXECUTION_RECOVERY_BLOCKED", "error", "dependency provider is unavailable for recovery audit"));
    return {
      ...base,
      status: "blocked",
      executionKind,
      project,
      target: record.target,
      coordinatorPid: record.coordinatorPid,
      coordinatorState,
      buildLockKey: record.buildLockKey,
      buildLockPath: buildLock.path,
      buildLockReleased: false,
      diagnostics,
    };
  }

  const [projectSnapshot, inspection, imageEvidence, binding, attestation] = await Promise.all([
    snapshotTree(project),
    inspectProject({ project, provider: "dependency-library", hashMode: "sha256", artifactMode: "none" }),
    buildImageEvidence(provider, "full"),
    loadProjectBinding(project),
    loadImageAttestation(stateRoot, record.imageId),
  ]);
  diagnostics.push(...inspection.diagnostics, ...imageEvidence.diagnostics);
  const protectedRecords = protectedProjectRecords(projectSnapshot.records);
  const projectProtectedRecordsStable =
    protectedRecords.length === record.projectProtectedRecordCount &&
    hashProtectedProjectRecords(projectSnapshot.records) === record.projectProtectedBefore;
  const dependencyArtifactAfter = imageEvidence.artifactTree?.treeHash;
  const dependencyArtifactsStable =
    imageEvidence.status === "complete" &&
    imageEvidence.imageId === record.imageId &&
    dependencyArtifactAfter === record.dependencyArtifactBefore;
  const bindingStable =
    binding.status === "valid" &&
    binding.sha256 === record.bindingSha256 &&
    binding.document.projectId === record.projectId &&
    binding.document.projectPath === project &&
    binding.document.imageId === record.imageId &&
    binding.document.allowedTargets.includes(record.target);
  const attestationStable =
    attestation.status === "valid" &&
    attestation.sha256 === record.attestationSha256;
  const attestationVerification = attestation.status === "valid"
    ? verifyImageAttestation(attestation.document, imageEvidence, inspection.provider)
    : { verified: false, mismatches: ["attestation"] as readonly string[] };
  const inspectionStable =
    projectId(project) === record.projectId &&
    inspection.project.path === project &&
    inspection.provider?.state === "matched" &&
    !inspection.diagnostics.some((value) => value.severity === "error" || value.code === "PACKAGE_DIRTY") &&
    attestationVerification.verified;
  const facts = {
    projectProtectedRecordsStable,
    dependencyArtifactsStable,
    bindingStable,
    attestationStable,
    inspectionStable,
  };
  const evidenceStable = recoveryEvidenceStable(facts);
  if (!evidenceStable) {
    diagnostics.push(
      diagnostic("EXECUTION_RECOVERY_EVIDENCE_DRIFTED", "error", "recovery audit found protected evidence drift", [
        ...Object.entries(facts).filter(([, value]) => !value).map(([name]) => name),
        ...attestationVerification.mismatches.map((value) => `attestation:${value}`),
      ]),
    );
  }
  const terminal = await finalizeExecutionRecord(
    stateRoot,
    executionId,
    "failed",
    new Date().toISOString(),
    {
      buildExecution: "failed",
      projectProtectedRecordsStable,
      ...(dependencyArtifactAfter === undefined ? {} : { dependencyArtifactAfter }),
      ...(imageEvidence.artifactTree === undefined ? {} : { dependencyArtifactCount: imageEvidence.artifactTree.fileCount }),
      bindingStable,
      attestationStable,
      inspectionStable,
      failureStage: "recovery",
      failureMessage: `explicit recovery after coordinator pid ${record.coordinatorPid} was absent; evidence=${evidenceStable ? "stable" : "drifted"}`,
    },
  );
  diagnostics.push(
    diagnostic(
      "EXECUTION_RECOVERED",
      evidenceStable ? "info" : "warning",
      "stale running execution was explicitly audited and atomically finalized as failed",
      [`executionId=${executionId}`],
    ),
  );
  if (executionKind === "reuse") {
    diagnostics.push(
      diagnostic("REUSE_EXECUTION_RECOVERED", evidenceStable ? "info" : "warning", "stale reuse transaction was finalized as failed", [
        `executionId=${executionId}`,
      ]),
    );
  }
  const released = await releaseBuildLock(stateRoot, buildLock.document);
  diagnostics.push(
    diagnostic("BUILD_LOCK_RELEASED", "info", "recovered execution build lock was released after terminal record publication", [
      `key=${buildLock.document.key}`,
      `release=${released.status}`,
    ]),
  );
  return {
    ...base,
    status: "recovered",
    executionKind,
    project,
    target: record.target,
    coordinatorPid: record.coordinatorPid,
    coordinatorState,
    buildLockKey: record.buildLockKey,
    buildLockPath: released.path,
    buildLockReleased: true,
    projectProcessState: "clear",
    projectProcesses: [],
    evidenceStatus: evidenceStable ? "stable" : "drifted",
    ...facts,
    dependencyArtifactBefore: record.dependencyArtifactBefore,
    ...(dependencyArtifactAfter === undefined ? {} : { dependencyArtifactAfter }),
    ...(imageEvidence.artifactTree === undefined ? {} : { dependencyArtifactCount: imageEvidence.artifactTree.fileCount }),
    executionRecord: recordReference(terminal),
    diagnostics,
  };
}
