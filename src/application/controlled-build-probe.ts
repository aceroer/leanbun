import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { loadImageAttestation, loadProjectBinding } from "../adapters/binding";
import { prepareBuildSandbox, runSandboxedProcess } from "../adapters/build-sandbox";
import {
  acquireBuildLock,
  BuildLockStoreError,
  releaseBuildLock,
  type StoredBuildLock,
} from "../adapters/build-lock-store";
import {
  beginExecutionRecord,
  finalizeExecutionRecord,
  loadExecutionRecord,
  type StoredExecutionRecord,
} from "../adapters/execution-record-store";
import { canonicalizeDirectory, isWithin } from "../adapters/filesystem";
import { auditProjectWorkingDirectoryProcesses } from "../adapters/process";
import {
  artifactTreePolicy,
  hashCanonicalTree,
  projectInputTreePolicy,
  projectOutputTreePolicy,
  type CanonicalTreeHash,
} from "../adapters/tree-hash";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { CanonicalPath, InspectReport } from "../domain/model";
import type { ProjectBuildReuseEvidenceV1 } from "../domain/build";
import { snapshotTree } from "../../scripts/nonmutation-snapshot";
import { preflightBuild } from "./preflight-build";
import { inspectProject } from "./inspect-project";
import {
  hashProtectedProjectRecords,
  protectedProjectRecords,
  stableOutsideBuildRoots,
} from "./lake-build-probe";

export interface ControlledBuildProbeReport {
  schemaVersion: 1;
  mode: "controlled-build-probe";
  status: "passed" | "failed";
  buildExecution: "completed" | "failed" | "not-attempted";
  project: CanonicalPath;
  target: string;
  verificationStatus: "approved" | "denied";
  profileSha256?: string;
  lakeExitCode?: number;
  projectProtectedRecordsStable?: boolean;
  dependencyArtifactBefore?: string;
  dependencyArtifactAfter?: string;
  dependencyArtifactCount?: number;
  bindingStable?: boolean;
  attestationStable?: boolean;
  terminationReason?: "exit" | "timeout" | "signal";
  triggerSignal?: "SIGINT" | "SIGTERM" | "ABORT";
  processGroupId?: number;
  terminationEscalated?: boolean;
  processGroupReaped?: boolean;
  buildLockKey?: string;
  buildLockPath?: CanonicalPath;
  buildLockReleased?: boolean;
  busyOwnerExecutionId?: string;
  reuseEvidence?: ProjectBuildReuseEvidenceV1;
  executionRecord?: {
    executionId: string;
    status: "running" | "completed" | "failed" | "reused";
    path: CanonicalPath;
    sha256: string;
  };
  diagnostics: readonly Diagnostic[];
}

function executionReference(record: StoredExecutionRecord): NonNullable<ControlledBuildProbeReport["executionRecord"]> {
  return {
    executionId: record.document.executionId,
    status: record.document.status,
    path: record.path,
    sha256: record.sha256,
  };
}

function inspectionStable(before: InspectReport, after: InspectReport): boolean {
  return (
    !after.diagnostics.some((value) => value.severity === "error" || value.code === "PACKAGE_DIRTY") &&
    before.project.path === after.project.path &&
    before.manifest.sha256 === after.manifest.sha256 &&
    before.project.toolchain.status === "ok" &&
    after.project.toolchain.status === "ok" &&
    before.project.toolchain.value === after.project.toolchain.value &&
    before.provider?.id === after.provider?.id &&
    before.provider?.registry.sha256 === after.provider?.registry.sha256 &&
    before.provider?.overrides.sha256 === after.provider?.overrides.sha256
  );
}

export function controlledBuildPassed(facts: {
  lakeExitCode: number;
  projectProtectedRecordsStable: boolean;
  dependencyArtifactsStable: boolean;
  bindingStable: boolean;
  attestationStable: boolean;
  inspectionStable: boolean;
  terminationClean: boolean;
  projectInputStable: boolean;
  projectOutputObserved: boolean;
}): boolean {
  return Object.values(facts).every((value) => value === true || value === 0);
}

export async function runControlledBuildProbe(
  projectInput: string,
  target: string,
  options: {
    developmentRoot: string;
    stateRoot: string;
    elanHome: string;
    lake: string;
    timeoutMs?: number;
    terminationGraceMs?: number;
    signal?: AbortSignal;
  },
): Promise<ControlledBuildProbeReport> {
  const developmentRoot = await canonicalizeDirectory(options.developmentRoot);
  const project = await canonicalizeDirectory(projectInput);
  const base = { schemaVersion: 1 as const, mode: "controlled-build-probe" as const, project, target };
  const diagnostics: Diagnostic[] = [];
  if (options.signal?.aborted) {
    diagnostics.push(diagnostic("LAKE_EXECUTION_CANCELLED", "error", "controlled build was cancelled before verification"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  if (!isWithin(developmentRoot, project)) {
    diagnostics.push(diagnostic("BUILD_SANDBOX_INVALID", "error", "controlled probe project must be inside LEANBUN_DEV_ROOT"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  const verification = await preflightBuild(project, target, {
    stateRoot: options.stateRoot,
    verifyAttestation: true,
  });
  diagnostics.push(...verification.diagnostics.filter((value) => value.code !== "LAKE_BUILD_NOT_ATTEMPTED"));
  if (options.signal?.aborted) {
    diagnostics.push(diagnostic("LAKE_EXECUTION_CANCELLED", "error", "controlled build was cancelled before Lake execution"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  if (
    verification.status !== "approved" ||
    verification.imageEvidence?.artifactTree === undefined ||
    verification.binding.document === undefined ||
    verification.attestation.document === undefined
  ) {
    diagnostics.push(diagnostic("CONTROLLED_BUILD_FAILED", "error", "build-time verification did not approve the transaction"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  const packageRoots = verification.inspection.packages.flatMap((value) =>
    value.path === undefined ? [] : [value.path],
  );
  if (packageRoots.length !== verification.inspection.packages.length) {
    diagnostics.push(diagnostic("CONTROLLED_BUILD_FAILED", "error", "provider package roots are incomplete"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "approved", diagnostics };
  }
  const stateRoot = await canonicalizeDirectory(options.stateRoot);
  const initialBinding = await loadProjectBinding(project);
  const initialAttestation = await loadImageAttestation(stateRoot, verification.binding.document.imageId);
  if (initialBinding.status !== "valid" || initialAttestation.status !== "valid") {
    diagnostics.push(diagnostic("CONTROLLED_BUILD_FAILED", "error", "binding or attestation disappeared after verification"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "approved", diagnostics };
  }
  const elanHome = await canonicalizeDirectory(options.elanHome);
  const lakePath = resolve(options.lake);
  const lakeTarget = await realpath(lakePath);
  if (!isWithin(developmentRoot, elanHome) || !isWithin(elanHome, lakePath) || !isWithin(elanHome, lakeTarget)) {
    diagnostics.push(diagnostic("BUILD_SANDBOX_INVALID", "error", "Lake proxy is outside isolated Elan home"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "approved", diagnostics };
  }
  const spec = await prepareBuildSandbox(project, [...packageRoots, stateRoot]);
  const [projectBefore, projectInputBefore] = await Promise.all([
    snapshotTree(project),
    hashCanonicalTree([{ owner: "project", path: project }], projectInputTreePolicy),
  ]);
  const executionId = crypto.randomUUID();
  let buildLock: StoredBuildLock;
  try {
    buildLock = await acquireBuildLock(stateRoot, {
      executionId,
      projectId: initialBinding.document.projectId,
      projectPath: project,
      imageId: initialBinding.document.imageId,
      target,
      coordinatorPid: process.pid,
      acquiredAt: new Date().toISOString(),
    });
  } catch (error) {
    const lockError = error instanceof BuildLockStoreError ? error : undefined;
    diagnostics.push(
      diagnostic(
        lockError?.code ?? "BUILD_LOCK_FAILED",
        "error",
        lockError?.code === "BUILD_LOCK_BUSY"
          ? "another execution already holds the project/image build lock"
          : "project/image build lock could not be acquired",
        [
          error instanceof Error ? error.message : String(error),
          ...(lockError?.owner === undefined ? [] : [`ownerExecutionId=${lockError.owner.executionId}`, `ownerPid=${lockError.owner.coordinatorPid}`]),
        ],
      ),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "not-attempted",
      verificationStatus: "approved",
      profileSha256: spec.profileSha256,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      ...(lockError?.owner === undefined ? {} : {
        buildLockKey: lockError.owner.key,
        busyOwnerExecutionId: lockError.owner.executionId,
      }),
      diagnostics,
    };
  }
  diagnostics.push(
    diagnostic("BUILD_LOCK_ACQUIRED", "info", "project/image build lock acquired", [
      `key=${buildLock.document.key}`,
      `executionId=${executionId}`,
    ]),
  );
  try {
    await beginExecutionRecord(stateRoot, {
      executionId,
      projectId: initialBinding.document.projectId,
      projectPath: project,
      target,
      imageId: initialBinding.document.imageId,
      bindingSha256: initialBinding.sha256,
      attestationSha256: initialAttestation.sha256,
      profileSha256: spec.profileSha256,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      buildLockKey: buildLock.document.key,
      coordinatorPid: process.pid,
      projectProtectedBefore: hashProtectedProjectRecords(projectBefore.records),
      projectProtectedRecordCount: protectedProjectRecords(projectBefore.records).length,
      startedAt: new Date().toISOString(),
    });
  } catch (error) {
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("BUILD_LOCK_RELEASED", "info", "build lock released after execution record creation failed"),
      diagnostic("EXECUTION_RECORD_FAILED", "error", "execution record could not be created; Lake was not started", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "not-attempted",
      verificationStatus: "approved",
      profileSha256: spec.profileSha256,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      diagnostics,
    };
  }
  diagnostics.push(
    diagnostic("EXECUTION_RECORD_STARTED", "info", "approved build attempt received a running execution record", [
      `executionId=${executionId}`,
    ]),
  );
  let lake: Awaited<ReturnType<typeof runSandboxedProcess>>;
  try {
    lake = await runSandboxedProcess(
      spec,
      lakePath,
      ["--verbose", "build", target],
      {
        PATH: `${elanHome}/bin:/usr/bin:/bin:/usr/sbin:/sbin`,
        ELAN_HOME: elanHome,
        TMPDIR: spec.controlTempRoot,
        LC_ALL: "C.UTF-8",
        LANG: "C.UTF-8",
      },
      {
        ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
        ...(options.terminationGraceMs === undefined ? {} : { terminationGraceMs: options.terminationGraceMs }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const terminalRecord = await finalizeExecutionRecord(
      stateRoot,
      executionId,
      "failed",
      new Date().toISOString(),
      { buildExecution: "failed", failureStage: "sandbox-execution", failureMessage: message.slice(0, 1024) },
    );
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("EXECUTION_RECORD_FINALIZED", "info", "execution record atomically transitioned to failed"),
      diagnostic("BUILD_LOCK_RELEASED", "info", "project/image build lock released"),
      diagnostic("CONTROLLED_BUILD_FAILED", "error", "sandboxed Lake execution could not complete", [message]),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "failed",
      verificationStatus: "approved",
      profileSha256: spec.profileSha256,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      executionRecord: executionReference(terminalRecord),
      diagnostics,
    };
  }
  const processAudit = await auditProjectWorkingDirectoryProcesses(project);
  const processGroupReaped = processAudit.status === "complete" && processAudit.processes.length === 0;
  if (!processGroupReaped) {
    diagnostics.push(
      diagnostic("PROCESS_GROUP_NOT_REAPED", "error", "sandbox process group or project cwd processes remain after Lake exit", [
        ...(processAudit.status === "unknown"
          ? [processAudit.message ?? "unknown cwd process audit failure"]
          : processAudit.processes.map((value) => `pid=${value.pid} command=${value.command} cwd=${value.cwd}`)),
      ]),
    );
    const running = await loadExecutionRecord(stateRoot, executionId);
    return {
      ...base,
      status: "failed",
      buildExecution: "failed",
      verificationStatus: "approved",
      profileSha256: spec.profileSha256,
      lakeExitCode: lake.exitCode,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      terminationReason: lake.terminationReason,
      ...(lake.triggerSignal === undefined ? {} : { triggerSignal: lake.triggerSignal }),
      processGroupId: lake.processGroupId,
      terminationEscalated: lake.terminationEscalated,
      processGroupReaped,
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: false,
      executionRecord: executionReference(running),
      diagnostics,
    };
  }
  let projectAfter: Awaited<ReturnType<typeof snapshotTree>>;
  let finalInspection: InspectReport;
  let finalBinding: Awaited<ReturnType<typeof loadProjectBinding>>;
  let finalAttestation: Awaited<ReturnType<typeof loadImageAttestation>>;
  let artifactAfter: Awaited<ReturnType<typeof hashCanonicalTree>>;
  let projectInputAfter: CanonicalTreeHash;
  let projectOutputAfter: CanonicalTreeHash;
  try {
    [projectAfter, finalInspection, finalBinding, finalAttestation, artifactAfter, projectInputAfter, projectOutputAfter] = await Promise.all([
      snapshotTree(project),
      inspectProject({ project, provider: "dependency-library", hashMode: "sha256", artifactMode: "none" }),
      loadProjectBinding(project),
      loadImageAttestation(stateRoot, verification.binding.document.imageId),
      hashCanonicalTree(packageRoots.map((path, index) => ({ owner: verification.inspection.packages[index]!.name, path: join(path, ".lake/build") })), artifactTreePolicy),
      hashCanonicalTree([{ owner: "project", path: project }], projectInputTreePolicy),
      hashCanonicalTree([{ owner: "project-output", path: spec.projectBuildRoot }], projectOutputTreePolicy),
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const terminalRecord = await finalizeExecutionRecord(
      stateRoot,
      executionId,
      "failed",
      new Date().toISOString(),
      {
        buildExecution: "failed",
        lakeExitCode: lake.exitCode,
        failureStage: "post-build-verification",
        failureMessage: message.slice(0, 1024),
      },
    );
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("EXECUTION_RECORD_FINALIZED", "info", "execution record atomically transitioned to failed"),
      diagnostic("BUILD_LOCK_RELEASED", "info", "project/image build lock released"),
      diagnostic("CONTROLLED_BUILD_FAILED", "error", "post-build verification could not complete", [message]),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "failed",
      verificationStatus: "approved",
      profileSha256: spec.profileSha256,
      lakeExitCode: lake.exitCode,
      dependencyArtifactBefore: verification.imageEvidence.artifactTree.treeHash,
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      executionRecord: executionReference(terminalRecord),
      diagnostics,
    };
  }
  const projectProtectedRecordsStable = stableOutsideBuildRoots(projectBefore.records, projectAfter.records);
  const dependencyArtifactBefore = verification.imageEvidence.artifactTree.treeHash;
  const dependencyArtifactAfter = artifactAfter.treeHash;
  const dependencyArtifactsStable =
    dependencyArtifactBefore === dependencyArtifactAfter &&
    verification.imageEvidence.artifactTree.fileCount === artifactAfter.fileCount;
  const bindingStable = finalBinding.status === "valid" && finalBinding.sha256 === initialBinding.sha256;
  const attestationStable = finalAttestation.status === "valid" && finalAttestation.sha256 === initialAttestation.sha256;
  const finalInspectionStable = inspectionStable(verification.inspection, finalInspection);
  const projectInputStable =
    projectInputBefore.treeHash === projectInputAfter.treeHash &&
    projectInputBefore.entryCount === projectInputAfter.entryCount &&
    projectInputBefore.fileCount === projectInputAfter.fileCount &&
    projectInputBefore.byteCount === projectInputAfter.byteCount;
  const projectOutputObserved = projectOutputAfter.missingRoots.length === 0;
  const passed = controlledBuildPassed({
    lakeExitCode: lake.exitCode,
    projectProtectedRecordsStable,
    dependencyArtifactsStable,
    bindingStable,
    attestationStable,
    inspectionStable: finalInspectionStable,
    terminationClean: lake.terminationReason === "exit",
    projectInputStable,
    projectOutputObserved,
  });
  const reuseEvidence: ProjectBuildReuseEvidenceV1 | undefined = passed
    ? {
        schemaVersion: 1,
        projectInput: {
          schema: "leanbun-project-input-tree-v1",
          treeHash: projectInputAfter.treeHash,
          entryCount: projectInputAfter.entryCount,
          fileCount: projectInputAfter.fileCount,
          byteCount: projectInputAfter.byteCount,
        },
        projectOutput: {
          schema: "leanbun-project-output-tree-v1",
          treeHash: projectOutputAfter.treeHash,
          entryCount: projectOutputAfter.entryCount,
          fileCount: projectOutputAfter.fileCount,
          byteCount: projectOutputAfter.byteCount,
        },
      }
    : undefined;
  const terminalRecord = await finalizeExecutionRecord(
    stateRoot,
    executionId,
    passed ? "completed" : "failed",
    new Date().toISOString(),
    {
      buildExecution: passed ? "completed" : "failed",
      lakeExitCode: lake.exitCode,
      projectProtectedRecordsStable,
      dependencyArtifactAfter,
      dependencyArtifactCount: artifactAfter.fileCount,
      bindingStable,
      attestationStable,
      inspectionStable: finalInspectionStable,
      terminationReason: lake.terminationReason,
      ...(lake.triggerSignal === undefined ? {} : { triggerSignal: lake.triggerSignal }),
      processGroupId: lake.processGroupId,
      terminationEscalated: lake.terminationEscalated,
      processGroupReaped,
      ...(reuseEvidence === undefined ? {} : { reuseEvidence }),
      ...(passed
        ? {}
        : {
            failureStage: lake.terminationReason === "exit"
              ? "post-build-verification" as const
              : "sandbox-execution" as const,
          }),
    },
  );
  const released = await releaseBuildLock(stateRoot, buildLock.document);
  diagnostics.push(
    diagnostic(
      "EXECUTION_RECORD_FINALIZED",
      "info",
      `execution record atomically transitioned to ${terminalRecord.document.status}`,
      [`executionId=${executionId}`],
    ),
    diagnostic("BUILD_LOCK_RELEASED", "info", "project/image build lock released", [
      `key=${buildLock.document.key}`,
    ]),
    ...(lake.terminationReason === "timeout"
      ? [diagnostic("LAKE_EXECUTION_TIMED_OUT", "error", "sandboxed Lake process group exceeded its deadline")]
      : lake.terminationReason === "signal"
        ? [diagnostic("LAKE_EXECUTION_CANCELLED", "error", "sandboxed Lake process group was cancelled", [lake.triggerSignal ?? "ABORT"])]
        : []),
    ...(projectInputStable
      ? []
      : [diagnostic("PROJECT_INPUT_DRIFTED", "error", "content-addressed project inputs changed during the build")]),
    ...(projectOutputObserved
      ? []
      : [diagnostic("PROJECT_OUTPUT_MISSING", "error", "project build output root was not observed after Lake execution")]),
    ...(reuseEvidence === undefined
      ? []
      : [diagnostic("REUSE_EVIDENCE_RECORDED", "info", "content-addressed project input and output evidence was recorded", [
          `input=${reuseEvidence.projectInput.treeHash}`,
          `output=${reuseEvidence.projectOutput.treeHash}`,
        ])]),
    diagnostic(
      passed ? "CONTROLLED_BUILD_PASSED" : "CONTROLLED_BUILD_FAILED",
      passed ? "info" : "error",
      passed
        ? "approved target completed and all protected evidence remained stable"
        : "controlled build failed execution or post-build evidence verification",
      passed ? [] : [`lakeExitCode=${lake.exitCode}`, lake.stderr.trim()],
    ),
  );
  return {
    ...base,
    status: passed ? "passed" : "failed",
    buildExecution: passed ? "completed" : "failed",
    verificationStatus: "approved",
    profileSha256: spec.profileSha256,
    lakeExitCode: lake.exitCode,
    projectProtectedRecordsStable,
    dependencyArtifactBefore,
    dependencyArtifactAfter,
    dependencyArtifactCount: artifactAfter.fileCount,
    bindingStable,
    attestationStable,
    terminationReason: lake.terminationReason,
    ...(lake.triggerSignal === undefined ? {} : { triggerSignal: lake.triggerSignal }),
    processGroupId: lake.processGroupId,
    terminationEscalated: lake.terminationEscalated,
    processGroupReaped,
    ...(reuseEvidence === undefined ? {} : { reuseEvidence }),
    buildLockKey: buildLock.document.key,
    buildLockPath: buildLock.path,
    buildLockReleased: released.status === "released" || released.status === "already-released",
    executionRecord: executionReference(terminalRecord),
    diagnostics,
  };
}
