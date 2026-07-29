import { loadImageAttestation, loadProjectBinding } from "../adapters/binding";
import {
  acquireBuildLock,
  BuildLockStoreError,
  releaseBuildLock,
  type StoredBuildLock,
} from "../adapters/build-lock-store";
import {
  beginExecutionRecord,
  finalizeExecutionRecord,
  type StoredExecutionRecord,
} from "../adapters/execution-record-store";
import { canonicalizeDirectory, isWithin } from "../adapters/filesystem";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { CanonicalPath } from "../domain/model";
import { snapshotTree } from "../../scripts/nonmutation-snapshot";
import {
  hashProtectedProjectRecords,
  protectedProjectRecords,
  stableOutsideBuildRoots,
} from "./lake-build-probe";
import { preflightBuild } from "./preflight-build";
import { evaluateReuseSnapshot, type TreeComparison } from "./reuse-candidate";

const reusePolicyDocument = Object.freeze({
  schema: "leanbun-reuse-transaction-v1",
  candidate: "latest-compatible-completed-record",
  verification: "full-attestation-and-live-project-trees-under-build-lock",
  lake: "not-executed",
});

export function reusePolicySha256(): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(JSON.stringify(reusePolicyDocument));
  return hasher.digest("hex");
}

export interface ReuseTransactionReport {
  schemaVersion: 1;
  mode: "reuse-transaction";
  status: "reused" | "failed";
  buildExecution: "reused" | "failed" | "not-attempted";
  project: CanonicalPath;
  target: string;
  verificationStatus: "approved" | "denied";
  reusedFromExecutionId?: string;
  projectInput?: TreeComparison;
  projectOutput?: TreeComparison;
  buildLockKey?: string;
  buildLockPath?: CanonicalPath;
  buildLockReleased?: boolean;
  triggerSignal?: "SIGINT" | "SIGTERM" | "ABORT";
  executionRecord?: {
    executionId: string;
    status: "running" | "reused" | "failed";
    path: CanonicalPath;
    sha256: string;
  };
  diagnostics: readonly Diagnostic[];
}

function recordReference(record: StoredExecutionRecord): NonNullable<ReuseTransactionReport["executionRecord"]> {
  if (record.document.status !== "running" && record.document.status !== "reused" && record.document.status !== "failed") {
    throw new Error(`unexpected reuse transaction record status: ${record.document.status}`);
  }
  return {
    executionId: record.document.executionId,
    status: record.document.status,
    path: record.path,
    sha256: record.sha256,
  };
}

export async function runReuseTransaction(
  projectInput: string,
  target: string,
  options: { developmentRoot: string; stateRoot: string; signal?: AbortSignal },
): Promise<ReuseTransactionReport> {
  const [developmentRoot, project, stateRoot] = await Promise.all([
    canonicalizeDirectory(options.developmentRoot),
    canonicalizeDirectory(projectInput),
    canonicalizeDirectory(options.stateRoot),
  ]);
  const diagnostics: Diagnostic[] = [];
  const base = { schemaVersion: 1 as const, mode: "reuse-transaction" as const, project, target };
  if (options.signal?.aborted) {
    diagnostics.push(diagnostic("REUSE_TRANSACTION_CANCELLED", "error", "reuse transaction was cancelled before lock acquisition"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  if (!isWithin(developmentRoot, project)) {
    diagnostics.push(diagnostic("BUILD_SANDBOX_INVALID", "error", "reuse transaction project must be inside LEANBUN_DEV_ROOT"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  const initialBinding = await loadProjectBinding(project);
  if (initialBinding.status !== "valid") {
    diagnostics.push(diagnostic("BINDING_INVALID", "error", "reuse transaction requires a valid project binding"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  const initialAttestation = await loadImageAttestation(stateRoot, initialBinding.document.imageId);
  if (initialAttestation.status !== "valid") {
    diagnostics.push(diagnostic("ATTESTATION_INVALID", "error", "reuse transaction requires a valid sealed attestation"));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
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
    diagnostics.push(diagnostic(lockError?.code ?? "BUILD_LOCK_FAILED", "error", "reuse transaction could not acquire the project/image lock", [
      error instanceof Error ? error.message : String(error),
    ]));
    return { ...base, status: "failed", buildExecution: "not-attempted", verificationStatus: "denied", diagnostics };
  }
  diagnostics.push(diagnostic("BUILD_LOCK_ACQUIRED", "info", "project/image build lock acquired for reuse transaction", [
    `key=${buildLock.document.key}`,
  ]));
  let projectBefore: Awaited<ReturnType<typeof snapshotTree>>;
  let running: StoredExecutionRecord;
  try {
    projectBefore = await snapshotTree(project);
    running = await beginExecutionRecord(stateRoot, {
      executionId,
      projectId: initialBinding.document.projectId,
      projectPath: project,
      target,
      imageId: initialBinding.document.imageId,
      bindingSha256: initialBinding.sha256,
      attestationSha256: initialAttestation.sha256,
      reusePolicySha256: reusePolicySha256(),
      dependencyArtifactBefore: initialAttestation.document.artifactTreeHash,
      buildLockKey: buildLock.document.key,
      coordinatorPid: process.pid,
      projectProtectedBefore: hashProtectedProjectRecords(projectBefore.records),
      projectProtectedRecordCount: protectedProjectRecords(projectBefore.records).length,
      startedAt: new Date().toISOString(),
    });
  } catch (error) {
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("BUILD_LOCK_RELEASED", "info", "reuse lock released after execution record creation failed"),
      diagnostic("EXECUTION_RECORD_FAILED", "error", "reuse execution record could not be created", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "not-attempted",
      verificationStatus: "denied",
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      diagnostics,
    };
  }
  diagnostics.push(
    diagnostic("EXECUTION_RECORD_STARTED", "info", "reuse transaction received a running execution record", [`executionId=${executionId}`]),
    diagnostic("REUSE_TRANSACTION_STARTED", "info", "reuse verification started under the project/image lock"),
  );
  let finalizationAttempted = false;
  try {
    const preflight = await preflightBuild(project, target, { stateRoot, verifyAttestation: true });
    diagnostics.push(...preflight.diagnostics);
    const cancelled = options.signal?.aborted === true;
    const triggerSignal = cancelled
      ? options.signal?.reason === "SIGINT" || options.signal?.reason === "SIGTERM"
        ? options.signal.reason
        : "ABORT" as const
      : undefined;
    if (cancelled) {
      diagnostics.push(diagnostic("REUSE_TRANSACTION_CANCELLED", "error", "reuse transaction was cancelled during lock-held verification", [
        triggerSignal!,
      ]));
    }
    const [binding, attestation] = await Promise.all([
      loadProjectBinding(project),
      loadImageAttestation(stateRoot, initialBinding.document.imageId),
    ]);
    const bindingStable = binding.status === "valid" && binding.sha256 === initialBinding.sha256;
    const attestationStable = attestation.status === "valid" && attestation.sha256 === initialAttestation.sha256;
    const snapshot = binding.status === "valid" && attestation.status === "valid"
      ? await evaluateReuseSnapshot(stateRoot, project, target, {
          projectId: binding.document.projectId,
          imageId: binding.document.imageId,
          bindingSha256: binding.sha256,
          attestationSha256: attestation.sha256,
        })
      : { eligible: false } as const;
    const projectAfter = await snapshotTree(project);
    const projectProtectedRecordsStable = stableOutsideBuildRoots(projectBefore.records, projectAfter.records);
    const approved = !cancelled &&
      preflight.status === "approved" &&
      preflight.imageEvidence?.artifactTree !== undefined &&
      bindingStable &&
      attestationStable &&
      projectProtectedRecordsStable &&
      snapshot.eligible &&
      snapshot.candidate?.document.outcome?.reuseEvidence !== undefined;
    if (!cancelled && snapshot.candidate === undefined) {
      diagnostics.push(diagnostic("REUSE_CANDIDATE_NOT_FOUND", "error", "lock-held reuse verification found no compatible actual Lake execution"));
    }
    if (snapshot.projectInput !== undefined && !snapshot.projectInput.matches) {
      diagnostics.push(diagnostic("REUSE_INPUT_MISMATCH", "error", "lock-held project input does not match a compatible candidate"));
    }
    if (snapshot.projectOutput !== undefined && !snapshot.projectOutput.matches) {
      diagnostics.push(diagnostic("REUSE_OUTPUT_MISMATCH", "error", "lock-held project output does not match a compatible candidate"));
    }
    if (!approved) {
      finalizationAttempted = true;
      const terminal = await finalizeExecutionRecord(stateRoot, executionId, "failed", new Date().toISOString(), {
        buildExecution: "failed",
        projectProtectedRecordsStable,
        ...(preflight.imageEvidence?.artifactTree === undefined ? {} : {
          dependencyArtifactAfter: preflight.imageEvidence.artifactTree.treeHash,
          dependencyArtifactCount: preflight.imageEvidence.artifactTree.fileCount,
        }),
        bindingStable,
        attestationStable,
        inspectionStable: preflight.status === "approved",
        failureStage: "reuse-verification",
        failureMessage: cancelled
          ? `reuse transaction cancelled by ${triggerSignal}`
          : "lock-held reuse evidence did not satisfy every authorization and snapshot condition",
      });
      const released = await releaseBuildLock(stateRoot, buildLock.document);
      diagnostics.push(
        diagnostic("EXECUTION_RECORD_FINALIZED", "info", "reuse execution record atomically transitioned to failed"),
        diagnostic("BUILD_LOCK_RELEASED", "info", "project/image reuse lock released"),
        diagnostic("REUSE_TRANSACTION_FAILED", "error", "reuse was not performed; run the normal controlled build path explicitly"),
      );
      return {
        ...base,
        status: "failed",
        buildExecution: "failed",
        verificationStatus: preflight.status,
        ...(snapshot.candidate === undefined ? {} : { reusedFromExecutionId: snapshot.candidate.document.executionId }),
        ...(snapshot.projectInput === undefined ? {} : { projectInput: snapshot.projectInput }),
        ...(snapshot.projectOutput === undefined ? {} : { projectOutput: snapshot.projectOutput }),
        ...(triggerSignal === undefined ? {} : { triggerSignal }),
        buildLockKey: buildLock.document.key,
        buildLockPath: buildLock.path,
        buildLockReleased: released.status === "released" || released.status === "already-released",
        executionRecord: recordReference(terminal),
        diagnostics,
      };
    }
    const candidate = snapshot.candidate!;
    const reuseEvidence = candidate.document.outcome!.reuseEvidence!;
    const artifactTree = preflight.imageEvidence!.artifactTree!;
    finalizationAttempted = true;
    const terminal = await finalizeExecutionRecord(stateRoot, executionId, "reused", new Date().toISOString(), {
      buildExecution: "reused",
      projectProtectedRecordsStable: true,
      dependencyArtifactAfter: artifactTree.treeHash,
      dependencyArtifactCount: artifactTree.fileCount,
      bindingStable: true,
      attestationStable: true,
      inspectionStable: true,
      reuseEvidence,
      reusedFromExecutionId: candidate.document.executionId,
    });
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("EXECUTION_RECORD_FINALIZED", "info", "reuse execution record atomically transitioned to reused"),
      diagnostic("BUILD_LOCK_RELEASED", "info", "project/image reuse lock released"),
      diagnostic("LAKE_EXECUTION_NOT_ATTEMPTED", "info", "verified reuse transaction did not execute Lake"),
      diagnostic("REUSE_TRANSACTION_COMPLETED", "info", "candidate outputs were reused after lock-held full verification", [
        `sourceExecutionId=${candidate.document.executionId}`,
      ]),
    );
    return {
      ...base,
      status: "reused",
      buildExecution: "reused",
      verificationStatus: "approved",
      reusedFromExecutionId: candidate.document.executionId,
      projectInput: snapshot.projectInput!,
      projectOutput: snapshot.projectOutput!,
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      executionRecord: recordReference(terminal),
      diagnostics,
    };
  } catch (error) {
    if (finalizationAttempted) throw error;
    finalizationAttempted = true;
    const terminal = await finalizeExecutionRecord(stateRoot, executionId, "failed", new Date().toISOString(), {
      buildExecution: "failed",
      failureStage: "reuse-verification",
      failureMessage: (error instanceof Error ? error.message : String(error)).slice(0, 1024),
    });
    const released = await releaseBuildLock(stateRoot, buildLock.document);
    diagnostics.push(
      diagnostic("EXECUTION_RECORD_FINALIZED", "info", "reuse execution record atomically transitioned to failed"),
      diagnostic("BUILD_LOCK_RELEASED", "info", "project/image reuse lock released"),
      diagnostic("REUSE_TRANSACTION_FAILED", "error", "reuse verification could not complete", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return {
      ...base,
      status: "failed",
      buildExecution: "failed",
      verificationStatus: "denied",
      buildLockKey: buildLock.document.key,
      buildLockPath: buildLock.path,
      buildLockReleased: released.status === "released" || released.status === "already-released",
      executionRecord: recordReference(terminal),
      diagnostics,
    };
  }
}
