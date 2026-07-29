import { join } from "node:path";
import { loadImageAttestation, loadProjectBinding } from "../adapters/binding";
import { buildLockKey, loadBuildLock } from "../adapters/build-lock-store";
import { listExecutionRecords, type StoredExecutionRecord } from "../adapters/execution-record-store";
import { canonicalizeDirectory } from "../adapters/filesystem";
import {
  hashCanonicalTree,
  projectInputTreePolicy,
  projectOutputTreePolicy,
  type CanonicalTreeHash,
} from "../adapters/tree-hash";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { ProjectBuildReuseEvidenceV1 } from "../domain/build";
import type { CanonicalPath } from "../domain/model";
import { preflightBuild } from "./preflight-build";

export interface ReuseCandidateReport {
  schemaVersion: 1;
  mode: "reuse-candidate-check";
  status: "eligible" | "miss";
  buildExecution: "not-attempted";
  project: CanonicalPath;
  target: string;
  verificationStatus: "approved" | "denied";
  candidate?: {
    executionId: string;
    path: CanonicalPath;
    sha256: string;
    finishedAt: string;
  };
  projectInput?: TreeComparison;
  projectOutput?: TreeComparison;
  diagnostics: readonly Diagnostic[];
}

export interface TreeComparison {
  expectedHash: string;
  observedHash: string;
  expectedEntryCount: number;
  observedEntryCount: number;
  expectedFileCount: number;
  observedFileCount: number;
  expectedByteCount: number;
  observedByteCount: number;
  matches: boolean;
}

export interface ReuseSnapshot {
  candidate?: StoredExecutionRecord;
  projectInput?: TreeComparison;
  projectOutput?: TreeComparison;
  eligible: boolean;
}

function successfulCandidate(
  stored: StoredExecutionRecord,
  identity: {
    projectId: string;
    projectPath: string;
    imageId: string;
    target: string;
    bindingSha256: string;
    attestationSha256: string;
  },
): boolean {
  const record = stored.document;
  const outcome = record.outcome;
  return record.status === "completed" &&
    record.projectId === identity.projectId &&
    record.projectPath === identity.projectPath &&
    record.imageId === identity.imageId &&
    record.target === identity.target &&
    record.bindingSha256 === identity.bindingSha256 &&
    record.attestationSha256 === identity.attestationSha256 &&
    outcome?.buildExecution === "completed" &&
    outcome.lakeExitCode === 0 &&
    outcome.projectProtectedRecordsStable === true &&
    outcome.bindingStable === true &&
    outcome.attestationStable === true &&
    outcome.inspectionStable === true &&
    outcome.terminationReason === "exit" &&
    outcome.processGroupReaped === true &&
    outcome.reuseEvidence !== undefined;
}

export function selectReuseCandidate(
  records: readonly StoredExecutionRecord[],
  identity: Parameters<typeof successfulCandidate>[1],
): StoredExecutionRecord | undefined {
  return records
    .filter((record) => successfulCandidate(record, identity))
    .sort((left, right) => {
      const time = Date.parse(right.document.finishedAt!) - Date.parse(left.document.finishedAt!);
      return time === 0
        ? right.document.executionId.localeCompare(left.document.executionId)
        : time;
    })[0];
}

export function compareReuseTree(
  expected: ProjectBuildReuseEvidenceV1["projectInput"] | ProjectBuildReuseEvidenceV1["projectOutput"],
  observed: CanonicalTreeHash,
): TreeComparison {
  const matches = expected.schema === observed.schema &&
    expected.treeHash === observed.treeHash &&
    expected.entryCount === observed.entryCount &&
    expected.fileCount === observed.fileCount &&
    expected.byteCount === observed.byteCount &&
    observed.missingRoots.length === 0;
  return {
    expectedHash: expected.treeHash,
    observedHash: observed.treeHash,
    expectedEntryCount: expected.entryCount,
    observedEntryCount: observed.entryCount,
    expectedFileCount: expected.fileCount,
    observedFileCount: observed.fileCount,
    expectedByteCount: expected.byteCount,
    observedByteCount: observed.byteCount,
    matches,
  };
}

export async function evaluateReuseSnapshot(
  stateRoot: CanonicalPath,
  project: CanonicalPath,
  target: string,
  identity: {
    projectId: string;
    imageId: string;
    bindingSha256: string;
    attestationSha256: string;
  },
): Promise<ReuseSnapshot> {
  const records = await listExecutionRecords(stateRoot);
  const candidate = selectReuseCandidate(records, {
    ...identity,
    projectPath: project,
    target,
  });
  if (candidate === undefined || candidate.document.outcome?.reuseEvidence === undefined) {
    return { eligible: false };
  }
  const evidence = candidate.document.outcome.reuseEvidence;
  const [inputTree, outputTree] = await Promise.all([
    hashCanonicalTree([{ owner: "project", path: project }], projectInputTreePolicy),
    hashCanonicalTree([{ owner: "project-output", path: join(project, ".lake/build") }], projectOutputTreePolicy),
  ]);
  const projectInput = compareReuseTree(evidence.projectInput, inputTree);
  const projectOutput = compareReuseTree(evidence.projectOutput, outputTree);
  return {
    candidate,
    projectInput,
    projectOutput,
    eligible: projectInput.matches && projectOutput.matches,
  };
}

export async function checkReuseCandidate(
  projectInput: string,
  target: string,
  options: { stateRoot: string },
): Promise<ReuseCandidateReport> {
  const [project, stateRoot] = await Promise.all([
    canonicalizeDirectory(projectInput),
    canonicalizeDirectory(options.stateRoot),
  ]);
  const base = {
    schemaVersion: 1 as const,
    mode: "reuse-candidate-check" as const,
    buildExecution: "not-attempted" as const,
    project,
    target,
  };
  const preflight = await preflightBuild(project, target, { stateRoot, verifyAttestation: true });
  const diagnostics = [...preflight.diagnostics];
  if (preflight.status !== "approved" || preflight.binding.document === undefined || preflight.attestation.document === undefined) {
    diagnostics.push(diagnostic("REUSE_CANDIDATE_NOT_FOUND", "warning", "reuse candidate selection requires approved current evidence"));
    return { ...base, status: "miss", verificationStatus: "denied", diagnostics };
  }
  const [binding, attestation] = await Promise.all([
    loadProjectBinding(project),
    loadImageAttestation(stateRoot, preflight.binding.document.imageId),
  ]);
  if (binding.status !== "valid" || attestation.status !== "valid") {
    diagnostics.push(diagnostic("REUSE_CANDIDATE_NOT_FOUND", "warning", "binding or attestation changed after preflight"));
    return { ...base, status: "miss", verificationStatus: "denied", diagnostics };
  }
  const key = buildLockKey(binding.document.projectId, binding.document.imageId);
  const initialLock = await loadBuildLock(stateRoot, key);
  if (initialLock !== undefined) {
    diagnostics.push(diagnostic("BUILD_LOCK_BUSY", "warning", "reuse snapshot was not evaluated while a matching build lock was active", [
      `ownerExecutionId=${initialLock.document.executionId}`,
    ]));
    return { ...base, status: "miss", verificationStatus: "approved", diagnostics };
  }
  const snapshot = await evaluateReuseSnapshot(stateRoot, project, target, {
    projectId: binding.document.projectId,
    imageId: binding.document.imageId,
    bindingSha256: binding.sha256,
    attestationSha256: attestation.sha256,
  });
  const candidate = snapshot.candidate;
  if (candidate === undefined || candidate.document.outcome?.reuseEvidence === undefined) {
    diagnostics.push(diagnostic("REUSE_CANDIDATE_NOT_FOUND", "warning", "no compatible successful execution record carries reuse evidence"));
    return { ...base, status: "miss", verificationStatus: "approved", diagnostics };
  }
  const projectInputComparison = snapshot.projectInput!;
  const projectOutputComparison = snapshot.projectOutput!;
  const finalLock = await loadBuildLock(stateRoot, key);
  if (finalLock !== undefined) {
    diagnostics.push(diagnostic("BUILD_LOCK_BUSY", "warning", "a matching build became active during reuse snapshot verification", [
      `ownerExecutionId=${finalLock.document.executionId}`,
    ]));
  }
  if (!projectInputComparison.matches) {
    diagnostics.push(diagnostic("REUSE_INPUT_MISMATCH", "warning", "current project input tree does not match the candidate"));
  }
  if (!projectOutputComparison.matches) {
    diagnostics.push(diagnostic("REUSE_OUTPUT_MISMATCH", "warning", "current project output tree does not match the candidate"));
  }
  const eligible = finalLock === undefined && projectInputComparison.matches && projectOutputComparison.matches;
  if (eligible) {
    diagnostics.push(diagnostic("REUSE_CANDIDATE_ELIGIBLE", "info", "candidate input and output evidence matches the current project snapshot", [
      `executionId=${candidate.document.executionId}`,
    ]));
  }
  return {
    ...base,
    status: eligible ? "eligible" : "miss",
    verificationStatus: "approved",
    candidate: {
      executionId: candidate.document.executionId,
      path: candidate.path,
      sha256: candidate.sha256,
      finishedAt: candidate.document.finishedAt!,
    },
    projectInput: projectInputComparison,
    projectOutput: projectOutputComparison,
    diagnostics,
  };
}
