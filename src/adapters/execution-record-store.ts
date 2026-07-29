import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, readdir, realpath, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import type {
  ControlledBuildExecutionOutcomeV1,
  ControlledBuildExecutionRecordV1,
} from "../domain/build";
import type { CanonicalPath, Sha256 } from "../domain/model";
import { isWithin } from "./filesystem";

const executionIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const shaPattern = /^[0-9a-f]{64}$/;

export class ExecutionRecordStoreError extends Error {
  constructor(
    readonly code:
      | "EXECUTION_RECORD_BUSY"
      | "EXECUTION_RECORD_CONFLICT"
      | "EXECUTION_RECORD_FAILED",
    message: string,
  ) {
    super(message);
  }
}

export interface StoredExecutionRecord {
  path: CanonicalPath;
  sha256: Sha256;
  document: ControlledBuildExecutionRecordV1;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

function canonicalBytes(document: ControlledBuildExecutionRecordV1): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
}

function hashBytes(value: Uint8Array): Sha256 {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex") as Sha256;
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validOutcome(
  value: unknown,
  status: "completed" | "failed" | "reused",
): value is ControlledBuildExecutionOutcomeV1 {
  if (value === null || typeof value !== "object") return false;
  const outcome = value as Record<string, unknown>;
  if (outcome.buildExecution !== status) return false;
  if (outcome.lakeExitCode !== undefined && !Number.isInteger(outcome.lakeExitCode)) return false;
  for (const field of [
    "projectProtectedRecordsStable",
    "bindingStable",
    "attestationStable",
    "inspectionStable",
    "terminationEscalated",
    "processGroupReaped",
  ]) {
    if (outcome[field] !== undefined && typeof outcome[field] !== "boolean") return false;
  }
  if (
    outcome.dependencyArtifactAfter !== undefined &&
    (typeof outcome.dependencyArtifactAfter !== "string" || !shaPattern.test(outcome.dependencyArtifactAfter))
  ) return false;
  if (outcome.reuseEvidence !== undefined && !validReuseEvidence(outcome.reuseEvidence)) return false;
  if (status === "reused" && (
    outcome.reuseEvidence === undefined ||
    typeof outcome.reusedFromExecutionId !== "string" ||
    !executionIdPattern.test(outcome.reusedFromExecutionId) ||
    outcome.lakeExitCode !== undefined ||
    outcome.terminationReason !== undefined ||
    outcome.processGroupId !== undefined
  )) return false;
  if (status !== "reused" && outcome.reusedFromExecutionId !== undefined) return false;
  if (
    outcome.dependencyArtifactCount !== undefined &&
    (!Number.isSafeInteger(outcome.dependencyArtifactCount) || (outcome.dependencyArtifactCount as number) < 0)
  ) return false;
  if (
    outcome.terminationReason !== undefined &&
    !["exit", "timeout", "signal"].includes(String(outcome.terminationReason))
  ) return false;
  if (
    outcome.triggerSignal !== undefined &&
    !["SIGINT", "SIGTERM", "ABORT"].includes(String(outcome.triggerSignal))
  ) return false;
  if (
    outcome.processGroupId !== undefined &&
    (!Number.isSafeInteger(outcome.processGroupId) || (outcome.processGroupId as number) <= 0)
  ) return false;
  if (
    outcome.failureStage !== undefined &&
    !["sandbox-execution", "post-build-verification", "reuse-verification", "recovery", "internal"].includes(String(outcome.failureStage))
  ) return false;
  return outcome.failureMessage === undefined ||
    (typeof outcome.failureMessage === "string" && outcome.failureMessage.length <= 1024);
}

function validReuseTree(
  value: unknown,
  schema: "leanbun-project-input-tree-v1" | "leanbun-project-output-tree-v1",
): boolean {
  if (value === null || typeof value !== "object") return false;
  const tree = value as Record<string, unknown>;
  return tree.schema === schema &&
    typeof tree.treeHash === "string" && shaPattern.test(tree.treeHash) &&
    [tree.entryCount, tree.fileCount, tree.byteCount].every(
      (item) => Number.isSafeInteger(item) && (item as number) >= 0,
    );
}

function validReuseEvidence(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false;
  const evidence = value as Record<string, unknown>;
  return evidence.schemaVersion === 1 &&
    validReuseTree(evidence.projectInput, "leanbun-project-input-tree-v1") &&
    validReuseTree(evidence.projectOutput, "leanbun-project-output-tree-v1");
}

function validRecord(value: unknown): value is ControlledBuildExecutionRecordV1 {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== 1 ||
    record.recordType !== "controlled-build-execution" ||
    typeof record.executionId !== "string" ||
    !executionIdPattern.test(record.executionId) ||
    typeof record.projectId !== "string" ||
    !shaPattern.test(record.projectId) ||
    typeof record.projectPath !== "string" ||
    record.projectPath.length === 0 ||
    typeof record.target !== "string" ||
    record.target.length === 0 ||
    ![record.imageId, record.bindingSha256, record.attestationSha256,
      record.dependencyArtifactBefore].every((item) => typeof item === "string" && shaPattern.test(item)) ||
    !validTimestamp(record.startedAt)
  ) return false;
  const policyHashes = [record.profileSha256, record.reusePolicySha256];
  if (
    policyHashes.filter((item) => item !== undefined).length !== 1 ||
    !policyHashes.filter((item) => item !== undefined).every((item) => typeof item === "string" && shaPattern.test(item))
  ) return false;
  if (record.buildLockKey !== undefined && (typeof record.buildLockKey !== "string" || !shaPattern.test(record.buildLockKey))) {
    return false;
  }
  const recoveryFields = [record.coordinatorPid, record.projectProtectedBefore, record.projectProtectedRecordCount];
  const recoveryFieldsPresent = recoveryFields.filter((item) => item !== undefined).length;
  if (
    recoveryFieldsPresent !== 0 &&
    (recoveryFieldsPresent !== 3 ||
      !Number.isSafeInteger(record.coordinatorPid) ||
      (record.coordinatorPid as number) <= 0 ||
      typeof record.projectProtectedBefore !== "string" ||
      !shaPattern.test(record.projectProtectedBefore) ||
      !Number.isSafeInteger(record.projectProtectedRecordCount) ||
      (record.projectProtectedRecordCount as number) < 0)
  ) return false;
  if (record.status === "running") return record.finishedAt === null && record.outcome === null;
  if (record.status !== "completed" && record.status !== "failed" && record.status !== "reused") return false;
  return validTimestamp(record.finishedAt) && validOutcome(record.outcome, record.status);
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function prepareExecutionDirectory(
  stateRoot: CanonicalPath,
  create = true,
): Promise<CanonicalPath> {
  const directory = join(stateRoot, "executions");
  let created = false;
  if (create) {
    try {
      await mkdir(directory, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
    }
  }
  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(directory);
  } catch (error) {
    if (!create && errorCode(error) === "ENOENT") {
      throw new ExecutionRecordStoreError(
        "EXECUTION_RECORD_CONFLICT",
        `execution record store does not exist: ${directory}`,
      );
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      `execution record store is not a direct directory: ${directory}`,
    );
  }
  const canonical = await realpath(directory);
  if (canonical !== directory || !isWithin(stateRoot, canonical)) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      `execution record store escapes state root: ${directory} -> ${canonical}`,
    );
  }
  if (created) await syncDirectory(stateRoot);
  return canonical as CanonicalPath;
}

export async function loadExecutionRecord(
  stateRoot: CanonicalPath,
  executionId: string,
): Promise<StoredExecutionRecord> {
  if (!executionIdPattern.test(executionId)) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      "execution id is not a canonical UUID",
    );
  }
  const directory = await prepareExecutionDirectory(stateRoot, false);
  const target = join(directory, `${executionId}.json`);
  let document: ControlledBuildExecutionRecordV1;
  try {
    document = await readRecord(target);
  } catch (error) {
    if (errorCode(error) === "ENOENT") {
      throw new ExecutionRecordStoreError(
        "EXECUTION_RECORD_CONFLICT",
        `execution record does not exist: ${target}`,
      );
    }
    throw error;
  }
  return await verifiedStoredRecord(target, document);
}

export async function listExecutionRecords(
  stateRoot: CanonicalPath,
): Promise<readonly StoredExecutionRecord[]> {
  try {
    await lstat(join(stateRoot, "executions"));
  } catch (error) {
    if (errorCode(error) === "ENOENT") return [];
    throw error;
  }
  const directory = await prepareExecutionDirectory(stateRoot, false);
  const entries = await readdir(directory, { withFileTypes: true });
  const recordNames = entries
    .filter((entry) => entry.name.endsWith(".json"))
    .map((entry) => entry.name)
    .sort();
  if (recordNames.length > 10_000) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      `execution record scan exceeds limit: ${recordNames.length} > 10000`,
    );
  }
  const ids = recordNames.map((name) => name.slice(0, -".json".length));
  if (ids.some((id) => !executionIdPattern.test(id))) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_CONFLICT",
      "execution record store contains a non-canonical JSON record name",
    );
  }
  return await Promise.all(ids.map((id) => loadExecutionRecord(stateRoot, id)));
}

async function readRecord(path: string): Promise<ControlledBuildExecutionRecordV1> {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 64 * 1024) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_CONFLICT",
      `execution record is not a bounded regular file: ${path}`,
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_CONFLICT",
      `execution record is unreadable: ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!validRecord(value)) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_CONFLICT",
      `execution record schema is invalid: ${path}`,
    );
  }
  return value as ControlledBuildExecutionRecordV1;
}

async function verifiedStoredRecord(
  path: string,
  expected: ControlledBuildExecutionRecordV1,
): Promise<StoredExecutionRecord> {
  const document = await readRecord(path);
  const bytes = canonicalBytes(expected);
  if (JSON.stringify(document) !== JSON.stringify(expected)) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      `execution record failed immediate readback verification: ${path}`,
    );
  }
  const mode = (await lstat(path)).mode & 0o777;
  if (mode !== 0o444) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      `execution record mode is ${mode.toString(8)}, expected 444: ${path}`,
    );
  }
  return { path: path as CanonicalPath, sha256: hashBytes(bytes), document };
}

export async function beginExecutionRecord(
  stateRoot: CanonicalPath,
  input: Omit<
    ControlledBuildExecutionRecordV1,
    "schemaVersion" | "recordType" | "status" | "finishedAt" | "outcome"
  >,
): Promise<StoredExecutionRecord> {
  if (
    !executionIdPattern.test(input.executionId) ||
    ![
      input.imageId,
      input.bindingSha256,
      input.attestationSha256,
      input.dependencyArtifactBefore,
    ].every((value) => shaPattern.test(value))
    || [input.profileSha256, input.reusePolicySha256].filter((value) => value !== undefined).length !== 1
    || ![input.profileSha256, input.reusePolicySha256]
      .filter((value): value is string => value !== undefined)
      .every((value) => shaPattern.test(value))
  ) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      "execution identity contains an invalid UUID or SHA-256 value",
    );
  }
  const directory = await prepareExecutionDirectory(stateRoot);
  const target = join(directory, `${input.executionId}.json`);
  const lock = join(directory, `${input.executionId}.lock`);
  const temporary = join(directory, `.${input.executionId}.${process.pid}.${crypto.randomUUID()}.tmp`);
  const document: ControlledBuildExecutionRecordV1 = {
    schemaVersion: 1,
    recordType: "controlled-build-execution",
    ...input,
    status: "running",
    finishedAt: null,
    outcome: null,
  };
  const bytes = canonicalBytes(document);
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryHandle: Awaited<ReturnType<typeof open>> | undefined;
  let published = false;
  try {
    try {
      lockHandle = await open(
        lock,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        throw new ExecutionRecordStoreError(
          "EXECUTION_RECORD_BUSY",
          `execution record creation is already locked: ${lock}`,
        );
      }
      throw error;
    }
    try {
      await lstat(target);
      throw new ExecutionRecordStoreError(
        "EXECUTION_RECORD_CONFLICT",
        `execution record already exists: ${target}`,
      );
    } catch (error) {
      if (error instanceof ExecutionRecordStoreError) throw error;
      if (errorCode(error) !== "ENOENT") throw error;
    }
    temporaryHandle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    await temporaryHandle.chmod(0o444);
    await temporaryHandle.sync();
    await temporaryHandle.close();
    temporaryHandle = undefined;
    await rename(temporary, target);
    published = true;
    await syncDirectory(directory);
    return await verifiedStoredRecord(target, document);
  } catch (error) {
    if (error instanceof ExecutionRecordStoreError) throw error;
    throw new ExecutionRecordStoreError(
      errorCode(error) === "EEXIST" ? "EXECUTION_RECORD_CONFLICT" : "EXECUTION_RECORD_FAILED",
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    await temporaryHandle?.close().catch(() => undefined);
    if (!published) await unlink(temporary).catch(() => undefined);
    await lockHandle?.close().catch(() => undefined);
    if (lockHandle !== undefined) {
      await unlink(lock).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
    }
  }
}

export async function finalizeExecutionRecord(
  stateRoot: CanonicalPath,
  executionId: string,
  status: "completed" | "failed" | "reused",
  finishedAt: string,
  outcome: ControlledBuildExecutionOutcomeV1,
): Promise<StoredExecutionRecord> {
  if (!executionIdPattern.test(executionId) || outcome.buildExecution !== status) {
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      "terminal execution status and outcome are inconsistent",
    );
  }
  const directory = await prepareExecutionDirectory(stateRoot);
  const target = join(directory, `${executionId}.json`);
  const lock = join(directory, `${executionId}.lock`);
  const temporary = join(directory, `.${executionId}.${process.pid}.${crypto.randomUUID()}.tmp`);
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryHandle: Awaited<ReturnType<typeof open>> | undefined;
  let published = false;
  try {
    try {
      lockHandle = await open(
        lock,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        throw new ExecutionRecordStoreError(
          "EXECUTION_RECORD_BUSY",
          `execution record transition is already locked: ${lock}`,
        );
      }
      throw error;
    }
    const running = await readRecord(target);
    if (running.executionId !== executionId || running.status !== "running" || running.outcome !== null) {
      throw new ExecutionRecordStoreError(
        "EXECUTION_RECORD_CONFLICT",
        `execution record is not in the running state: ${target}`,
      );
    }
    const document: ControlledBuildExecutionRecordV1 = {
      ...running,
      status,
      finishedAt,
      outcome,
    };
    const bytes = canonicalBytes(document);
    temporaryHandle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    await temporaryHandle.chmod(0o444);
    await temporaryHandle.sync();
    await temporaryHandle.close();
    temporaryHandle = undefined;
    await rename(temporary, target);
    published = true;
    await syncDirectory(directory);
    return await verifiedStoredRecord(target, document);
  } catch (error) {
    if (error instanceof ExecutionRecordStoreError) throw error;
    throw new ExecutionRecordStoreError(
      "EXECUTION_RECORD_FAILED",
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    await temporaryHandle?.close().catch(() => undefined);
    if (!published) await unlink(temporary).catch(() => undefined);
    await lockHandle?.close().catch(() => undefined);
    if (lockHandle !== undefined) {
      await unlink(lock).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
    }
  }
}
