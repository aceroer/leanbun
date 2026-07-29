import { afterAll, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  beginExecutionRecord,
  ExecutionRecordStoreError,
  finalizeExecutionRecord,
  listExecutionRecords,
  loadExecutionRecord,
} from "../src/adapters/execution-record-store";
import { canonicalizeDirectory } from "../src/adapters/filesystem";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const hash = "1".repeat(64);
const executionId = "12345678-1234-4123-8123-123456789abc";

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-execution-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected execution workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

function fixtureInput(id = executionId) {
  return {
    executionId: id,
    projectId: hash,
    projectPath: "/fixture/project",
    target: "Fixture",
    imageId: hash,
    bindingSha256: hash,
    attestationSha256: hash,
    profileSha256: hash,
    dependencyArtifactBefore: hash,
    startedAt: "2026-07-23T00:00:00.000Z",
  };
}

test.serial("execution record atomically transitions once from running to completed", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-execution-store-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);

  const running = await beginExecutionRecord(canonicalState, fixtureInput());
  expect(running.document.status).toBe("running");
  expect(running.document.finishedAt).toBeNull();
  expect(running.document.outcome).toBeNull();
  expect((await lstat(running.path)).mode & 0o777).toBe(0o444);

  const completed = await finalizeExecutionRecord(
    canonicalState,
    executionId,
    "completed",
    "2026-07-23T00:01:00.000Z",
    {
      buildExecution: "completed",
      lakeExitCode: 0,
      projectProtectedRecordsStable: true,
      dependencyArtifactAfter: hash,
      dependencyArtifactCount: 1,
      bindingStable: true,
      attestationStable: true,
      inspectionStable: true,
      terminationReason: "exit",
      processGroupId: 12345,
      terminationEscalated: false,
      processGroupReaped: true,
      reuseEvidence: {
        schemaVersion: 1,
        projectInput: {
          schema: "leanbun-project-input-tree-v1",
          treeHash: hash,
          entryCount: 2,
          fileCount: 1,
          byteCount: 16,
        },
        projectOutput: {
          schema: "leanbun-project-output-tree-v1",
          treeHash: hash,
          entryCount: 3,
          fileCount: 2,
          byteCount: 32,
        },
      },
    },
  );
  expect(completed.document.status).toBe("completed");
  expect(completed.document.outcome?.lakeExitCode).toBe(0);
  expect(completed.document.outcome?.terminationReason).toBe("exit");
  expect(completed.document.outcome?.reuseEvidence?.projectOutput.fileCount).toBe(2);
  expect(completed.sha256).not.toBe(running.sha256);
  expect((await lstat(completed.path)).mode & 0o777).toBe(0o444);
  expect((await readdir(join(stateRoot, "executions"))).sort()).toEqual([
    `${executionId}.json`,
  ]);
  expect((await loadExecutionRecord(canonicalState, executionId)).sha256).toBe(completed.sha256);
  expect((await listExecutionRecords(canonicalState)).map((record) => record.document.executionId)).toEqual([executionId]);

  let repeated: unknown;
  try {
    await finalizeExecutionRecord(
      canonicalState,
      executionId,
      "completed",
      "2026-07-23T00:02:00.000Z",
      { buildExecution: "completed", lakeExitCode: 0 },
    );
  } catch (error) {
    repeated = error;
  }
  expect(repeated).toBeInstanceOf(ExecutionRecordStoreError);
  expect((repeated as ExecutionRecordStoreError).code).toBe("EXECUTION_RECORD_CONFLICT");
  expect((await readdir(join(stateRoot, "executions"))).sort()).toEqual([
    `${executionId}.json`,
  ]);
});

test.serial("execution record refuses duplicate ids and mismatched terminal outcomes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-execution-conflict-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  await beginExecutionRecord(canonicalState, fixtureInput());

  let duplicate: unknown;
  try {
    await beginExecutionRecord(canonicalState, fixtureInput());
  } catch (error) {
    duplicate = error;
  }
  expect(duplicate).toBeInstanceOf(ExecutionRecordStoreError);
  expect((duplicate as ExecutionRecordStoreError).code).toBe("EXECUTION_RECORD_CONFLICT");

  let mismatch: unknown;
  try {
    await finalizeExecutionRecord(
      canonicalState,
      executionId,
      "failed",
      "2026-07-23T00:01:00.000Z",
      { buildExecution: "completed" },
    );
  } catch (error) {
    mismatch = error;
  }
  expect(mismatch).toBeInstanceOf(ExecutionRecordStoreError);
  expect((mismatch as ExecutionRecordStoreError).code).toBe("EXECUTION_RECORD_FAILED");
});

test.serial("execution record preserves an explicit failed terminal outcome", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-execution-failed-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const failedId = "87654321-4321-4321-8321-cba987654321";
  await beginExecutionRecord(canonicalState, fixtureInput(failedId));

  const failed = await finalizeExecutionRecord(
    canonicalState,
    failedId,
    "failed",
    "2026-07-23T00:01:00.000Z",
    {
      buildExecution: "failed",
      lakeExitCode: 1,
      failureStage: "post-build-verification",
      failureMessage: "fixture failure",
    },
  );
  expect(failed.document.status).toBe("failed");
  expect(failed.document.outcome).toEqual({
    buildExecution: "failed",
    lakeExitCode: 1,
    failureStage: "post-build-verification",
    failureMessage: "fixture failure",
  });
});

test.serial("execution record supports an explicit reused terminal outcome without Lake fields", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-execution-reused-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const reusedId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const sourceId = "11111111-2222-4333-8444-555555555555";
  const { profileSha256: _profileSha256, ...input } = fixtureInput(reusedId);
  await beginExecutionRecord(canonicalState, { ...input, reusePolicySha256: hash });
  const reused = await finalizeExecutionRecord(
    canonicalState,
    reusedId,
    "reused",
    "2026-07-23T00:01:00.000Z",
    {
      buildExecution: "reused",
      projectProtectedRecordsStable: true,
      bindingStable: true,
      attestationStable: true,
      inspectionStable: true,
      reusedFromExecutionId: sourceId,
      reuseEvidence: {
        schemaVersion: 1,
        projectInput: {
          schema: "leanbun-project-input-tree-v1",
          treeHash: hash,
          entryCount: 2,
          fileCount: 1,
          byteCount: 4,
        },
        projectOutput: {
          schema: "leanbun-project-output-tree-v1",
          treeHash: hash,
          entryCount: 3,
          fileCount: 2,
          byteCount: 8,
        },
      },
    },
  );
  expect(reused.document.status).toBe("reused");
  expect(reused.document.profileSha256).toBeUndefined();
  expect(reused.document.reusePolicySha256).toBe(hash);
  expect(reused.document.outcome?.reusedFromExecutionId).toBe(sourceId);
  expect(reused.document.outcome?.lakeExitCode).toBeUndefined();
});

test.serial("execution record refuses a symlinked store directory", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-execution-symlink-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  const outside = join(root, "outside");
  await mkdir(stateRoot);
  await mkdir(outside);
  await symlink(outside, join(stateRoot, "executions"));
  const canonicalState = await canonicalizeDirectory(stateRoot);

  let failure: unknown;
  try {
    await beginExecutionRecord(canonicalState, fixtureInput());
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(ExecutionRecordStoreError);
  expect((failure as ExecutionRecordStoreError).code).toBe("EXECUTION_RECORD_FAILED");
  expect(await readdir(outside)).toEqual([]);
});
