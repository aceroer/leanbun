import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  beginExecutionRecord,
  finalizeExecutionRecord,
  loadExecutionRecord,
} from "../src/adapters/execution-record-store";
import { canonicalizeDirectory } from "../src/adapters/filesystem";
import { acquireBuildLock, loadBuildLock, releaseBuildLock } from "../src/adapters/build-lock-store";
import { projectId } from "../src/domain/identity";
import {
  coordinatorProcessState,
  recoverStaleExecution,
  recoveryEvidenceStable,
} from "../src/application/recover-execution";
import { parseLsofWorkingDirectories } from "../src/adapters/process";
import { auditProjectWorkingDirectoryProcesses } from "../src/adapters/process";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const hash = "1".repeat(64);

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-recovery-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected recovery workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("recovery evidence requires every protected fact", () => {
  const facts = {
    projectProtectedRecordsStable: true,
    dependencyArtifactsStable: true,
    bindingStable: true,
    attestationStable: true,
    inspectionStable: true,
  };
  expect(recoveryEvidenceStable(facts)).toBeTrue();
  expect(recoveryEvidenceStable({ ...facts, bindingStable: false })).toBeFalse();
  expect(coordinatorProcessState(process.pid)).toBe("active");
  expect(coordinatorProcessState(2_147_483_647)).toBe("absent");
  expect(parseLsofWorkingDirectories("p12\nclake\nfcwd\nn/tmp/project\np13\ncleanc\nfcwd\nn/tmp/project/sub\n")).toEqual([
    { pid: 12, command: "lake", cwd: "/tmp/project" },
    { pid: 13, command: "leanc", cwd: "/tmp/project/sub" },
  ]);
});

test.serial("recovery refuses a running record whose coordinator is active", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-recovery-active-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  const project = join(root, "not-needed-while-active");
  await mkdir(project);
  await mkdir(stateRoot);
  const canonicalProject = await canonicalizeDirectory(project);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const executionId = "abcdef12-3456-4789-8abc-def123456789";
  const lock = await acquireBuildLock(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    coordinatorPid: process.pid,
    acquiredAt: "2026-07-23T00:00:00.000Z",
  });
  await beginExecutionRecord(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    bindingSha256: hash,
    attestationSha256: hash,
    reusePolicySha256: hash,
    dependencyArtifactBefore: hash,
    buildLockKey: lock.document.key,
    coordinatorPid: process.pid,
    projectProtectedBefore: hash,
    projectProtectedRecordCount: 1,
    startedAt: "2026-07-23T00:00:00.000Z",
  });

  const report = await recoverStaleExecution(executionId, {
    developmentRoot: root,
    stateRoot,
  });
  expect(report.status).toBe("blocked");
  expect(report.executionKind).toBe("reuse");
  expect(report.coordinatorState).toBe("active");
  expect(report.diagnostics.map((value) => value.code)).toContain("EXECUTION_COORDINATOR_ACTIVE");
  expect((await loadExecutionRecord(canonicalState, executionId)).document.status).toBe("running");
  await releaseBuildLock(canonicalState, lock.document);
});

test.serial("recovery refuses an orphan record while a project cwd process remains active", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-recovery-cwd-"));
  workspaces.push(root);
  const project = join(root, "project");
  const stateRoot = join(root, "state");
  await mkdir(project);
  await mkdir(stateRoot);
  const canonicalProject = await canonicalizeDirectory(project);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const executionId = "fedcba98-7654-4321-8fed-cba987654321";
  const lock = await acquireBuildLock(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    coordinatorPid: 2_147_483_647,
    acquiredAt: "2026-07-23T00:00:00.000Z",
  });
  await beginExecutionRecord(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    bindingSha256: hash,
    attestationSha256: hash,
    profileSha256: hash,
    dependencyArtifactBefore: hash,
    buildLockKey: lock.document.key,
    coordinatorPid: 2_147_483_647,
    projectProtectedBefore: hash,
    projectProtectedRecordCount: 1,
    startedAt: "2026-07-23T00:00:00.000Z",
  });
  const child = Bun.spawn({ cmd: ["/bin/sleep", "30"], cwd: project, stdout: "ignore", stderr: "ignore" });
  try {
    let observed = false;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const audit = await auditProjectWorkingDirectoryProcesses(canonicalProject);
      if (audit.status === "complete" && audit.processes.some((value) => value.pid === child.pid)) {
        observed = true;
        break;
      }
      await Bun.sleep(25);
    }
    expect(observed).toBeTrue();
    const report = await recoverStaleExecution(executionId, {
      developmentRoot: root,
      stateRoot,
    });
    expect(report.status).toBe("blocked");
    expect(report.projectProcessState).toBe("active");
    expect(report.projectProcesses?.map((value) => value.pid)).toContain(child.pid);
    expect(report.diagnostics.map((value) => value.code)).toContain("EXECUTION_PROJECT_PROCESS_ACTIVE");
    expect((await loadExecutionRecord(canonicalState, executionId)).document.status).toBe("running");
  } finally {
    child.kill("SIGTERM");
    await child.exited;
    await releaseBuildLock(canonicalState, lock.document);
  }
});

test.serial("recovery releases an owned lock left after reused terminal publication", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-recovery-terminal-lock-"));
  workspaces.push(root);
  const project = join(root, "project");
  const stateRoot = join(root, "state");
  await mkdir(project);
  await mkdir(stateRoot);
  const canonicalProject = await canonicalizeDirectory(project);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const executionId = "01234567-89ab-4cde-8fab-0123456789ab";
  const lock = await acquireBuildLock(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    coordinatorPid: 2_147_483_647,
    acquiredAt: "2026-07-23T00:00:00.000Z",
  });
  await beginExecutionRecord(canonicalState, {
    executionId,
    projectId: projectId(canonicalProject),
    projectPath: canonicalProject,
    target: "Fixture",
    imageId: hash,
    bindingSha256: hash,
    attestationSha256: hash,
    reusePolicySha256: hash,
    dependencyArtifactBefore: hash,
    buildLockKey: lock.document.key,
    coordinatorPid: 2_147_483_647,
    projectProtectedBefore: hash,
    projectProtectedRecordCount: 1,
    startedAt: "2026-07-23T00:00:00.000Z",
  });
  await finalizeExecutionRecord(canonicalState, executionId, "reused", "2026-07-23T00:00:01.000Z", {
    buildExecution: "reused",
    projectProtectedRecordsStable: true,
    bindingStable: true,
    attestationStable: true,
    inspectionStable: true,
    reusedFromExecutionId: "11111111-2222-4333-8444-555555555555",
    reuseEvidence: {
      schemaVersion: 1,
      projectInput: {
        schema: "leanbun-project-input-tree-v1",
        treeHash: hash,
        entryCount: 1,
        fileCount: 1,
        byteCount: 1,
      },
      projectOutput: {
        schema: "leanbun-project-output-tree-v1",
        treeHash: hash,
        entryCount: 1,
        fileCount: 1,
        byteCount: 1,
      },
    },
  });

  const report = await recoverStaleExecution(executionId, { developmentRoot: root, stateRoot });
  expect(report.status).toBe("lock-released");
  expect(report.executionKind).toBe("reuse");
  expect(report.buildLockReleased).toBeTrue();
  expect(await loadBuildLock(canonicalState, lock.document.key)).toBeUndefined();
  expect((await loadExecutionRecord(canonicalState, executionId)).document.status).toBe("reused");
});
