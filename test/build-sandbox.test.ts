import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { prepareBuildSandbox, runDetachedProcess } from "../src/adapters/build-sandbox";
import { sandboxProbePassed } from "../src/application/sandbox-probe";
import { stableOutsideBuildRoots } from "../src/application/lake-build-probe";
import type { SnapshotRecord } from "../scripts/nonmutation-snapshot";
import {
  controlledBuildPassed,
  runControlledBuildProbe,
} from "../src/application/controlled-build-probe";
import { coordinatorProcessState } from "../src/application/recover-execution";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const repository = resolve(import.meta.dir, "..");

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-build-sandbox-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected sandbox workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("Lake probe snapshot comparison ignores only declared writable roots", () => {
  const record = (path: string, mtimeNs: string) => ({ path, mtimeNs }) as SnapshotRecord;
  const before = [record("Main.lean", "1"), record(".lake/build/output.olean", "1")];
  expect(
    stableOutsideBuildRoots(before, [
      record("Main.lean", "1"),
      record(".lake/build/output.olean", "2"),
    ]),
  ).toBeTrue();
  expect(
    stableOutsideBuildRoots(before, [
      record("Main.lean", "2"),
      record(".lake/build/output.olean", "1"),
    ]),
  ).toBeFalse();
});

test("controlled build approval requires every post-build fact", () => {
  const facts = {
    lakeExitCode: 0,
    projectProtectedRecordsStable: true,
    dependencyArtifactsStable: true,
    bindingStable: true,
    attestationStable: true,
    inspectionStable: true,
    terminationClean: true,
    projectInputStable: true,
    projectOutputObserved: true,
  };
  expect(controlledBuildPassed(facts)).toBeTrue();
  expect(controlledBuildPassed({ ...facts, dependencyArtifactsStable: false })).toBeFalse();
  expect(controlledBuildPassed({ ...facts, lakeExitCode: 1 })).toBeFalse();
  expect(controlledBuildPassed({ ...facts, terminationClean: false })).toBeFalse();
  expect(controlledBuildPassed({ ...facts, projectInputStable: false })).toBeFalse();
  expect(controlledBuildPassed({ ...facts, projectOutputObserved: false })).toBeFalse();
});

test("controlled build cancelled before verification never creates an execution", async () => {
  const cancellation = new AbortController();
  cancellation.abort("SIGTERM");
  const report = await runControlledBuildProbe(
    join(repository, "test/fixtures/lake-basic"),
    "LeanBunLakeFixture",
    {
      developmentRoot: repository,
      stateRoot: join(repository, ".leanbun-dev/state"),
      elanHome: join(repository, ".leanbun-dev/lean/elan-home"),
      lake: join(repository, ".leanbun-dev/lean/elan-home/bin/lake"),
      signal: cancellation.signal,
    },
  );
  expect(report.status).toBe("failed");
  expect(report.buildExecution).toBe("not-attempted");
  expect(report.executionRecord).toBeUndefined();
  expect(report.diagnostics.map((value) => value.code)).toContain("LAKE_EXECUTION_CANCELLED");
});

test.serial("build sandbox profile exposes only project build and controlled temporary writes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-build-sandbox-probe-"));
  workspaces.push(root);
  const project = join(root, "project");
  const protectedRoot = join(root, "protected-dependency");
  await mkdir(project);
  await mkdir(protectedRoot);
  await writeFile(join(project, "Main.lean"), "def main := 1\n");
  await writeFile(join(protectedRoot, "artifact.olean"), "sealed-artifact");

  const spec = await prepareBuildSandbox(project, [protectedRoot]);
  expect(spec.profile).toContain(`(subpath ${JSON.stringify(spec.projectBuildRoot)})`);
  expect(spec.profile).toContain(`(subpath ${JSON.stringify(spec.projectConfigRoot)})`);
  expect(spec.profile).toContain(`(subpath ${JSON.stringify(spec.controlTempRoot)})`);
  expect(spec.profile).toContain("(deny network*)");
  expect(spec.profile).toContain("(deny file-write*)");
  expect(sandboxProbePassed({
    projectBuildWrite: "allowed",
    projectConfigWrite: "allowed",
    controlTempWrite: "allowed",
    projectSourceWrite: "denied",
    projectControlWrite: "denied",
    protectedWrites: ["denied"],
    networkListen: "denied",
  })).toBeTrue();
  expect(await readdir(spec.projectBuildRoot)).toEqual([]);
  expect(await readdir(spec.projectConfigRoot)).toEqual([]);
  expect(await readdir(spec.controlTempRoot)).toEqual([]);
  expect(await readdir(protectedRoot)).toEqual(["artifact.olean"]);
  expect(await Bun.file(join(project, "Main.lean")).text()).toBe("def main := 1\n");

  await expect(
    prepareBuildSandbox(project, [join(project, ".leanbun/tmp")]),
  ).rejects.toThrow("protected and writable sandbox roots overlap");
});

test.serial("sandbox timeout terminates and reaps the detached process group", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-build-sandbox-timeout-"));
  workspaces.push(root);
  const project = join(root, "project");
  const protectedRoot = join(root, "protected");
  await mkdir(project);
  await mkdir(protectedRoot);
  const spec = await prepareBuildSandbox(project, [protectedRoot]);
  const pidFile = join(spec.controlTempRoot, "timeout-child.pid");
  const result = await runDetachedProcess(
    process.execPath,
    [join(repository, "test/helpers/process-tree-worker.ts"), pidFile, "ignore-term"],
    spec.project,
    {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      TMPDIR: spec.controlTempRoot,
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: spec.controlTempRoot,
    },
    { timeoutMs: 500, terminationGraceMs: 100 },
  );
  const descendantPid = Number((await Bun.file(pidFile).text()).trim());
  expect(result.terminationReason).toBe("timeout");
  expect(result.terminationEscalated).toBeTrue();
  expect(result.processGroupId).toBeGreaterThan(0);
  expect(coordinatorProcessState(result.processGroupId)).toBe("absent");
  expect(coordinatorProcessState(descendantPid)).toBe("absent");
});

test.serial("sandbox abort signal terminates and reaps the detached process group", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-build-sandbox-signal-"));
  workspaces.push(root);
  const project = join(root, "project");
  const protectedRoot = join(root, "protected");
  await mkdir(project);
  await mkdir(protectedRoot);
  const spec = await prepareBuildSandbox(project, [protectedRoot]);
  const pidFile = join(spec.controlTempRoot, "signal-child.pid");
  const cancellation = new AbortController();
  const timer = setTimeout(() => cancellation.abort("SIGINT"), 500);
  const result = await runDetachedProcess(
    process.execPath,
    [join(repository, "test/helpers/process-tree-worker.ts"), pidFile],
    spec.project,
    {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      TMPDIR: spec.controlTempRoot,
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: spec.controlTempRoot,
    },
    { timeoutMs: 5_000, terminationGraceMs: 500, signal: cancellation.signal },
  );
  clearTimeout(timer);
  const descendantPid = Number((await Bun.file(pidFile).text()).trim());
  expect(result.terminationReason).toBe("signal");
  expect(result.triggerSignal).toBe("SIGINT");
  expect(result.terminationEscalated).toBeFalse();
  expect(coordinatorProcessState(result.processGroupId)).toBe("absent");
  expect(coordinatorProcessState(descendantPid)).toBe("absent");
});
