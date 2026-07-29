import { afterAll, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  acquireBuildLock,
  BuildLockStoreError,
  loadBuildLock,
  releaseBuildLock,
} from "../src/adapters/build-lock-store";
import { canonicalizeDirectory } from "../src/adapters/filesystem";
import { projectId } from "../src/domain/identity";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const imageId = "2".repeat(64);

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-build-lock-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) throw new Error(`refusing cleanup: ${workspace}`);
    await rm(workspace, { recursive: true, force: true });
  }
});

async function fixture(suffix: string) {
  const root = await mkdtemp(join(temporaryRoot, `leanbun-build-lock-${suffix}-`));
  workspaces.push(root);
  const state = join(root, "state");
  const project = join(root, "project");
  await mkdir(state);
  await mkdir(project);
  return {
    root,
    state: await canonicalizeDirectory(state),
    project: await canonicalizeDirectory(project),
  };
}

test("lock is immutable and release requires exact ownership", async () => {
  const value = await fixture("ownership");
  const lock = await acquireBuildLock(value.state, {
    executionId: "12345678-1234-4234-8234-123456789abc",
    projectId: projectId(value.project),
    projectPath: value.project,
    imageId,
    target: "Fixture",
    coordinatorPid: process.pid,
    acquiredAt: "2026-07-23T00:00:00.000Z",
  });
  expect((await lstat(lock.path)).mode & 0o777).toBe(0o444);
  expect((await loadBuildLock(value.state, lock.document.key))?.document).toEqual(lock.document);
  await expect(releaseBuildLock(value.state, { ...lock.document, executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }))
    .rejects.toMatchObject({ code: "BUILD_LOCK_CONFLICT" });
  expect((await releaseBuildLock(value.state, lock.document)).status).toBe("released");
  expect(await loadBuildLock(value.state, lock.document.key)).toBeUndefined();
});

test("lock store refuses a symlink directory", async () => {
  const value = await fixture("symlink");
  const outside = join(value.root, "outside");
  await mkdir(outside);
  await symlink(outside, join(value.state, "build-locks"));
  await expect(acquireBuildLock(value.state, {
    executionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    projectId: projectId(value.project),
    projectPath: value.project,
    imageId,
    target: "Fixture",
    coordinatorPid: process.pid,
    acquiredAt: new Date().toISOString(),
  })).rejects.toBeInstanceOf(BuildLockStoreError);
});

test("two Bun processes cannot hold the same project/image lock", async () => {
  const value = await fixture("race");
  const start = join(value.root, "start");
  const outputs = [join(value.root, "one.out"), join(value.root, "two.out")];
  const worker = join(import.meta.dir, "helpers/build-lock-worker.ts");
  const ids = ["cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"];
  const children = ids.map((id, index) => Bun.spawn({
    cmd: [process.execPath, worker, value.state, value.project, id, outputs[index]!, start, "400"],
    stdout: "pipe",
    stderr: "pipe",
  }));
  await writeFile(start, "go\n", { mode: 0o600 });
  const exits = await Promise.all(children.map((child) => child.exited));
  expect(exits).toEqual([0, 0]);
  const results = await Promise.all(outputs.map((path) => readFile(path, "utf8")));
  expect(results.filter((value) => value.startsWith("acquired:"))).toHaveLength(1);
  expect(results.filter((value) => value.startsWith("busy:"))).toHaveLength(1);
  const key = (await acquireBuildLock(value.state, {
    executionId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    projectId: projectId(value.project),
    projectPath: value.project,
    imageId,
    target: "Fixture",
    coordinatorPid: process.pid,
    acquiredAt: new Date().toISOString(),
  })).document;
  expect((await releaseBuildLock(value.state, key)).status).toBe("released");
});
