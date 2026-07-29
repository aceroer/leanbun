import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { snapshotTree } from "../scripts/nonmutation-snapshot";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-m4-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected M4 workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("complete snapshot is stable and detects a content change", async () => {
  const workspace = await mkdtemp(join(temporaryRoot, "leanbun-m4-snapshot-"));
  workspaces.push(workspace);
  await mkdir(join(workspace, "nested"));
  await writeFile(join(workspace, "nested/value.txt"), "before\n");

  const first = await snapshotTree(workspace);
  const second = await snapshotTree(workspace);
  expect(second.treeHash).toBe(first.treeHash);
  expect(second.records).toEqual(first.records);

  await writeFile(join(workspace, "nested/value.txt"), "after\n");
  const changed = await snapshotTree(workspace);
  expect(changed.treeHash).not.toBe(first.treeHash);
});
