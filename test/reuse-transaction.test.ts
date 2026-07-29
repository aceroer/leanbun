import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { reusePolicySha256, runReuseTransaction } from "../src/application/reuse-transaction";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-reuse-transaction-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) throw new Error(`refusing cleanup: ${workspace}`);
    await rm(workspace, { recursive: true, force: true });
  }
});

test("reuse policy identity is deterministic and content addressed", () => {
  expect(reusePolicySha256()).toMatch(/^[0-9a-f]{64}$/);
  expect(reusePolicySha256()).toBe(reusePolicySha256());
});

test("reuse transaction refuses a project outside the development root without state writes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-reuse-transaction-boundary-"));
  workspaces.push(root);
  const developmentRoot = join(root, "development");
  const project = join(root, "outside-project");
  const stateRoot = join(root, "state");
  await mkdir(developmentRoot);
  await mkdir(project);
  await mkdir(stateRoot);
  const report = await runReuseTransaction(project, "Fixture", { developmentRoot, stateRoot });
  expect(report.status).toBe("failed");
  expect(report.buildExecution).toBe("not-attempted");
  expect(report.diagnostics.map((value) => value.code)).toContain("BUILD_SANDBOX_INVALID");
  expect(await readdir(stateRoot)).toEqual([]);
});

test("reuse transaction cancelled before lock acquisition performs no state writes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-reuse-transaction-cancelled-"));
  workspaces.push(root);
  const developmentRoot = join(root, "development");
  const project = join(developmentRoot, "project");
  const stateRoot = join(root, "state");
  await mkdir(project, { recursive: true });
  await mkdir(stateRoot);
  const cancellation = new AbortController();
  cancellation.abort("SIGTERM");
  const report = await runReuseTransaction(project, "Fixture", {
    developmentRoot,
    stateRoot,
    signal: cancellation.signal,
  });
  expect(report.status).toBe("failed");
  expect(report.buildExecution).toBe("not-attempted");
  expect(report.diagnostics.map((value) => value.code)).toContain("REUSE_TRANSACTION_CANCELLED");
  expect(await readdir(stateRoot)).toEqual([]);
});
