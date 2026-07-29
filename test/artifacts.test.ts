import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { observeArtifacts } from "../src/adapters/artifacts";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

async function temporaryWorkspace(label: string): Promise<string> {
  const workspace = await mkdtemp(join(temporaryRoot, `leanbun-m3-${label}-`));
  workspaces.push(workspace);
  return workspace;
}

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-m3-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected M3 workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("full SHA-256 observation records real bytes without trusting .hash", async () => {
  const workspace = await temporaryWorkspace("full");
  const build = join(workspace, "build");
  const cache = join(workspace, "cache");
  await mkdir(build);
  await mkdir(cache);
  for (const [name, content] of [
    ["A.olean", "olean-bytes"],
    ["A.ilean", "ilean-bytes"],
    ["A.trace", "trace-bytes"],
    ["A.olean.hash", "untrusted-hash"],
  ]) {
    await writeFile(join(build, name), content);
  }
  await writeFile(join(cache, "cache-entry.ltar"), "archive-bytes");
  const before = await stat(join(build, "A.olean"));

  const result = await observeArtifacts(
    [
      { owner: "sample", path: build, role: "package" },
      { owner: "cache", path: cache, role: "cache" },
    ],
    "full",
    "sha256",
  );
  const after = await stat(join(build, "A.olean"));

  expect(result.evidence.complete).toBeTrue();
  expect(result.evidence.total).toBe(5);
  expect(result.evidence.counts).toEqual({ olean: 1, ilean: 1, trace: 1, hash: 1, ltar: 1 });
  expect(result.evidence.observed).toHaveLength(5);
  expect(result.evidence.observed.every((value) => value.sha256?.length === 64)).toBeTrue();
  expect(result.evidence.observed.every((value) => value.stability === "stable")).toBeTrue();
  expect(result.evidence.unverifiedHashFiles).toHaveLength(1);
  expect(result.diagnostics.map((value) => value.code)).toContain("HASH_FILE_UNVERIFIED");
  expect({ size: after.size, mtimeMs: after.mtimeMs }).toEqual({
    size: before.size,
    mtimeMs: before.mtimeMs,
  });
});

test("artifact observer skips links and classifies missing package evidence", async () => {
  const workspace = await temporaryWorkspace("risks");
  const build = join(workspace, "build");
  const outside = join(workspace, "outside.olean");
  await mkdir(build);
  await writeFile(join(build, "Only.olean"), "object");
  await writeFile(outside, "outside");
  await symlink(outside, join(build, "linked.olean"));

  const result = await observeArtifacts(
    [
      { owner: "no-trace", path: build, role: "package" },
      { owner: "missing", path: join(workspace, "missing-build"), role: "package" },
    ],
    "full",
    "metadata",
  );
  const codes = result.diagnostics.map((value) => value.code);
  expect(result.evidence.total).toBe(1);
  expect(codes).toContain("ARTIFACT_SYMLINK_SKIPPED");
  expect(codes).toContain("TRACE_MISSING");
  expect(codes).toContain("DEPENDENCY_ARTIFACT_MISSING");
});
