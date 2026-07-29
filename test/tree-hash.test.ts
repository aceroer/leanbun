import { afterAll, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { hashCanonicalTree, projectInputTreePolicy, sourceTreePolicy } from "../src/adapters/tree-hash";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const projectInputTreeGolden = new URL("../rust/golden/project-input-tree.tsv", import.meta.url);

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-tree-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected tree workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("project input identity excludes generated roots but binds source and binding bytes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-tree-project-input-"));
  workspaces.push(root);
  await mkdir(join(root, ".lake/build"), { recursive: true });
  await mkdir(join(root, ".leanbun/tmp"), { recursive: true });
  await writeFile(join(root, "Main.lean"), "def value := 1\n");
  await writeFile(join(root, ".leanbun/binding.json"), "binding-one\n");
  await writeFile(join(root, ".lake/build/Main.olean"), "output-one");
  await writeFile(join(root, ".leanbun/tmp/process.log"), "temp-one");

  const first = await hashCanonicalTree([{ owner: "project", path: root }], projectInputTreePolicy);
  await writeFile(join(root, ".lake/build/Main.olean"), "output-two");
  await writeFile(join(root, ".leanbun/tmp/process.log"), "temp-two");
  const generatedOnly = await hashCanonicalTree([{ owner: "project", path: root }], projectInputTreePolicy);
  expect(generatedOnly.treeHash).toBe(first.treeHash);

  await writeFile(join(root, ".leanbun/binding.json"), "binding-two\n");
  const bindingChanged = await hashCanonicalTree([{ owner: "project", path: root }], projectInputTreePolicy);
  expect(bindingChanged.treeHash).not.toBe(first.treeHash);
});

test("project input tree hash matches the shared Rust golden fixture", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-tree-project-golden-"));
  workspaces.push(root);
  await chmod(root, 0o755);
  const lines = (await readFile(projectInputTreeGolden, "utf8")).trimEnd().split("\n");
  const expected = lines.find((line) => line.startsWith("expected\t"))!.split("\t")[1];
  const counts = lines.find((line) => line.startsWith("counts\t"))!.split("\t").slice(1).map(Number);

  for (const line of lines) {
    const [kind, modeText, relativePath, hex = ""] = line.split("\t");
    if (kind !== "dir" && kind !== "excluded-dir" && kind !== "file" && kind !== "excluded-file") {
      continue;
    }
    const path = join(root, relativePath);
    if (kind === "dir" || kind === "excluded-dir") {
      await mkdir(path, { recursive: true });
    } else {
      await mkdir(resolve(path, ".."), { recursive: true });
      await writeFile(path, Buffer.from(hex, "hex"));
    }
    await chmod(path, Number.parseInt(modeText, 8));
  }
  await writeFile(join(root, ".git/ignored"), "git");
  await writeFile(join(root, ".lake/ignored"), "lake");
  await writeFile(join(root, ".leanbun/tmp/ignored"), "tmp");

  const observed = await hashCanonicalTree([{ owner: "project", path: root }], projectInputTreePolicy);
  expect(observed.treeHash).toBe(expected);
  expect([observed.entryCount, observed.fileCount, observed.byteCount]).toEqual(counts);
});

test("source tree identity ignores timestamps and excluded state but detects source bytes", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-tree-source-"));
  workspaces.push(root);
  await mkdir(join(root, ".git"));
  await mkdir(join(root, ".lake/build"), { recursive: true });
  const source = join(root, "Main.lean");
  await writeFile(source, "def value := 1\n");
  await writeFile(join(root, ".git/index"), "git-state");
  await writeFile(join(root, ".lake/build/Main.olean"), "build-state");

  const first = await hashCanonicalTree([{ owner: "sample", path: root }], sourceTreePolicy);
  await utimes(source, new Date(1_700_000_000_000), new Date(1_700_000_000_000));
  await writeFile(join(root, ".git/index"), "changed-git-state");
  await writeFile(join(root, ".lake/build/Main.olean"), "changed-build-state");
  const metadataOnly = await hashCanonicalTree([{ owner: "sample", path: root }], sourceTreePolicy);
  expect(metadataOnly.treeHash).toBe(first.treeHash);

  await writeFile(source, "def value := 2\n");
  const changed = await hashCanonicalTree([{ owner: "sample", path: root }], sourceTreePolicy);
  expect(changed.treeHash).not.toBe(first.treeHash);
});
