import { afterAll, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { inspectDependencyProvider } from "../src/adapters/dependency-library";
import { inspectProject } from "../src/application/inspect-project";

const repository = resolve(import.meta.dir, "..");
const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

async function temporaryWorkspace(label: string): Promise<string> {
  const workspace = await mkdtemp(join(temporaryRoot, `leanbun-m2-${label}-`));
  workspaces.push(workspace);
  return workspace;
}

async function runGit(cwd: string, args: string[]): Promise<string> {
  const child = Bun.spawn({
    cmd: ["/usr/bin/git", ...args],
    cwd,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
    },
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) throw new Error(`git ${args.join(" ")} failed: ${stderr}`);
  return stdout.trim();
}

async function fileIdentity(path: string): Promise<{ size: number; mtimeMs: number; sha256: string }> {
  const metadata = await stat(path);
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(await Bun.file(path).arrayBuffer());
  return { size: metadata.size, mtimeMs: metadata.mtimeMs, sha256: hasher.digest("hex") };
}

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-m2-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected M2 workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test.serial("registered nine-package provider matches without writing Git indexes", async () => {
  const project = await temporaryWorkspace("registered");
  await cp(join(repository, "test/fixtures/mathlib-project"), project, { recursive: true });
  await mkdir(join(project, ".lake"), { recursive: true });
  await cp(process.env.LEANBUN_PROVIDER_OVERRIDES!, join(project, ".lake/package-overrides.json"));

  const overrides = JSON.parse(
    await readFile(process.env.LEANBUN_PROVIDER_OVERRIDES!, "utf8"),
  ) as { packages: Array<{ name: string; dir: string }> };
  const indexes = overrides.packages.map((value) => join(value.dir, ".git/index"));
  const mathlib = overrides.packages.find((value) => value.name === "mathlib")!;
  const cacheEntries = (await readdir(process.env.LEANBUN_PROVIDER_CACHE_ROOT!))
    .filter((value) => value.endsWith(".ltar"))
    .sort();
  const representativeArtifacts = [
    join(mathlib.dir, ".lake/build/lib/lean/Mathlib/Data/Nat/Prime/Basic.olean"),
    join(process.env.LEANBUN_PROVIDER_CACHE_ROOT!, cacheEntries[0]!),
  ];
  const unchangedFiles = [...indexes, ...representativeArtifacts];
  const before = await Promise.all(unchangedFiles.map(fileIdentity));
  const report = await inspectProject({
    project,
    provider: "dependency-library",
    hashMode: "sha256",
    artifactMode: "summary",
  });
  const after = await Promise.all(unchangedFiles.map(fileIdentity));

  expect(report.provider?.id).toBe("lean4-v4.32.0_mathlib-81a5d257c8e4");
  expect(report.provider?.state).toBe("matched");
  expect(report.provider?.packageCount).toBe(9);
  expect(report.packages).toHaveLength(9);
  expect(report.packages.every((value) => value.state === "matched")).toBeTrue();
  expect(report.overrides.state).toBe("registered");
  expect(report.artifacts.mode).toBe("summary");
  expect(report.artifacts.complete).toBeTrue();
  expect(report.artifacts.counts.olean).toBeGreaterThan(8_000);
  expect(report.artifacts.counts.hash).toBeGreaterThan(40_000);
  expect(report.artifacts.counts.ltar).toBeGreaterThan(20_000);
  expect(report.artifacts.observed).toEqual([]);
  expect(report.diagnostics.map((value) => value.code)).toContain("HASH_FILE_UNVERIFIED");
  expect(report.diagnostics.map((value) => value.code)).toContain(
    "DEPENDENCY_ARTIFACT_MISSING",
  );
  expect(report.diagnostics.some((value) => value.severity === "error")).toBeFalse();
  expect(after).toEqual(before);

  await writeFile(join(project, "lean-toolchain"), "leanprover/lean4:v4.31.0\n");
  const wrongToolchain = await inspectProject({
    project,
    provider: "dependency-library",
    hashMode: "metadata",
  });
  expect(wrongToolchain.diagnostics.map((value) => value.code)).toContain(
    "TOOLCHAIN_MISMATCH",
  );
});

test.serial("provider local fixture locates dirty, revision, and path drift", async () => {
  const root = await temporaryWorkspace("drift");
  const packageRoot = join(root, "packages");
  const packageDirectory = join(packageRoot, "sample");
  await mkdir(packageDirectory, { recursive: true });
  await runGit(packageDirectory, ["init", "--quiet"]);
  await writeFile(join(packageDirectory, "Sample.lean"), "def sample := 1\n");
  await runGit(packageDirectory, ["add", "Sample.lean"]);
  await runGit(packageDirectory, [
    "-c",
    "user.name=LeanBun Test",
    "-c",
    "user.email=leanbun@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "fixture",
  ]);
  const revision = await runGit(packageDirectory, ["rev-parse", "HEAD"]);
  const registry = join(root, "registry.json");
  const overrides = join(root, "overrides.json");
  const writeRegistry = async (rev: string) =>
    writeFile(
      registry,
      JSON.stringify({ version: "1.2.0", packages: [{ name: "sample", type: "git", rev }] }),
    );
  const writeOverride = async (dir: string) =>
    writeFile(
      overrides,
      JSON.stringify({ version: "1.2.0", packages: [{ name: "sample", type: "path", dir }] }),
    );
  await writeRegistry(revision);
  await writeOverride(packageDirectory);
  const config = {
    id: "fixture",
    toolchain: "leanprover/lean4:v4.32.0",
    registry,
    overrides,
    packageRoot,
    cacheRoot: root,
  };

  const matched = await inspectDependencyProvider(config);
  expect(matched.evidence.state).toBe("matched");
  expect(matched.packages[0]?.state).toBe("matched");

  await writeFile(join(packageDirectory, "untracked.txt"), "dirty\n");
  const dirty = await inspectDependencyProvider(config);
  expect(dirty.packages[0]?.state).toBe("dirty");
  expect(dirty.diagnostics.map((value) => value.code)).toContain("PACKAGE_DIRTY");

  await writeRegistry("0000000000000000000000000000000000000000");
  const revisionDrift = await inspectDependencyProvider(config);
  expect(revisionDrift.packages[0]?.state).toBe("mismatched");
  expect(revisionDrift.diagnostics.map((value) => value.code)).toContain(
    "PACKAGE_REVISION_MISMATCH",
  );

  await writeOverride(root);
  const pathDrift = await inspectDependencyProvider(config);
  expect(pathDrift.packages[0]?.state).toBe("missing");
  expect(pathDrift.diagnostics.map((value) => value.code)).toContain(
    "PROVIDER_PACKAGE_MISSING",
  );
});
