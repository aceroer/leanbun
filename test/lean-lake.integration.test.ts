import { afterAll, expect, test } from "bun:test";
import { cp, mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dir, "..");
const fixtureRoot = join(repository, "test/fixtures");
const temporaryRoot = process.env.TMPDIR!;
const elanHome = process.env.ELAN_HOME!;
const lake = join(elanHome, "bin/lake");
const packageOverrides = process.env.LEANBUN_PACKAGE_OVERRIDES!;
const mathlibRoot = join(
  process.env.LEANBUN_DEV_ROOT!,
  "lean/package-set/packages/mathlib",
);
const primeOlean = join(
  mathlibRoot,
  ".lake/build/lib/lean/Mathlib/Data/Nat/Prime/Basic.olean",
);
const gcdOlean = join(
  mathlibRoot,
  ".lake/build/lib/lean/Mathlib/Data/Nat/GCD/Basic.olean",
);

const temporaryWorkspaces: string[] = [];

type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

async function run(executable: string, args: string[], cwd: string): Promise<CommandResult> {
  const process = Bun.spawn({
    cmd: [executable, ...args],
    cwd,
    env: { ...processEnv() },
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
    timeout: 120_000,
    killSignal: "SIGTERM",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  return { stdout, stderr, exitCode };
}

function processEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

async function stageFixture(name: string): Promise<string> {
  const workspace = await mkdtemp(join(temporaryRoot, `leanbun-${name}-`));
  temporaryWorkspaces.push(workspace);
  await cp(join(fixtureRoot, name), workspace, { recursive: true });
  return workspace;
}

async function fileEvidence(path: string): Promise<{ size: number; mtimeMs: number; sha256: string }> {
  const metadata = await stat(path);
  const hasher = new Bun.CryptoHasher("sha256");
  for await (const chunk of Bun.file(path).stream()) hasher.update(chunk);
  return { size: metadata.size, mtimeMs: metadata.mtimeMs, sha256: hasher.digest("hex") };
}

afterAll(async () => {
  const allowedPrefix = join(resolve(temporaryRoot), "leanbun-");
  for (const workspace of temporaryWorkspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected integration workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test.serial(
  "Lake builds and reuses a dependency-free Lean library and executable",
  async () => {
    const workspace = await stageFixture("lake-basic");
    const firstBuild = await run(lake, ["--verbose", "build"], workspace);
    expect(firstBuild.exitCode, `${firstBuild.stdout}\n${firstBuild.stderr}`).toBe(0);

    const executable = await run(lake, ["exe", "leanbun_lake_fixture"], workspace);
    expect(executable.exitCode, `${executable.stdout}\n${executable.stderr}`).toBe(0);
    expect(executable.stdout.trim()).toBe("42");

    const olean = join(workspace, ".lake/build/lib/lean/LeanBunLakeFixture/Basic.olean");
    const before = await fileEvidence(olean);
    const secondBuild = await run(lake, ["build"], workspace);
    expect(secondBuild.exitCode, `${secondBuild.stdout}\n${secondBuild.stderr}`).toBe(0);
    const after = await fileEvidence(olean);
    expect(after).toEqual(before);
  },
  120_000,
);

test.serial(
  "Lake uses the isolated Mathlib override without changing the imported dependency artifact",
  async () => {
    const workspace = await stageFixture("mathlib-project");
    const lakeDirectory = join(workspace, ".lake");
    await mkdir(lakeDirectory, { recursive: true });
    await cp(packageOverrides, join(lakeDirectory, "package-overrides.json"));

    const dependencyBefore = await fileEvidence(primeOlean);
    const build = await run(lake, ["--verbose", "build", "LeanBunMathlibFixture"], workspace);
    expect(build.exitCode, `${build.stdout}\n${build.stderr}`).toBe(0);
    const dependencyAfter = await fileEvidence(primeOlean);
    expect(dependencyAfter).toEqual(dependencyBefore);

    const projectOlean = join(
      workspace,
      ".lake/build/lib/lean/LeanBunMathlibFixture/Prime.olean",
    );
    expect((await stat(projectOlean)).isFile()).toBeTrue();

    const installedOverride = await readFile(join(lakeDirectory, "package-overrides.json"), "utf8");
    expect(installedOverride).not.toContain("/Dependency libraries/");
  },
  120_000,
);

test.serial(
  "two independent Lean projects consume one unchanged Mathlib provider cache",
  async () => {
    const first = await stageFixture("mathlib-project");
    const second = await stageFixture("mathlib-shared-consumer");
    const firstManifest = JSON.parse(
      await readFile(join(first, "lake-manifest.json"), "utf8"),
    );
    const secondManifest = JSON.parse(
      await readFile(join(second, "lake-manifest.json"), "utf8"),
    );
    expect(firstManifest.name).not.toBe(secondManifest.name);
    expect(firstManifest.packages).toEqual(secondManifest.packages);
    for (const workspace of [first, second]) {
      const lakeDirectory = join(workspace, ".lake");
      await mkdir(lakeDirectory, { recursive: true });
      await cp(packageOverrides, join(lakeDirectory, "package-overrides.json"));
    }

    const primeBefore = await fileEvidence(primeOlean);
    const gcdBefore = await fileEvidence(gcdOlean);
    const firstBuild = await run(lake, ["build", "LeanBunMathlibFixture"], first);
    expect(firstBuild.exitCode, `${firstBuild.stdout}\n${firstBuild.stderr}`).toBe(0);
    const secondBuild = await run(
      lake,
      ["build", "LeanBunMathlibSharedConsumer"],
      second,
    );
    expect(secondBuild.exitCode, `${secondBuild.stdout}\n${secondBuild.stderr}`).toBe(0);

    expect(await fileEvidence(primeOlean)).toEqual(primeBefore);
    expect(await fileEvidence(gcdOlean)).toEqual(gcdBefore);
    expect(
      (
        await stat(
          join(first, ".lake/build/lib/lean/LeanBunMathlibFixture/Prime.olean"),
        )
      ).isFile(),
    ).toBeTrue();
    expect(
      (
        await stat(
          join(
            second,
            ".lake/build/lib/lean/LeanBunMathlibSharedConsumer/GCD.olean",
          ),
        )
      ).isFile(),
    ).toBeTrue();
    expect(first).not.toBe(second);
  },
  120_000,
);
