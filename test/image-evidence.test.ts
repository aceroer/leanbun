import { afterAll, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { buildImageEvidence } from "../src/application/image-evidence";
import { sealImage } from "../src/application/seal-image";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

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

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-image-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected image workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test.serial("image evidence deterministically binds clean source and build config", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-image-evidence-"));
  workspaces.push(root);
  const packageRoot = join(root, "packages");
  const mathlib = join(packageRoot, "mathlib");
  const cacheRoot = join(root, "cache");
  await mkdir(mathlib, { recursive: true });
  await mkdir(cacheRoot);
  await runGit(mathlib, ["init", "--quiet"]);
  await writeFile(join(mathlib, "Mathlib.lean"), "def evidenceFixture := 1\n");
  await writeFile(join(mathlib, ".gitignore"), ".lake/\n");
  await writeFile(join(mathlib, "lean-toolchain"), "leanprover/lean4:v4.32.0\n");
  await writeFile(join(mathlib, "lakefile.toml"), 'name = "mathlib"\n');
  await writeFile(
    join(mathlib, "lake-manifest.json"),
    JSON.stringify({ version: "1.2.0", packages: [] }),
  );
  await runGit(mathlib, ["add", "."]);
  await runGit(mathlib, [
    "-c",
    "user.name=LeanBun Test",
    "-c",
    "user.email=leanbun@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "fixture",
  ]);
  const revision = await runGit(mathlib, ["rev-parse", "HEAD"]);
  await mkdir(join(mathlib, ".lake/build/lib/lean"), { recursive: true });
  await writeFile(join(mathlib, ".lake/build/lib/lean/Mathlib.olean"), "artifact-v1");
  const registry = join(root, "registry.json");
  const overrides = join(root, "overrides.json");
  await writeFile(
    registry,
    JSON.stringify({ version: "1.2.0", packages: [{ name: "mathlib", type: "git", rev: revision }] }),
  );
  await writeFile(
    overrides,
    JSON.stringify({ version: "1.2.0", packages: [{ name: "mathlib", type: "path", dir: mathlib }] }),
  );
  const config = {
    id: "fixture-image",
    toolchain: "leanprover/lean4:v4.32.0",
    registry,
    overrides,
    packageRoot,
    cacheRoot,
  };

  const first = await buildImageEvidence(config, "skip");
  const second = await buildImageEvidence(config, "skip");
  expect(first.status).toBe("source-config-only");
  expect(first.imageId).toHaveLength(64);
  expect(first.sourceTree?.treeHash).toHaveLength(64);
  expect(first.configTree?.treeHash).toHaveLength(64);
  expect(first.dependencyTreeHash).toHaveLength(64);
  expect(second.imageId).toBe(first.imageId);
  expect(second.dependencyTreeHash).toBe(first.dependencyTreeHash);
  const full = await buildImageEvidence(config, "full");
  expect(full.status).toBe("complete");
  expect(full.imageId).toBe(first.imageId);
  expect(full.artifactTree?.fileCount).toBe(1);
  expect(full.artifactTree?.treeHash).toHaveLength(64);

  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const sealed = await sealImage(config, {
    stateRoot,
    now: () => new Date("2026-07-23T00:00:00.000Z"),
  });
  expect(sealed.status).toBe("sealed");
  expect(sealed.attestation?.artifactPolicy.missingRoots).toEqual([]);
  const repeated = await sealImage(config, {
    stateRoot,
    now: () => new Date("2026-07-23T01:00:00.000Z"),
  });
  expect(repeated.status).toBe("already-sealed");
  expect(repeated.attestationSha256).toBe(sealed.attestationSha256);

  await writeFile(join(mathlib, ".lake/build/lib/lean/Mathlib.olean"), "artifact-v2");
  const changedArtifact = await buildImageEvidence(config, "full");
  expect(changedArtifact.imageId).toBe(first.imageId);
  expect(changedArtifact.artifactTree?.treeHash).not.toBe(full.artifactTree?.treeHash);
  const conflict = await sealImage(config, { stateRoot });
  expect(conflict.status).toBe("blocked");
  expect(conflict.diagnostics.map((value) => value.code)).toContain(
    "ATTESTATION_SEAL_CONFLICT",
  );

  await rm(join(mathlib, ".lake/build"), { recursive: true });
  const policyStateRoot = join(root, "policy-state");
  await mkdir(policyStateRoot);
  const policyBlocked = await sealImage(config, { stateRoot: policyStateRoot });
  expect(policyBlocked.status).toBe("blocked");
  expect(policyBlocked.diagnostics.map((value) => value.code)).toContain(
    "ATTESTATION_POLICY_REJECTED",
  );
  const policyAllowed = await sealImage(config, {
    stateRoot: policyStateRoot,
    allowedMissingArtifactRoots: ["mathlib"],
  });
  expect(policyAllowed.status).toBe("sealed");
  expect(policyAllowed.attestation?.artifactPolicy.missingRoots).toEqual(["mathlib"]);
  expect(await Bun.file(join(root, "attestations", `${first.imageId}.json`)).exists()).toBeFalse();
});
