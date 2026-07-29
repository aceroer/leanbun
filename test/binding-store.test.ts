import { afterAll, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { BindingStoreError, storeProjectBinding } from "../src/adapters/binding-store";
import { canonicalizeDirectory } from "../src/adapters/filesystem";
import type { ProjectBindingV1 } from "../src/domain/build";
import { projectId } from "../src/domain/identity";
import type { CanonicalPath } from "../src/domain/model";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const hash = "1".repeat(64);

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-binding-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected binding workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

function fixtureBinding(project: CanonicalPath, targets = ["Fixture"]): ProjectBindingV1 {
  return {
    schemaVersion: 1,
    projectId: projectId(project),
    projectPath: project,
    imageId: hash,
    providerId: "fixture",
    boundAt: "2026-07-23T00:00:00.000Z",
    manifestSha256: hash,
    toolchain: "leanprover/lean4:v4.32.0",
    policyVersion: 1,
    allowedTargets: targets,
    lastVerifiedAt: "2026-07-23T00:00:00.000Z",
  };
}

async function temporaryProject(label: string): Promise<CanonicalPath> {
  const root = await mkdtemp(join(temporaryRoot, `leanbun-binding-${label}-`));
  workspaces.push(root);
  const project = join(root, "project");
  await mkdir(project);
  return await canonicalizeDirectory(project);
}

test.serial("binding store atomically publishes and reuses an exact policy", async () => {
  const project = await temporaryProject("store");
  const binding = fixtureBinding(project);
  const stored = await storeProjectBinding(project, binding);
  expect(stored.status).toBe("bound");
  expect(stored.sha256).toHaveLength(64);
  expect((await lstat(stored.path)).mode & 0o777).toBe(0o444);

  const repeated = await storeProjectBinding(project, {
    ...binding,
    boundAt: "2026-07-23T01:00:00.000Z",
    lastVerifiedAt: "2026-07-23T01:00:00.000Z",
  });
  expect(repeated.status).toBe("already-bound");
  expect(repeated.sha256).toBe(stored.sha256);
  expect(repeated.document.boundAt).toBe(binding.boundAt);
  expect(await readdir(join(project, ".leanbun"))).toEqual(["binding.json"]);
});

test.serial("binding store refuses a policy change without replacing the binding", async () => {
  const project = await temporaryProject("conflict");
  const binding = fixtureBinding(project);
  const stored = await storeProjectBinding(project, binding);
  let failure: unknown;
  try {
    await storeProjectBinding(project, fixtureBinding(project, ["AnotherTarget"]));
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(BindingStoreError);
  expect((failure as BindingStoreError).code).toBe("BINDING_WRITE_CONFLICT");
  expect(await Bun.file(stored.path).text()).toContain('"Fixture"');
  expect(await readdir(join(project, ".leanbun"))).toEqual(["binding.json"]);
});

test.serial("binding store rejects a symlinked project control directory", async () => {
  const project = await temporaryProject("symlink");
  const outside = join(resolve(project, ".."), "outside");
  await mkdir(outside);
  await symlink(outside, join(project, ".leanbun"));
  let failure: unknown;
  try {
    await storeProjectBinding(project, fixtureBinding(project));
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(BindingStoreError);
  expect((failure as BindingStoreError).code).toBe("BINDING_WRITE_FAILED");
  expect(await readdir(outside)).toEqual([]);
});
