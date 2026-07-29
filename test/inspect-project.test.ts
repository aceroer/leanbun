import { afterAll, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { readStableText } from "../src/adapters/filesystem";
import { parseLakeDocument } from "../src/adapters/manifest";
import { inspectProject } from "../src/application/inspect-project";
import { renderJsonReport } from "../src/reporting/json";

const repository = resolve(import.meta.dir, "..");
const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];

async function temporaryWorkspace(label: string): Promise<string> {
  const workspace = await mkdtemp(join(temporaryRoot, `leanbun-m1-${label}-`));
  workspaces.push(workspace);
  return workspace;
}

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-m1-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected M1 workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test.serial("inspect reads a Lake project without creating .lake", async () => {
  const project = join(repository, "test/fixtures/lake-basic");
  const manifest = join(project, "lake-manifest.json");
  const before = await stat(manifest);
  expect(lstat(join(project, ".lake"))).rejects.toHaveProperty("code", "ENOENT");

  const report = await inspectProject({ project, hashMode: "sha256" });
  const rendered = renderJsonReport(report);
  const after = await stat(manifest);

  expect(report.schemaVersion).toBe(1);
  expect(report.mode).toBe("filesystem-only");
  expect(report.project.toolchain.status).toBe("ok");
  expect(report.manifest.lakeSchema).toBe("1.2.0");
  expect(report.manifest.sha256).toHaveLength(64);
  expect(report.manifest.raw).toHaveProperty("name", "leanbun_lake_fixture");
  expect(report.overrides.state).toBe("missing");
  expect(report.diagnostics.map((value) => value.code)).toContain(
    "LAKE_EXECUTION_NOT_ATTEMPTED",
  );
  expect(JSON.parse(rendered).schemaVersion).toBe(1);
  expect({ size: after.size, mtimeMs: after.mtimeMs }).toEqual({
    size: before.size,
    mtimeMs: before.mtimeMs,
  });
  expect(lstat(join(project, ".lake"))).rejects.toHaveProperty("code", "ENOENT");
});

test("manifest parser reports malformed and unsupported schemas", () => {
  const malformed = parseLakeDocument("{", "manifest");
  expect(malformed.diagnostics[0]?.code).toBe("JSON_MALFORMED");

  const future = parseLakeDocument('{"version":"2.0.0","packages":[]}', "manifest");
  expect(future.diagnostics[0]?.code).toBe("MANIFEST_SCHEMA_UNSUPPORTED");
  expect(future.document).toBeUndefined();

  const malformedVersion = parseLakeDocument(
    '{"version":"1-not-semver","packages":[]}',
    "manifest",
  );
  expect(malformedVersion.diagnostics[0]?.code).toBe("MANIFEST_SCHEMA_UNSUPPORTED");
});

test("nonexistent lexical path escape is rejected before lookup", async () => {
  const project = await temporaryWorkspace("lexical-escape");
  await writeFile(join(project, "lean-toolchain"), "leanprover/lean4:v4.32.0\n");
  await writeFile(
    join(project, "lake-manifest.json"),
    JSON.stringify({
      version: "1.2.0",
      packages: [{ name: "escaped", type: "path", dir: "../../does-not-exist" }],
    }),
  );
  const report = await inspectProject({ project, hashMode: "none" });
  expect(report.diagnostics.map((value) => value.code)).toContain(
    "PATH_ESCAPES_ALLOWED_ROOT",
  );
});

test("bounded reader refuses oversized JSON", async () => {
  const project = await temporaryWorkspace("oversized");
  const path = join(project, "lake-manifest.json");
  await writeFile(path, "123456789");
  const observation = await readStableText(path, 8);
  expect(observation.status).toBe("error");
  if (observation.status === "error") {
    expect(observation.error.code).toBe("EVIDENCE_TOO_LARGE");
  }
});

test("path dependency symlink cannot escape the inspected project", async () => {
  const container = await temporaryWorkspace("escape");
  const project = join(container, "project");
  const outside = join(container, "outside");
  await mkdir(project);
  await mkdir(outside);
  await symlink(outside, join(project, "dependency"));
  await writeFile(join(project, "lean-toolchain"), "leanprover/lean4:v4.32.0\n");
  await writeFile(
    join(project, "lake-manifest.json"),
    JSON.stringify({
      version: "1.2.0",
      packages: [{ name: "escaped", type: "path", dir: "dependency" }],
    }),
  );

  const report = await inspectProject({ project, hashMode: "metadata" });
  const escaped = report.diagnostics.find(
    (value) => value.code === "PATH_ESCAPES_ALLOWED_ROOT",
  );
  expect(escaped).toBeDefined();
  expect(escaped?.evidence).toContain("package=escaped");
});
