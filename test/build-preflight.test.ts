import { afterAll, expect, test } from "bun:test";
import { release } from "node:os";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { preflightBuild } from "../src/application/preflight-build";
import { evaluateBuildAuthorization, type ImageIdentityV1 } from "../src/domain/build";
import { imageId, projectId } from "../src/domain/identity";
import { inspectProject } from "../src/application/inspect-project";

const repository = resolve(import.meta.dir, "..");
const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const hash = "1".repeat(64);

async function temporaryWorkspace(label: string): Promise<string> {
  const workspace = await mkdtemp(join(temporaryRoot, `leanbun-m5-${label}-`));
  workspaces.push(workspace);
  return workspace;
}

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-m5-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected M5 workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

test("pure authorization state approves only fully verified facts", () => {
  const approved = evaluateBuildAuthorization({
    bindingPresent: true,
    bindingValid: true,
    projectIdMatches: true,
    projectPathMatches: true,
    manifestMatches: true,
    toolchainMatches: true,
    providerMatches: true,
    targetValid: true,
    targetApproved: true,
    attestationPresent: true,
    attestationValid: true,
    attestationSealed: true,
    imageIdMatches: true,
    attestationVerified: true,
    inspectionPassed: true,
  });
  expect(approved).toEqual({ status: "approved", diagnostics: [] });
});

test.serial("preflight does not create a missing project binding", async () => {
  const project = join(repository, "test/fixtures/lake-basic");
  const report = await preflightBuild(project, "LeanBunLakeFixture");
  expect(report.status).toBe("denied");
  expect(report.buildExecution).toBe("not-attempted");
  expect(report.binding.state).toBe("missing");
  expect(report.diagnostics.map((value) => value.code)).toContain("BINDING_MISSING");
  expect(report.diagnostics.map((value) => value.code)).toContain("LAKE_BUILD_NOT_ATTEMPTED");
  expect(await Bun.file(join(project, ".leanbun/binding.json")).exists()).toBeFalse();
});

test.serial("well-formed binding remains denied until tree attestation is reverified", async () => {
  const root = await temporaryWorkspace("unverified");
  const project = join(root, "project");
  const stateRoot = join(root, "state");
  await cp(join(repository, "test/fixtures/mathlib-project"), project, { recursive: true });
  await mkdir(join(project, ".lake"), { recursive: true });
  await cp(process.env.LEANBUN_PROVIDER_OVERRIDES!, join(project, ".lake/package-overrides.json"));
  await mkdir(join(project, ".leanbun"));
  await mkdir(join(stateRoot, "attestations"), { recursive: true });
  const inspection = await inspectProject({
    project,
    provider: "dependency-library",
    hashMode: "sha256",
    artifactMode: "none",
  });
  const identity: ImageIdentityV1 = {
    schemaVersion: 1,
    leanToolchain: inspection.provider!.toolchain,
    leanCompilerGithash: process.env.LEANBUN_PROVIDER_LEAN_GITHASH!,
    mathlibRevision: inspection.packages.find((value) => value.name === "mathlib")!
      .providerRevision!,
    canonicalManifestHash: inspection.provider!.registry.sha256!,
    packageSourceTreeHash: hash,
    buildRelevantConfigHash: hash,
    targetPlatform: `${process.platform}-${process.arch}-${release()}`,
  };
  const currentImageId = imageId(identity);
  const target = "LeanBunMathlibFixture";
  await writeFile(
    join(project, ".leanbun/binding.json"),
    JSON.stringify({
      schemaVersion: 1,
      projectId: projectId(inspection.project.path),
      projectPath: inspection.project.path,
      imageId: currentImageId,
      providerId: inspection.provider!.id,
      boundAt: new Date().toISOString(),
      manifestSha256: inspection.manifest.sha256,
      toolchain: inspection.provider!.toolchain,
      policyVersion: 1,
      allowedTargets: [target],
      lastVerifiedAt: new Date().toISOString(),
    }),
  );
  await writeFile(
    join(stateRoot, "attestations", `${currentImageId}.json`),
    JSON.stringify({
      schemaVersion: 1,
      imageId: currentImageId,
      providerId: inspection.provider!.id,
      status: "sealed",
      identity,
      provider: {
        registrySha256: inspection.provider!.registry.sha256,
        overridesSha256: inspection.provider!.overrides.sha256,
      },
      dependencyTreeHash: hash,
      artifactTreeHash: hash,
      artifactCount: 1,
      artifactPolicy: { missingRoots: [] },
      sealedAt: new Date().toISOString(),
    }),
  );

  const report = await preflightBuild(project, target, { stateRoot });
  expect(report.binding.state).toBe("valid");
  expect(report.attestation.state).toBe("valid-unverified");
  expect(report.status).toBe("denied");
  expect(report.diagnostics.map((value) => value.code)).toContain("ATTESTATION_UNVERIFIED");
  expect(report.diagnostics.map((value) => value.code)).not.toContain("BINDING_DRIFTED");
});

test("invalid target is rejected by the authorization state", () => {
  const denied = evaluateBuildAuthorization({
    bindingPresent: false,
    bindingValid: false,
    projectIdMatches: false,
    projectPathMatches: false,
    manifestMatches: false,
    toolchainMatches: false,
    providerMatches: false,
    targetValid: false,
    targetApproved: false,
    attestationPresent: false,
    attestationValid: false,
    attestationSealed: false,
    imageIdMatches: false,
    attestationVerified: false,
    inspectionPassed: true,
  });
  expect(denied.diagnostics.map((value) => value.code)).toContain("TARGET_INVALID");
});
