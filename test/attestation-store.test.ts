import { afterAll, expect, test } from "bun:test";
import { lstat, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { storeImageAttestation, AttestationStoreError } from "../src/adapters/attestation-store";
import { canonicalizeDirectory } from "../src/adapters/filesystem";
import type { ImageAttestationV1, ImageIdentityV1 } from "../src/domain/build";
import { imageId } from "../src/domain/identity";

const temporaryRoot = resolve(process.env.TMPDIR!);
const workspaces: string[] = [];
const hash = "1".repeat(64);
const revision = "2".repeat(40);

afterAll(async () => {
  const allowedPrefix = join(temporaryRoot, "leanbun-attestation-");
  for (const workspace of workspaces) {
    if (!resolve(workspace).startsWith(allowedPrefix)) {
      throw new Error(`refusing to clean unexpected attestation workspace: ${workspace}`);
    }
    await rm(workspace, { recursive: true, force: true });
  }
});

function fixtureAttestation(artifactTreeHash = hash): ImageAttestationV1 {
  const identity: ImageIdentityV1 = {
    schemaVersion: 1,
    leanToolchain: "leanprover/lean4:v4.32.0",
    leanCompilerGithash: revision,
    mathlibRevision: revision,
    canonicalManifestHash: hash,
    packageSourceTreeHash: hash,
    buildRelevantConfigHash: hash,
    targetPlatform: "darwin-arm64-test",
  };
  return {
    schemaVersion: 1,
    imageId: imageId(identity),
    providerId: "fixture",
    status: "sealed",
    identity,
    provider: { registrySha256: hash, overridesSha256: hash },
    dependencyTreeHash: hash,
    artifactTreeHash,
    artifactCount: 1,
    artifactPolicy: { missingRoots: [] },
    sealedAt: "2026-07-23T00:00:00.000Z",
  };
}

test.serial("attestation store atomically publishes, verifies, and reuses exact evidence", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-attestation-store-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const document = fixtureAttestation();

  const sealed = await storeImageAttestation(canonicalState, document);
  expect(sealed.status).toBe("sealed");
  expect(sealed.sha256).toHaveLength(64);
  expect((await lstat(sealed.path)).mode & 0o777).toBe(0o444);
  const repeated = await storeImageAttestation(canonicalState, {
    ...document,
    sealedAt: "2026-07-23T01:00:00.000Z",
  });
  expect(repeated.status).toBe("already-sealed");
  expect(repeated.sha256).toBe(sealed.sha256);
  expect(repeated.document.sealedAt).toBe(document.sealedAt);
  expect((await readdir(join(stateRoot, "attestations"))).sort()).toEqual([
    `${document.imageId}.json`,
  ]);
});

test.serial("attestation store refuses conflicting evidence without replacing the seal", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-attestation-conflict-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  await mkdir(stateRoot);
  const canonicalState = await canonicalizeDirectory(stateRoot);
  const document = fixtureAttestation();
  const sealed = await storeImageAttestation(canonicalState, document);

  let failure: unknown;
  try {
    await storeImageAttestation(canonicalState, fixtureAttestation("3".repeat(64)));
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(AttestationStoreError);
  expect((failure as AttestationStoreError).code).toBe("ATTESTATION_SEAL_CONFLICT");
  expect(await Bun.file(sealed.path).text()).toContain(`"artifactTreeHash": "${hash}"`);
  expect((await readdir(join(stateRoot, "attestations"))).sort()).toEqual([
    `${document.imageId}.json`,
  ]);
});

test.serial("attestation store rejects a symlinked store directory", async () => {
  const root = await mkdtemp(join(temporaryRoot, "leanbun-attestation-symlink-"));
  workspaces.push(root);
  const stateRoot = join(root, "state");
  const outside = join(root, "outside");
  await mkdir(stateRoot);
  await mkdir(outside);
  await symlink(outside, join(stateRoot, "attestations"));
  const canonicalState = await canonicalizeDirectory(stateRoot);

  let failure: unknown;
  try {
    await storeImageAttestation(canonicalState, fixtureAttestation());
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(AttestationStoreError);
  expect((failure as AttestationStoreError).code).toBe("ATTESTATION_SEAL_FAILED");
  expect(await readdir(outside)).toEqual([]);
});
