import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, unlink } from "node:fs/promises";
import { join } from "node:path";
import type { BuildExecutionLockV1 } from "../domain/build";
import { projectId } from "../domain/identity";
import type { CanonicalPath, Sha256 } from "../domain/model";
import { isWithin } from "./filesystem";

const executionIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const shaPattern = /^[0-9a-f]{64}$/;

export class BuildLockStoreError extends Error {
  constructor(
    readonly code: "BUILD_LOCK_BUSY" | "BUILD_LOCK_CONFLICT" | "BUILD_LOCK_FAILED",
    message: string,
    readonly owner?: BuildExecutionLockV1,
  ) {
    super(message);
  }
}

export interface StoredBuildLock {
  path: CanonicalPath;
  sha256: Sha256;
  document: BuildExecutionLockV1;
}

export interface ReleasedBuildLock {
  status: "released" | "already-released";
  path: CanonicalPath;
  key: Sha256;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

function hashBytes(value: Uint8Array): Sha256 {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex") as Sha256;
}

function canonicalBytes(document: BuildExecutionLockV1): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validLock(value: unknown): value is BuildExecutionLockV1 {
  if (value === null || typeof value !== "object") return false;
  const lock = value as Record<string, unknown>;
  return (
    lock.schemaVersion === 1 &&
    lock.recordType === "build-execution-lock" &&
    typeof lock.key === "string" && shaPattern.test(lock.key) &&
    typeof lock.executionId === "string" && executionIdPattern.test(lock.executionId) &&
    typeof lock.projectId === "string" && shaPattern.test(lock.projectId) &&
    typeof lock.projectPath === "string" && lock.projectPath.length > 0 &&
    typeof lock.imageId === "string" && shaPattern.test(lock.imageId) &&
    typeof lock.target === "string" && lock.target.length > 0 &&
    Number.isSafeInteger(lock.coordinatorPid) && (lock.coordinatorPid as number) > 0 &&
    validTimestamp(lock.acquiredAt) &&
    lock.key === buildLockKey(lock.projectId, lock.imageId) &&
    lock.projectId === projectId(lock.projectPath as CanonicalPath)
  );
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function executionLockDirectory(
  stateRoot: CanonicalPath,
  create: boolean,
): Promise<CanonicalPath> {
  const directory = join(stateRoot, "build-locks");
  let created = false;
  if (create) {
    try {
      await mkdir(directory, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
    }
  }
  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(directory);
  } catch (error) {
    if (!create && errorCode(error) === "ENOENT") {
      throw new BuildLockStoreError("BUILD_LOCK_FAILED", `build lock store does not exist: ${directory}`);
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new BuildLockStoreError("BUILD_LOCK_FAILED", `build lock store is not a direct directory: ${directory}`);
  }
  const canonical = await realpath(directory);
  if (canonical !== directory || !isWithin(stateRoot, canonical)) {
    throw new BuildLockStoreError("BUILD_LOCK_FAILED", `build lock store escapes state root: ${directory} -> ${canonical}`);
  }
  if (created) await syncDirectory(stateRoot);
  return canonical as CanonicalPath;
}

async function readLock(path: string): Promise<BuildExecutionLockV1> {
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 32 * 1024) {
    throw new BuildLockStoreError("BUILD_LOCK_CONFLICT", `build lock is not a bounded regular file: ${path}`);
  }
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new BuildLockStoreError(
      "BUILD_LOCK_CONFLICT",
      `build lock is unreadable: ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!validLock(value)) {
    throw new BuildLockStoreError("BUILD_LOCK_CONFLICT", `build lock schema is invalid: ${path}`);
  }
  const mode = metadata.mode & 0o777;
  if (mode !== 0o444) {
    throw new BuildLockStoreError("BUILD_LOCK_CONFLICT", `build lock mode is ${mode.toString(8)}, expected 444: ${path}`);
  }
  return value;
}

export function buildLockKey(project: string, image: string): Sha256 {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(JSON.stringify({ schema: "leanbun-build-lock-v1", projectId: project, imageId: image }));
  return hasher.digest("hex") as Sha256;
}

export async function loadBuildLock(
  stateRoot: CanonicalPath,
  key: string,
): Promise<StoredBuildLock | undefined> {
  if (!shaPattern.test(key)) throw new BuildLockStoreError("BUILD_LOCK_FAILED", "build lock key is not SHA-256");
  let directory: CanonicalPath;
  try {
    directory = await executionLockDirectory(stateRoot, false);
  } catch (error) {
    if (error instanceof BuildLockStoreError && error.message.includes("does not exist")) return undefined;
    throw error;
  }
  const path = join(directory, `${key}.lock`);
  let document: BuildExecutionLockV1;
  try {
    document = await readLock(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  const bytes = canonicalBytes(document);
  return { path: path as CanonicalPath, sha256: hashBytes(bytes), document };
}

export async function acquireBuildLock(
  stateRoot: CanonicalPath,
  input: Omit<BuildExecutionLockV1, "schemaVersion" | "recordType" | "key">,
): Promise<StoredBuildLock> {
  const key = buildLockKey(input.projectId, input.imageId);
  const document: BuildExecutionLockV1 = {
    schemaVersion: 1,
    recordType: "build-execution-lock",
    key,
    ...input,
  };
  if (!validLock(document)) {
    throw new BuildLockStoreError("BUILD_LOCK_FAILED", "build lock identity is invalid or internally inconsistent");
  }
  const directory = await executionLockDirectory(stateRoot, true);
  const target = join(directory, `${key}.lock`);
  const bytes = canonicalBytes(document);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let created = false;
  let published = false;
  try {
    try {
      handle = await open(
        target,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      created = true;
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        let existing: StoredBuildLock | undefined;
        let publicationError: unknown;
        for (let attempt = 0; attempt < 100; attempt += 1) {
          try {
            existing = await loadBuildLock(stateRoot, key);
            if (existing !== undefined) break;
          } catch (readError) {
            publicationError = readError;
          }
          await Bun.sleep(5);
        }
        if (existing === undefined) {
          throw new BuildLockStoreError(
            "BUILD_LOCK_CONFLICT",
            `existing build lock did not become readable after bounded publication wait: ${target}: ${publicationError instanceof Error ? publicationError.message : String(publicationError)}`,
          );
        }
        throw new BuildLockStoreError(
          "BUILD_LOCK_BUSY",
          `project/image build lock is already held: ${target}`,
          existing?.document,
        );
      }
      throw error;
    }
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.chmod(0o444);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(directory);
    const verified = await loadBuildLock(stateRoot, key);
    if (verified === undefined || JSON.stringify(verified.document) !== JSON.stringify(document)) {
      throw new BuildLockStoreError("BUILD_LOCK_FAILED", `build lock failed immediate readback: ${target}`);
    }
    published = true;
    return verified;
  } catch (error) {
    if (error instanceof BuildLockStoreError) throw error;
    throw new BuildLockStoreError("BUILD_LOCK_FAILED", error instanceof Error ? error.message : String(error));
  } finally {
    await handle?.close().catch(() => undefined);
    if (created && !published) {
      await unlink(target).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
    }
  }
}

export async function releaseBuildLock(
  stateRoot: CanonicalPath,
  expected: Pick<BuildExecutionLockV1, "key" | "executionId" | "projectId" | "imageId">,
): Promise<ReleasedBuildLock> {
  if (expected.key !== buildLockKey(expected.projectId, expected.imageId)) {
    throw new BuildLockStoreError("BUILD_LOCK_FAILED", "expected build lock identity is inconsistent");
  }
  const existing = await loadBuildLock(stateRoot, expected.key);
  const path = join(stateRoot, "build-locks", `${expected.key}.lock`) as CanonicalPath;
  if (existing === undefined) return { status: "already-released", path, key: expected.key as Sha256 };
  if (
    existing.document.executionId !== expected.executionId ||
    existing.document.projectId !== expected.projectId ||
    existing.document.imageId !== expected.imageId
  ) {
    throw new BuildLockStoreError(
      "BUILD_LOCK_CONFLICT",
      `build lock belongs to another execution: ${existing.path}`,
      existing.document,
    );
  }
  await unlink(existing.path);
  await syncDirectory(join(stateRoot, "build-locks"));
  return { status: "released", path: existing.path, key: expected.key as Sha256 };
}
