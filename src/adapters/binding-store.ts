import { constants } from "node:fs";
import { lstat, mkdir, open, realpath, rename, unlink } from "node:fs/promises";
import { join } from "node:path";
import type { ProjectBindingV1 } from "../domain/build";
import { projectId } from "../domain/identity";
import type { CanonicalPath, Sha256 } from "../domain/model";
import { loadProjectBinding } from "./binding";
import { isWithin } from "./filesystem";

export class BindingStoreError extends Error {
  constructor(
    readonly code:
      | "BINDING_WRITE_BUSY"
      | "BINDING_WRITE_CONFLICT"
      | "BINDING_WRITE_FAILED",
    message: string,
  ) {
    super(message);
  }
}

export interface StoredBinding {
  status: "bound" | "already-bound";
  path: CanonicalPath;
  sha256: Sha256;
  document: ProjectBindingV1;
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

function canonicalBytes(document: ProjectBindingV1): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
}

function samePolicy(left: ProjectBindingV1, right: ProjectBindingV1): boolean {
  return (
    JSON.stringify({ ...left, boundAt: "", lastVerifiedAt: "" }) ===
    JSON.stringify({ ...right, boundAt: "", lastVerifiedAt: "" })
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

async function prepareBindingDirectory(project: CanonicalPath): Promise<CanonicalPath> {
  const directory = join(project, ".leanbun");
  let created = false;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
  }
  const metadata = await lstat(directory);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new BindingStoreError(
      "BINDING_WRITE_FAILED",
      `binding store is not a direct directory: ${directory}`,
    );
  }
  const canonical = await realpath(directory);
  if (canonical !== directory || !isWithin(project, canonical)) {
    throw new BindingStoreError(
      "BINDING_WRITE_FAILED",
      `binding store escapes project root: ${directory} -> ${canonical}`,
    );
  }
  if (created) await syncDirectory(project);
  return canonical as CanonicalPath;
}

export async function storeProjectBinding(
  project: CanonicalPath,
  document: ProjectBindingV1,
): Promise<StoredBinding> {
  if (document.projectPath !== project || document.projectId !== projectId(project)) {
    throw new BindingStoreError(
      "BINDING_WRITE_FAILED",
      "binding project path or project id is internally inconsistent",
    );
  }
  const directory = await prepareBindingDirectory(project);
  const target = join(directory, "binding.json");
  const lock = join(directory, "binding.lock");
  const temporary = join(directory, `.binding.${process.pid}.${crypto.randomUUID()}.tmp`);
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryHandle: Awaited<ReturnType<typeof open>> | undefined;
  let published = false;
  try {
    try {
      lockHandle = await open(
        lock,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        throw new BindingStoreError(
          "BINDING_WRITE_BUSY",
          `project binding lock already exists: ${lock}`,
        );
      }
      throw error;
    }
    await lockHandle.writeFile(
      `${JSON.stringify({ pid: process.pid, projectId: document.projectId, startedAt: new Date().toISOString() })}\n`,
    );
    await lockHandle.sync();

    const existing = await loadProjectBinding(project);
    if (existing.status === "valid") {
      if (!samePolicy(existing.document, document)) {
        throw new BindingStoreError(
          "BINDING_WRITE_CONFLICT",
          `project already has a different binding: ${target}`,
        );
      }
      return {
        status: "already-bound",
        path: existing.path,
        sha256: existing.sha256,
        document: existing.document,
      };
    }
    if (existing.status === "invalid") {
      throw new BindingStoreError(
        "BINDING_WRITE_CONFLICT",
        `binding target exists but is invalid: ${target}: ${existing.message}`,
      );
    }

    const bytes = canonicalBytes(document);
    temporaryHandle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    await temporaryHandle.chmod(0o444);
    await temporaryHandle.sync();
    await temporaryHandle.close();
    temporaryHandle = undefined;

    await rename(temporary, target);
    published = true;
    await syncDirectory(directory);
    const verified = await loadProjectBinding(project);
    const expectedSha = hashBytes(bytes);
    if (
      verified.status !== "valid" ||
      verified.sha256 !== expectedSha ||
      JSON.stringify(verified.document) !== JSON.stringify(document)
    ) {
      throw new BindingStoreError(
        "BINDING_WRITE_FAILED",
        `published binding failed immediate readback verification: ${target}`,
      );
    }
    const mode = (await lstat(target)).mode & 0o777;
    if (mode !== 0o444) {
      throw new BindingStoreError(
        "BINDING_WRITE_FAILED",
        `published binding mode is ${mode.toString(8)}, expected 444: ${target}`,
      );
    }
    return {
      status: "bound",
      path: verified.path,
      sha256: verified.sha256,
      document: verified.document,
    };
  } catch (error) {
    if (error instanceof BindingStoreError) throw error;
    throw new BindingStoreError(
      "BINDING_WRITE_FAILED",
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    await temporaryHandle?.close().catch(() => undefined);
    if (!published) await unlink(temporary).catch(() => undefined);
    await lockHandle?.close().catch(() => undefined);
    if (lockHandle !== undefined) {
      await unlink(lock).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
    }
  }
}
