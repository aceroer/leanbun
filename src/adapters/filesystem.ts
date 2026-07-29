import { lstat, open, realpath, stat } from "node:fs/promises";
import { constants, type Stats } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { CanonicalPath, Observed, Sha256 } from "../domain/model";

const chunkSize = 64 * 1024;

export interface StableTextFile {
  text: string;
  size: number;
  sha256: Sha256;
  modifiedAt: string;
}

export interface StableBinaryFile {
  size: number;
  sha256: Sha256;
  modifiedAt: string;
}

export class FilesystemEvidenceError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function canonicalPath(path: string): CanonicalPath {
  return path as CanonicalPath;
}

function sha256(value: Uint8Array): Sha256 {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex") as Sha256;
}

function metadataIdentity(value: Stats): string {
  return [value.dev, value.ino, value.mode, value.size, value.mtimeMs].join(":");
}

function errorCode(error: unknown): string {
  if (error instanceof FilesystemEvidenceError) return error.code;
  if (typeof error === "object" && error !== null && "code" in error) {
    if (error.code === "ENOENT") return "EVIDENCE_MISSING";
  }
  return "EVIDENCE_READ_FAILED";
}

export function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

export async function canonicalizeDirectory(path: string): Promise<CanonicalPath> {
  let canonical: string;
  try {
    canonical = await realpath(resolve(path));
  } catch (error) {
    throw new FilesystemEvidenceError(
      "PROJECT_NOT_FOUND",
      `project directory cannot be resolved: ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const metadata = await stat(canonical);
  if (!metadata.isDirectory()) {
    throw new FilesystemEvidenceError("PROJECT_NOT_DIRECTORY", `project is not a directory: ${canonical}`);
  }
  return canonicalPath(canonical);
}

export async function canonicalizeContained(
  root: CanonicalPath,
  candidate: string,
): Promise<CanonicalPath> {
  const requested = isAbsolute(candidate) ? candidate : resolve(root, candidate);
  if (!isWithin(root, requested)) {
    throw new FilesystemEvidenceError(
      "PATH_ESCAPES_ALLOWED_ROOT",
      `path escapes project root before resolution: ${requested}`,
    );
  }
  let canonical: string;
  try {
    canonical = await realpath(requested);
  } catch (error) {
    throw new FilesystemEvidenceError(
      "EVIDENCE_MISSING",
      `path cannot be resolved: ${requested}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isWithin(root, canonical)) {
    throw new FilesystemEvidenceError(
      "PATH_ESCAPES_ALLOWED_ROOT",
      `resolved path escapes project root: ${requested} -> ${canonical}`,
    );
  }
  return canonicalPath(canonical);
}

export async function readStableText(
  path: string,
  maximumBytes: number,
): Promise<Observed<StableTextFile>> {
  const requested = resolve(path);
  const observedAt = new Date().toISOString();
  let source = canonicalPath(requested);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    source = canonicalPath(await realpath(requested));
    handle = await open(source, "r");
    const before = await handle.stat();
    if (!before.isFile()) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_NOT_REGULAR_FILE",
        `evidence is not a regular file: ${source}`,
      );
    }
    if (before.size > maximumBytes) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_TOO_LARGE",
        `evidence exceeds ${maximumBytes} bytes: ${source}`,
      );
    }

    const chunks: Uint8Array[] = [];
    let total = 0;
    while (total <= maximumBytes) {
      const buffer = new Uint8Array(Math.min(chunkSize, maximumBytes + 1 - total));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total > maximumBytes) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_TOO_LARGE",
        `evidence grew beyond ${maximumBytes} bytes while reading: ${source}`,
      );
    }

    const after = await handle.stat();
    const bytes = Buffer.concat(chunks, total);
    const stability = metadataIdentity(before) === metadataIdentity(after) ? "stable" : "changed";
    return {
      status: "ok",
      observedAt,
      source,
      stability,
      value: {
        text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        size: total,
        sha256: sha256(bytes),
        modifiedAt: after.mtime.toISOString(),
      },
    };
  } catch (error) {
    return {
      status: "error",
      observedAt,
      source,
      stability: "unchecked",
      error: {
        code: errorCode(error),
        message: error instanceof Error ? error.message : String(error),
      },
    };
  } finally {
    await handle?.close();
  }
}

export async function hashStableFile(
  path: string,
  allowedRoot?: CanonicalPath,
): Promise<Observed<StableBinaryFile>> {
  const requested = resolve(path);
  const observedAt = new Date().toISOString();
  let source = canonicalPath(requested);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    source = canonicalPath(await realpath(requested));
    if (allowedRoot !== undefined && !isWithin(allowedRoot, source)) {
      throw new FilesystemEvidenceError(
        "PATH_ESCAPES_ALLOWED_ROOT",
        `artifact escapes allowed root: ${requested} -> ${source}`,
      );
    }
    const pathBefore = await lstat(requested);
    if (!pathBefore.isFile()) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_NOT_REGULAR_FILE",
        `artifact is not a regular file: ${requested}`,
      );
    }
    handle = await open(requested, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat();
    const sourceAfterOpen = canonicalPath(await realpath(requested));
    const pathAfterOpen = await lstat(requested);
    if (
      sourceAfterOpen !== source ||
      (allowedRoot !== undefined && !isWithin(allowedRoot, sourceAfterOpen)) ||
      metadataIdentity(pathBefore) !== metadataIdentity(before) ||
      metadataIdentity(pathAfterOpen) !== metadataIdentity(before)
    ) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_CHANGED_DURING_READ",
        `artifact path changed while opening: ${requested}`,
      );
    }
    if (!before.isFile()) {
      throw new FilesystemEvidenceError(
        "EVIDENCE_NOT_REGULAR_FILE",
        `evidence is not a regular file: ${source}`,
      );
    }
    const hasher = new Bun.CryptoHasher("sha256");
    let position = 0;
    while (position < before.size) {
      const buffer = new Uint8Array(Math.min(chunkSize, before.size - position));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      hasher.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat();
    const stability =
      position === before.size && metadataIdentity(before) === metadataIdentity(after)
        ? "stable"
        : "changed";
    return {
      status: "ok",
      observedAt,
      source,
      stability,
      value: {
        size: position,
        sha256: hasher.digest("hex") as Sha256,
        modifiedAt: after.mtime.toISOString(),
      },
    };
  } catch (error) {
    return {
      status: "error",
      observedAt,
      source,
      stability: "unchecked",
      error: {
        code: errorCode(error),
        message: error instanceof Error ? error.message : String(error),
      },
    };
  } finally {
    await handle?.close();
  }
}
