import { lstat, readdir, readlink, realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { hashStableFile } from "./filesystem";
import type { CanonicalPath } from "../domain/model";

export interface CanonicalTreeRoot {
  owner: string;
  path: string;
}

export interface CanonicalTreePolicy {
  schema: string;
  excludeDirectory(relativePath: string, name: string): boolean;
  excludeFile(relativePath: string, name: string): boolean;
  maximumEntries?: number;
}

export interface CanonicalTreeHash {
  schema: string;
  treeHash: string;
  entryCount: number;
  fileCount: number;
  byteCount: number;
  missingRoots: readonly string[];
}

type TreeEntry = {
  owner: string;
  root: CanonicalPath;
  path: string;
  relativePath: string;
  type: "directory" | "file" | "symlink" | "other";
};

const defaultLimit = 500_000;

function bytewise(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function entryType(metadata: Awaited<ReturnType<typeof lstat>>): TreeEntry["type"] {
  if (metadata.isDirectory()) return "directory";
  if (metadata.isFile()) return "file";
  if (metadata.isSymbolicLink()) return "symlink";
  return "other";
}

function mode(metadata: Awaited<ReturnType<typeof lstat>>): number {
  return metadata.mode & 0o7777;
}

function identity(metadata: Awaited<ReturnType<typeof lstat>>): string {
  return [metadata.dev, metadata.ino, metadata.mode, metadata.size, metadata.mtimeMs].join(":");
}

function relativeName(root: string, path: string): string {
  const value = relative(root, path);
  return value === "" ? "." : value.split(sep).join("/");
}

async function collectEntries(
  roots: readonly CanonicalTreeRoot[],
  policy: CanonicalTreePolicy,
): Promise<{ entries: TreeEntry[]; missingRoots: string[] }> {
  const entries: TreeEntry[] = [];
  const missingRoots: string[] = [];
  const limit = policy.maximumEntries ?? defaultLimit;
  for (const rootSpec of roots) {
    let root: CanonicalPath;
    try {
      root = (await realpath(resolve(rootSpec.path))) as CanonicalPath;
    } catch (error) {
      if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
        missingRoots.push(rootSpec.owner);
        continue;
      }
      throw error;
    }
    const pending = [root as string];
    while (pending.length > 0) {
      const path = pending.pop()!;
      const metadata = await lstat(path);
      const relativePath = relativeName(root, path);
      const type = entryType(metadata);
      if (relativePath !== ".") {
        const name = relativePath.slice(relativePath.lastIndexOf("/") + 1);
        if (type === "directory" && policy.excludeDirectory(relativePath, name)) continue;
        if (type !== "directory" && policy.excludeFile(relativePath, name)) continue;
      }
      entries.push({ owner: rootSpec.owner, root, path, relativePath, type });
      if (entries.length > limit) {
        throw new Error(`TREE_HASH_LIMIT_EXCEEDED: ${entries.length} > ${limit}`);
      }
      if (type === "directory") {
        const children = await readdir(path);
        children.sort(bytewise).reverse();
        for (const child of children) pending.push(resolve(path, child));
      }
    }
  }
  entries.sort((left, right) => {
    const ownerOrder = bytewise(left.owner, right.owner);
    return ownerOrder === 0 ? bytewise(left.relativePath, right.relativePath) : ownerOrder;
  });
  return { entries, missingRoots: missingRoots.sort(bytewise) };
}

export async function hashCanonicalTree(
  roots: readonly CanonicalTreeRoot[],
  policy: CanonicalTreePolicy,
): Promise<CanonicalTreeHash> {
  const { entries, missingRoots } = await collectEntries(roots, policy);
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(`${JSON.stringify({ schema: policy.schema })}\n`);
  let fileCount = 0;
  let byteCount = 0;
  for (const entry of entries) {
    const before = await lstat(entry.path);
    const record: Record<string, unknown> = {
      owner: entry.owner,
      path: entry.relativePath,
      type: entry.type,
      mode: mode(before),
    };
    if (entry.type === "file") {
      const hashed = await hashStableFile(entry.path, entry.root);
      if (hashed.status === "error" || hashed.stability !== "stable") {
        throw new Error(
          `tree file is unstable: ${entry.path}: ${
            hashed.status === "error" ? hashed.error.message : hashed.stability
          }`,
        );
      }
      const after = await lstat(entry.path);
      if (identity(before) !== identity(after)) {
        throw new Error(`tree metadata changed during hashing: ${entry.path}`);
      }
      record.size = hashed.value.size;
      record.sha256 = hashed.value.sha256;
      fileCount += 1;
      byteCount += hashed.value.size;
    } else if (entry.type === "symlink") {
      record.target = await readlink(entry.path);
    } else if (entry.type === "other") {
      throw new Error(`unsupported tree entry type: ${entry.path}`);
    }
    hasher.update(`${JSON.stringify(record)}\n`);
  }
  for (const owner of missingRoots) {
    hasher.update(`${JSON.stringify({ owner, type: "missing-root" })}\n`);
  }
  return {
    schema: policy.schema,
    treeHash: hasher.digest("hex"),
    entryCount: entries.length + missingRoots.length,
    fileCount,
    byteCount,
    missingRoots,
  };
}

export const sourceTreePolicy: CanonicalTreePolicy = Object.freeze({
  schema: "leanbun-source-tree-v1",
  excludeDirectory: (_relativePath: string, name: string) => name === ".git" || name === ".lake",
  excludeFile: (_relativePath: string, name: string) => name === ".DS_Store",
});

export const artifactTreePolicy: CanonicalTreePolicy = Object.freeze({
  schema: "leanbun-artifact-tree-v1",
  excludeDirectory: () => false,
  excludeFile: (_relativePath: string, name: string) =>
    name === ".DS_Store" || name.endsWith(".lock") || name.endsWith("-wal") || name.endsWith("-shm"),
});

export const projectInputTreePolicy: CanonicalTreePolicy = Object.freeze({
  schema: "leanbun-project-input-tree-v1",
  excludeDirectory: (relativePath: string, name: string) =>
    name === ".git" || name === ".lake" || relativePath === ".leanbun/tmp",
  excludeFile: (_relativePath: string, name: string) => name === ".DS_Store",
});

export const projectOutputTreePolicy: CanonicalTreePolicy = Object.freeze({
  schema: "leanbun-project-output-tree-v1",
  excludeDirectory: () => false,
  excludeFile: (_relativePath: string, name: string) =>
    name === ".DS_Store" || name.endsWith(".lock") || name.endsWith("-wal") || name.endsWith("-shm"),
});
