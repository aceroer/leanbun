import { lstat, readdir, readlink, realpath } from "node:fs/promises";
import type { BigIntStats } from "node:fs";
import { relative, resolve } from "node:path";
import { hashStableFile } from "../src/adapters/filesystem";
import type { CanonicalPath } from "../src/domain/model";

export interface SnapshotRecord {
  path: string;
  type: "directory" | "file" | "symlink" | "other";
  mode: string;
  uid: string;
  gid: string;
  size: string;
  mtimeNs: string;
  ctimeNs: string;
  inode: string;
  device: string;
  links: string;
  sha256?: string;
  target?: string;
}

export interface TreeSnapshot {
  schemaVersion: 1;
  root: CanonicalPath;
  capturedAt: string;
  recordCount: number;
  treeHash: string;
  records: readonly SnapshotRecord[];
}

function bytewise(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function fileType(metadata: BigIntStats): SnapshotRecord["type"] {
  if (metadata.isDirectory()) return "directory";
  if (metadata.isFile()) return "file";
  if (metadata.isSymbolicLink()) return "symlink";
  return "other";
}

function metadataRecord(path: string, type: SnapshotRecord["type"], value: BigIntStats): SnapshotRecord {
  return {
    path,
    type,
    mode: value.mode.toString(),
    uid: value.uid.toString(),
    gid: value.gid.toString(),
    size: value.size.toString(),
    mtimeNs: value.mtimeNs.toString(),
    ctimeNs: value.ctimeNs.toString(),
    inode: value.ino.toString(),
    device: value.dev.toString(),
    links: value.nlink.toString(),
  };
}

export async function snapshotTree(input: string): Promise<TreeSnapshot> {
  const root = (await realpath(resolve(input))) as CanonicalPath;
  const pending = [root as string];
  const records: SnapshotRecord[] = [];
  while (pending.length > 0) {
    const path = pending.pop()!;
    const metadata = await lstat(path, { bigint: true });
    const name = path === root ? "." : relative(root, path);
    const type = fileType(metadata);
    const record = metadataRecord(name, type, metadata);
    if (type === "file") {
      const hashed = await hashStableFile(path, root);
      if (hashed.status === "error" || hashed.stability !== "stable") {
        throw new Error(
          `unstable snapshot file: ${path}: ${
            hashed.status === "error" ? hashed.error.message : hashed.stability
          }`,
        );
      }
      record.sha256 = hashed.value.sha256;
    } else if (type === "symlink") {
      record.target = await readlink(path);
    } else if (type === "directory") {
      const entries = await readdir(path);
      entries.sort(bytewise).reverse();
      for (const entry of entries) pending.push(resolve(path, entry));
    }
    records.push(record);
  }
  records.sort((left, right) => bytewise(left.path, right.path));
  const hasher = new Bun.CryptoHasher("sha256");
  for (const record of records) hasher.update(`${JSON.stringify(record)}\n`);
  return {
    schemaVersion: 1,
    root,
    capturedAt: new Date().toISOString(),
    recordCount: records.length,
    treeHash: hasher.digest("hex"),
    records,
  };
}

if (import.meta.main) {
  const root = process.argv[2];
  if (root === undefined || process.argv.length !== 3) {
    console.error("usage: nonmutation-snapshot <root>");
    process.exitCode = 2;
  } else {
    console.log(JSON.stringify(await snapshotTree(root), null, 2));
  }
}
