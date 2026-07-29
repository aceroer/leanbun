import { lstat, readdir, realpath } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { hashStableFile, isWithin } from "./filesystem";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type {
  ArtifactEvidence,
  ArtifactFileEvidence,
  ArtifactKind,
  ArtifactMode,
  ArtifactRootSummary,
  CanonicalPath,
  HashMode,
} from "../domain/model";

export interface ArtifactRootSpec {
  owner: string;
  path: string;
  role: "project" | "package" | "cache";
}

export interface ArtifactObservation {
  evidence: ArtifactEvidence;
  diagnostics: readonly Diagnostic[];
}

const artifactLimit = 200_000;
const buildKinds = new Set<ArtifactKind>(["olean", "ilean", "trace", "hash"]);
const cacheKinds = new Set<ArtifactKind>(["ltar"]);

function emptyCounts(): Record<ArtifactKind, number> {
  return { olean: 0, ilean: 0, trace: 0, hash: 0, ltar: 0 };
}

function artifactKind(path: string): ArtifactKind | undefined {
  const extension = extname(path).slice(1);
  return extension === "olean" ||
    extension === "ilean" ||
    extension === "trace" ||
    extension === "hash" ||
    extension === "ltar"
    ? extension
    : undefined;
}

function bytewise(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

async function collectPaths(
  root: string,
  allowedKinds: ReadonlySet<ArtifactKind>,
  remaining: number,
): Promise<{
  canonicalRoot: CanonicalPath;
  paths: Array<{ path: CanonicalPath; kind: ArtifactKind }>;
  missing: boolean;
  skippedSymlinks: string[];
  exceeded: boolean;
}> {
  let canonicalRoot: CanonicalPath;
  try {
    canonicalRoot = (await realpath(root)) as CanonicalPath;
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return {
        canonicalRoot: resolve(root) as CanonicalPath,
        paths: [],
        missing: true,
        skippedSymlinks: [],
        exceeded: false,
      };
    }
    throw error;
  }

  const paths: Array<{ path: CanonicalPath; kind: ArtifactKind }> = [];
  const skippedSymlinks: string[] = [];
  const directories = [canonicalRoot as string];
  let exceeded = false;
  while (directories.length > 0 && !exceeded) {
    const directory = directories.pop()!;
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => bytewise(left.name, right.name));
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) {
        skippedSymlinks.push(path);
      } else if (entry.isDirectory()) {
        directories.push(path);
      } else if (entry.isFile()) {
        const kind = artifactKind(path);
        if (kind !== undefined && allowedKinds.has(kind)) {
          if (paths.length >= remaining) {
            exceeded = true;
            break;
          }
          paths.push({ path: path as CanonicalPath, kind });
        }
      }
    }
  }
  paths.sort((left, right) => bytewise(left.path, right.path));
  return { canonicalRoot, paths, missing: false, skippedSymlinks, exceeded };
}

export async function observeArtifacts(
  roots: readonly ArtifactRootSpec[],
  mode: ArtifactMode,
  hashMode: HashMode,
): Promise<ArtifactObservation> {
  if (mode === "none") {
    return {
      evidence: {
        mode,
        complete: true,
        total: 0,
        counts: emptyCounts(),
        roots: [],
        observed: [],
        unverifiedHashFiles: [],
      },
      diagnostics: [],
    };
  }

  const diagnostics: Diagnostic[] = [];
  const rootSummaries: ArtifactRootSummary[] = [];
  const observed: ArtifactFileEvidence[] = [];
  const unverifiedHashFiles: CanonicalPath[] = [];
  const counts = emptyCounts();
  let complete = true;
  let total = 0;

  for (const root of roots) {
    let collection;
    try {
      collection = await collectPaths(
        root.path,
        root.role === "cache" ? cacheKinds : buildKinds,
        artifactLimit - total,
      );
    } catch (error) {
      complete = false;
      diagnostics.push(
        diagnostic("EVIDENCE_READ_FAILED", "error", "artifact root cannot be traversed", [
          `owner=${root.owner}`,
          root.path,
          error instanceof Error ? error.message : String(error),
        ]),
      );
      continue;
    }
    const rootCounts = emptyCounts();
    for (const path of collection.paths) {
      rootCounts[path.kind] += 1;
      counts[path.kind] += 1;
      total += 1;
      if (mode !== "full") continue;

      if (hashMode === "sha256") {
        const hashed = await hashStableFile(path.path, collection.canonicalRoot);
        if (hashed.status === "error") {
          complete = false;
          diagnostics.push(
            diagnostic("EVIDENCE_READ_FAILED", "error", "artifact cannot be hashed", [
              path.path,
              hashed.error.message,
            ]),
          );
          continue;
        }
        if (hashed.stability === "changed") {
          complete = false;
          diagnostics.push(
            diagnostic(
              "EVIDENCE_CHANGED_DURING_READ",
              "error",
              "artifact changed while hashing",
              [path.path],
            ),
          );
        }
        observed.push({
          path: path.path,
          root: collection.canonicalRoot,
          owner: root.owner,
          kind: path.kind,
          size: hashed.value.size,
          modifiedAt: hashed.value.modifiedAt,
          stability: hashed.stability,
          sha256: hashed.value.sha256,
        });
      } else {
        try {
          const resolvedPath = await realpath(path.path);
          const metadata = await lstat(path.path);
          if (!isWithin(collection.canonicalRoot, resolvedPath) || !metadata.isFile()) {
            complete = false;
            diagnostics.push(
              diagnostic(
                "ARTIFACT_SYMLINK_SKIPPED",
                "warning",
                "artifact path stopped being a contained regular file",
                [path.path, resolvedPath],
              ),
            );
            continue;
          }
          observed.push({
            path: path.path,
            root: collection.canonicalRoot,
            owner: root.owner,
            kind: path.kind,
            size: metadata.size,
            modifiedAt: metadata.mtime.toISOString(),
            stability: "unchecked",
          });
        } catch (error) {
          complete = false;
          diagnostics.push(
            diagnostic("EVIDENCE_READ_FAILED", "error", "artifact metadata cannot be read", [
              path.path,
              error instanceof Error ? error.message : String(error),
            ]),
          );
          continue;
        }
      }
      if (path.kind === "hash") unverifiedHashFiles.push(path.path);
    }
    rootSummaries.push({
      owner: root.owner,
      root: collection.canonicalRoot,
      missing: collection.missing,
      counts: rootCounts,
    });
    if (collection.skippedSymlinks.length > 0) {
      diagnostics.push(
        diagnostic(
          "ARTIFACT_SYMLINK_SKIPPED",
          "warning",
          "symbolic links were not followed while observing artifacts",
          [`owner=${root.owner}`, ...collection.skippedSymlinks.slice(0, 20)],
        ),
      );
    }
    if (collection.exceeded) {
      complete = false;
      diagnostics.push(
        diagnostic("ARTIFACT_LIMIT_EXCEEDED", "error", "artifact entry limit was exceeded", [
          `limit=${artifactLimit}`,
        ]),
      );
      break;
    }
    if (root.role === "package" && rootCounts.olean === 0) {
      diagnostics.push(
        diagnostic(
          "DEPENDENCY_ARTIFACT_MISSING",
          "warning",
          "provider package has no observed .olean artifact",
          [`package=${root.owner}`, collection.canonicalRoot],
        ),
      );
    }
    if (root.role === "package" && rootCounts.olean > 0 && rootCounts.trace === 0) {
      diagnostics.push(
        diagnostic("TRACE_MISSING", "warning", "provider package has .olean but no .trace", [
          `package=${root.owner}`,
          collection.canonicalRoot,
        ]),
      );
    }
  }

  if (counts.hash > 0) {
    diagnostics.push(
      diagnostic(
        "HASH_FILE_UNVERIFIED",
        "warning",
        "Lake .hash files were observed but are not artifact attestations",
        [`count=${counts.hash}`],
      ),
    );
  }
  return {
    evidence: {
      mode,
      complete,
      total,
      counts,
      roots: rootSummaries,
      observed,
      unverifiedHashFiles,
    },
    diagnostics,
  };
}
