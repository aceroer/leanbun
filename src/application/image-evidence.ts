import { lstat } from "node:fs/promises";
import { release } from "node:os";
import { join } from "node:path";
import {
  inspectDependencyProvider,
  type DependencyProviderConfig,
  type ProviderInspection,
} from "../adapters/dependency-library";
import { hashStableFile } from "../adapters/filesystem";
import {
  artifactTreePolicy,
  hashCanonicalTree,
  sourceTreePolicy,
  type CanonicalTreeHash,
} from "../adapters/tree-hash";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { ImageIdentityV1 } from "../domain/build";
import { imageId } from "../domain/identity";

export interface ImageEvidenceReport {
  schemaVersion: 1;
  mode: "image-evidence";
  status: "complete" | "source-config-only" | "blocked";
  providerId: string;
  imageId?: string;
  identity?: ImageIdentityV1;
  sourceTree?: CanonicalTreeHash;
  configTree?: {
    schema: "leanbun-build-config-v1";
    treeHash: string;
    fileCount: number;
    missingCount: number;
  };
  dependencyTreeHash?: string;
  artifactTree?: CanonicalTreeHash;
  diagnostics: readonly Diagnostic[];
}

const configNames = [
  "lean-toolchain",
  "lake-manifest.json",
  "lakefile.lean",
  "lakefile.toml",
] as const;

function hashJson(value: unknown): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(JSON.stringify(value));
  return hasher.digest("hex");
}

async function hashBuildConfig(provider: ProviderInspection): Promise<{
  schema: "leanbun-build-config-v1";
  treeHash: string;
  fileCount: number;
  missingCount: number;
}> {
  const records: Array<Record<string, unknown>> = [
    {
      type: "provider",
      toolchain: provider.evidence.toolchain,
      registrySha256: provider.evidence.registry.sha256,
    },
  ];
  let fileCount = 0;
  let missingCount = 0;
  for (const packageValue of provider.packages) {
    if (packageValue.path === undefined) throw new Error(`package has no canonical path: ${packageValue.name}`);
    for (const name of configNames) {
      const path = join(packageValue.path, name);
      const hashed = await hashStableFile(path, packageValue.path);
      if (hashed.status === "error") {
        if (hashed.error.code === "EVIDENCE_MISSING") {
          records.push({ package: packageValue.name, path: name, type: "missing" });
          missingCount += 1;
          continue;
        }
        throw new Error(`config cannot be hashed: ${path}: ${hashed.error.message}`);
      }
      if (hashed.stability !== "stable") throw new Error(`config changed while hashing: ${path}`);
      const metadata = await lstat(path);
      records.push({
        package: packageValue.name,
        path: name,
        type: "file",
        mode: metadata.mode & 0o7777,
        size: hashed.value.size,
        sha256: hashed.value.sha256,
      });
      fileCount += 1;
    }
  }
  records.sort((left, right) =>
    Buffer.compare(Buffer.from(JSON.stringify(left)), Buffer.from(JSON.stringify(right))),
  );
  return {
    schema: "leanbun-build-config-v1",
    treeHash: hashJson({ schema: "leanbun-build-config-v1", records }),
    fileCount,
    missingCount,
  };
}

export async function buildImageEvidence(
  config: DependencyProviderConfig,
  artifactMode: "skip" | "full",
): Promise<ImageEvidenceReport> {
  const provider = await inspectDependencyProvider(config);
  const diagnostics = [...provider.diagnostics];
  const providerBlocked = diagnostics.some(
    (value) => value.severity === "error" || value.code === "PACKAGE_DIRTY",
  );
  const compilerGithash = process.env.LEANBUN_PROVIDER_LEAN_GITHASH;
  if (compilerGithash === undefined) {
    diagnostics.push(
      diagnostic("IMAGE_EVIDENCE_BLOCKED", "error", "Lean compiler githash is not configured"),
    );
  }
  if (providerBlocked || compilerGithash === undefined) {
    return {
      schemaVersion: 1,
      mode: "image-evidence",
      status: "blocked",
      providerId: config.id,
      diagnostics,
    };
  }

  try {
    const sourceRoots = provider.packages.map((value) => ({
      owner: value.name,
      path: value.path!,
    }));
    const sourceTree = await hashCanonicalTree(sourceRoots, sourceTreePolicy);
    const configTree = await hashBuildConfig(provider);
    const mathlibRevision = provider.packages.find((value) => value.name === "mathlib")
      ?.providerRevision;
    const canonicalManifestHash = provider.evidence.registry.sha256;
    if (mathlibRevision === undefined || canonicalManifestHash === undefined) {
      throw new Error("provider lacks Mathlib revision or canonical manifest hash");
    }
    const identity: ImageIdentityV1 = {
      schemaVersion: 1,
      leanToolchain: provider.evidence.toolchain,
      leanCompilerGithash: compilerGithash,
      mathlibRevision,
      canonicalManifestHash,
      packageSourceTreeHash: sourceTree.treeHash,
      buildRelevantConfigHash: configTree.treeHash,
      targetPlatform: `${process.platform}-${process.arch}-${release()}`,
    };
    const dependencyTreeHash = hashJson({
      schema: "leanbun-dependency-tree-v1",
      providerId: provider.evidence.id,
      registrySha256: provider.evidence.registry.sha256,
      packages: provider.packages.map((value) => ({
        name: value.name,
        revision: value.providerRevision,
      })),
      packageSourceTreeHash: sourceTree.treeHash,
      buildRelevantConfigHash: configTree.treeHash,
    });
    if (artifactMode === "skip") {
      return {
        schemaVersion: 1,
        mode: "image-evidence",
        status: "source-config-only",
        providerId: config.id,
        imageId: imageId(identity),
        identity,
        sourceTree,
        configTree,
        dependencyTreeHash,
        diagnostics,
      };
    }
    const artifactTree = await hashCanonicalTree(
      provider.packages.map((value) => ({
        owner: value.name,
        path: join(value.path!, ".lake/build"),
      })),
      artifactTreePolicy,
    );
    for (const owner of artifactTree.missingRoots) {
      diagnostics.push(
        diagnostic(
          "DEPENDENCY_ARTIFACT_MISSING",
          "warning",
          "provider package build root is missing from artifact tree",
          [`package=${owner}`],
        ),
      );
    }
    return {
      schemaVersion: 1,
      mode: "image-evidence",
      status: "complete",
      providerId: config.id,
      imageId: imageId(identity),
      identity,
      sourceTree,
      configTree,
      dependencyTreeHash,
      artifactTree,
      diagnostics,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const code = message.startsWith("TREE_HASH_LIMIT_EXCEEDED:")
      ? "TREE_HASH_LIMIT_EXCEEDED"
      : "IMAGE_EVIDENCE_BLOCKED";
    diagnostics.push(
      diagnostic(code, "error", "canonical image evidence failed", [message]),
    );
    return {
      schemaVersion: 1,
      mode: "image-evidence",
      status: "blocked",
      providerId: config.id,
      diagnostics,
    };
  }
}
