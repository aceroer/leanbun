import { join, resolve } from "node:path";
import { realpath } from "node:fs/promises";
import { prepareBuildSandbox, runSandboxedProcess } from "../adapters/build-sandbox";
import { canonicalizeDirectory, isWithin, readStableText } from "../adapters/filesystem";
import { parseLakeDocument } from "../adapters/manifest";
import { artifactTreePolicy, hashCanonicalTree } from "../adapters/tree-hash";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import { validBuildTarget } from "../domain/identity";
import type { CanonicalPath } from "../domain/model";
import { snapshotTree, type SnapshotRecord } from "../../scripts/nonmutation-snapshot";

export interface LakeBuildProbeReport {
  schemaVersion: 1;
  mode: "sandboxed-lake-build-probe";
  status: "passed" | "failed";
  buildExecution: "completed" | "failed" | "not-attempted";
  project: CanonicalPath;
  target: string;
  profileSha256?: string;
  dependencySnapshots?: readonly { root: CanonicalPath; before: string; after: string }[];
  projectProtectedRecordsStable?: boolean;
  projectArtifactTreeHash?: string;
  projectArtifactCount?: number;
  lakeExitCode?: number;
  lakeStdoutSha256?: string;
  lakeStderrSha256?: string;
  diagnostics: readonly Diagnostic[];
}

function hashText(value: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex");
}

export function protectedProjectRecords(records: readonly SnapshotRecord[]): readonly SnapshotRecord[] {
  return records.filter(
    (record) =>
      record.path !== ".lake/build" &&
      !record.path.startsWith(".lake/build/") &&
      record.path !== ".lake/config" &&
      !record.path.startsWith(".lake/config/") &&
      record.path !== ".leanbun/tmp" &&
      !record.path.startsWith(".leanbun/tmp/"),
  );
}

export function hashProtectedProjectRecords(records: readonly SnapshotRecord[]): string {
  const hasher = new Bun.CryptoHasher("sha256");
  for (const record of protectedProjectRecords(records)) {
    hasher.update(`${JSON.stringify(record)}\n`);
  }
  return hasher.digest("hex");
}

export function stableOutsideBuildRoots(
  before: readonly SnapshotRecord[],
  after: readonly SnapshotRecord[],
): boolean {
  return JSON.stringify(protectedProjectRecords(before)) === JSON.stringify(protectedProjectRecords(after));
}

export async function runLakeBuildProbe(
  projectInput: string,
  target: string,
  protectedRootInputs: readonly string[],
  options: { developmentRoot: string; lake: string; elanHome: string; toolchain: string },
): Promise<LakeBuildProbeReport> {
  const developmentRoot = await canonicalizeDirectory(options.developmentRoot);
  const project = await canonicalizeDirectory(projectInput);
  const elanHome = await canonicalizeDirectory(options.elanHome);
  const lakePath = resolve(options.lake);
  const lakeTarget = (await realpath(lakePath)) as CanonicalPath;
  const protectedRoots = await Promise.all(protectedRootInputs.map(canonicalizeDirectory));
  const diagnostics: Diagnostic[] = [];
  const base = { schemaVersion: 1 as const, mode: "sandboxed-lake-build-probe" as const, project, target };
  if (
    !validBuildTarget(target) ||
    protectedRoots.length === 0 ||
    !isWithin(developmentRoot, project) ||
    !isWithin(developmentRoot, elanHome) ||
    !isWithin(elanHome, lakePath) ||
    !isWithin(elanHome, lakeTarget) ||
    protectedRoots.some((root) => !isWithin(developmentRoot, root) || isWithin(project, root) || isWithin(root, project))
  ) {
    diagnostics.push(diagnostic("BUILD_SANDBOX_INVALID", "error", "Lake probe paths or target are not allowed"));
    return { ...base, status: "failed", buildExecution: "not-attempted", diagnostics };
  }
  const [manifestRead, toolchainRead] = await Promise.all([
    readStableText(join(project, "lake-manifest.json"), 4 * 1024 * 1024),
    readStableText(join(project, "lean-toolchain"), 16 * 1024),
  ]);
  const manifest = manifestRead.status === "ok" ? parseLakeDocument(manifestRead.value.text, "manifest") : undefined;
  if (
    manifestRead.status !== "ok" ||
    manifestRead.stability !== "stable" ||
    manifest?.document === undefined ||
    manifest.document.packages.length !== 0 ||
    toolchainRead.status !== "ok" ||
    toolchainRead.stability !== "stable" ||
    toolchainRead.value.text.trim() !== options.toolchain
  ) {
    diagnostics.push(diagnostic("BUILD_SANDBOX_INVALID", "error", "Lake probe requires a stable dependency-free manifest and matching toolchain"));
    return { ...base, status: "failed", buildExecution: "not-attempted", diagnostics };
  }
  const spec = await prepareBuildSandbox(project, protectedRoots);
  const [projectBefore, ...dependencyBefore] = await Promise.all([
    snapshotTree(project),
    ...protectedRoots.map(snapshotTree),
  ]);
  const result = await runSandboxedProcess(
    spec,
    lakePath,
    ["--verbose", "build", target],
    {
      PATH: `${elanHome}/bin:/usr/bin:/bin:/usr/sbin:/sbin`,
      ELAN_HOME: elanHome,
      TMPDIR: spec.controlTempRoot,
      LC_ALL: "C.UTF-8",
      LANG: "C.UTF-8",
    },
  );
  const [projectAfter, ...dependencyAfter] = await Promise.all([
    snapshotTree(project),
    ...protectedRoots.map(snapshotTree),
  ]);
  const dependencySnapshots = protectedRoots.map((root, index) => ({
    root,
    before: dependencyBefore[index]!.treeHash,
    after: dependencyAfter[index]!.treeHash,
  }));
  const dependenciesStable = dependencySnapshots.every((value) => value.before === value.after);
  const projectProtectedRecordsStable = stableOutsideBuildRoots(projectBefore.records, projectAfter.records);
  const artifactTree = await hashCanonicalTree(
    [{ owner: "project", path: spec.projectBuildRoot }],
    artifactTreePolicy,
  );
  if (!dependenciesStable) {
    diagnostics.push(diagnostic("DEPENDENCY_ROOT_DRIFTED", "error", "protected dependency root changed during sandboxed Lake build"));
  }
  if (result.exitCode !== 0 || !projectProtectedRecordsStable || !dependenciesStable) {
    diagnostics.push(diagnostic("LAKE_EXECUTION_FAILED", "error", "sandboxed dependency-free Lake build failed containment", [
      `exitCode=${result.exitCode}`,
      result.stderr.trim(),
    ]));
  } else {
    diagnostics.push(diagnostic("LAKE_SANDBOX_BUILD_PASSED", "info", "dependency-free Lake target completed inside the build sandbox"));
  }
  const passed = result.exitCode === 0 && projectProtectedRecordsStable && dependenciesStable;
  return {
    ...base,
    status: passed ? "passed" : "failed",
    buildExecution: result.exitCode === 0 ? "completed" : "failed",
    profileSha256: spec.profileSha256,
    dependencySnapshots,
    projectProtectedRecordsStable,
    projectArtifactTreeHash: artifactTree.treeHash,
    projectArtifactCount: artifactTree.fileCount,
    lakeExitCode: result.exitCode,
    lakeStdoutSha256: hashText(result.stdout),
    lakeStderrSha256: hashText(result.stderr),
    diagnostics,
  };
}
