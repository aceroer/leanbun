import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export type DependencyGraph = ReadonlyMap<string, ReadonlySet<string>>;

type CargoDependency = { name?: unknown; path?: unknown };
type CargoPackage = { name?: unknown; id?: unknown; dependencies?: unknown };
type CargoMetadata = {
  packages?: unknown;
  workspace_members?: unknown;
  workspace_default_members?: unknown;
};

const repository = resolve(import.meta.dir, "..");
const rustManifest = join(repository, "rust/Cargo.toml");
const dependencyBaselines = Object.freeze({
  preSplit: join(repository, "architecture/m43/cargo-dependencies.tsv"),
  lockSplit: join(repository, "architecture/m44a/cargo-dependencies.tsv"),
  inventorySplit: join(repository, "architecture/m44b/cargo-dependencies.tsv"),
  codecSplit: join(repository, "architecture/m45/cargo-dependencies.tsv"),
});
const protectedBaseline = join(repository, "architecture/m43/pre-refactor-sha256.tsv");
const apiCensus = join(repository, "architecture/m43/public-api-census.tsv");

export const MAINLINE_ROOTS = Object.freeze([
  "leanbun-lake-bridge",
  "leanbun-resolver",
  "leanbun-store",
  "leanbun-generation",
  "leanbun-build",
  "leanbun-managed",
]);

export const DEFAULT_MAINLINE_CRATES = Object.freeze([
  "leanbun-build",
  "leanbun-codec",
  "leanbun-core",
  "leanbun-evidence",
  "leanbun-generation",
  "leanbun-lake-bridge",
  "leanbun-lock",
  "leanbun-managed",
  "leanbun-resolver",
  "leanbun-store",
]);

export const HISTORICAL_CRATES = Object.freeze([
  "leanbun-inventory-legacy",
  "leanbun-plan",
  "leanbun-state",
  "leanbun-approval-macos",
  "leanbun-macos-acl-sys",
]);

const POLICY_CRATES = new Set([
  ...MAINLINE_ROOTS,
  "leanbun-package",
  ...HISTORICAL_CRATES,
]);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${label} must be an array of strings`);
  }
  return value;
}

export function graphFromCargoMetadata(value: unknown): Map<string, Set<string>> {
  if (!record(value)) throw new Error("cargo metadata root must be an object");
  const metadata = value as CargoMetadata;
  if (!Array.isArray(metadata.packages)) throw new Error("cargo metadata packages missing");
  const members = new Set(stringArray(metadata.workspace_members, "workspace_members"));
  const packages = metadata.packages.map((item, index) => {
    if (!record(item)) throw new Error(`cargo package ${index} must be an object`);
    const entry = item as CargoPackage;
    if (typeof entry.name !== "string" || typeof entry.id !== "string") {
      throw new Error(`cargo package ${index} lacks name or id`);
    }
    if (!Array.isArray(entry.dependencies)) {
      throw new Error(`cargo package ${entry.name} lacks dependencies`);
    }
    return entry;
  });
  const workspaceNames = new Set(
    packages.filter((item) => members.has(item.id as string)).map((item) => item.name as string),
  );
  if (workspaceNames.size === 0) throw new Error("cargo metadata has no workspace packages");

  const graph = new Map<string, Set<string>>();
  for (const item of packages) {
    const name = item.name as string;
    if (!workspaceNames.has(name)) continue;
    const dependencies = new Set<string>();
    for (const raw of item.dependencies as unknown[]) {
      if (!record(raw)) throw new Error(`dependency of ${name} must be an object`);
      const dependency = raw as CargoDependency;
      if (dependency.path === null || dependency.path === undefined) continue;
      if (typeof dependency.name !== "string" || !workspaceNames.has(dependency.name)) {
        throw new Error(`path dependency of ${name} is not a workspace package`);
      }
      dependencies.add(dependency.name);
    }
    graph.set(name, dependencies);
  }
  return graph;
}

export function defaultMemberNamesFromCargoMetadata(value: unknown): Set<string> {
  if (!record(value)) throw new Error("cargo metadata root must be an object");
  const metadata = value as CargoMetadata;
  if (!Array.isArray(metadata.packages)) throw new Error("cargo metadata packages missing");
  const defaultIds = new Set(
    stringArray(metadata.workspace_default_members, "workspace_default_members"),
  );
  const names = new Set<string>();
  for (const [index, item] of metadata.packages.entries()) {
    if (!record(item)) throw new Error(`cargo package ${index} must be an object`);
    const entry = item as CargoPackage;
    if (typeof entry.name !== "string" || typeof entry.id !== "string") {
      throw new Error(`cargo package ${index} lacks name or id`);
    }
    if (defaultIds.has(entry.id)) names.add(entry.name);
  }
  if (names.size !== defaultIds.size) {
    throw new Error("workspace_default_members names do not match Cargo package ids");
  }
  return names;
}

export function checkDefaultMembers(
  graph: DependencyGraph,
  defaultMembers: ReadonlySet<string>,
): string[] {
  const errors: string[] = [];
  const expected = new Set(DEFAULT_MAINLINE_CRATES);
  for (const name of DEFAULT_MAINLINE_CRATES) {
    if (!graph.has(name)) errors.push(`default mainline crate is missing from workspace: ${name}`);
    if (!defaultMembers.has(name)) errors.push(`default mainline crate is not a default member: ${name}`);
  }
  for (const name of [...defaultMembers].sort()) {
    if (!graph.has(name)) errors.push(`default member is not a workspace crate: ${name}`);
    if (!expected.has(name)) errors.push(`non-mainline crate is a default member: ${name}`);
    if (HISTORICAL_CRATES.includes(name)) {
      errors.push(`historical crate is a default member: ${name}`);
    }
  }
  return [...new Set(errors)].sort();
}

function closure(graph: DependencyGraph, root: string): Set<string> {
  if (!graph.has(root)) throw new Error(`required workspace crate is missing: ${root}`);
  const visited = new Set<string>();
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.pop();
    if (current === undefined || visited.has(current)) continue;
    visited.add(current);
    const dependencies = graph.get(current);
    if (dependencies === undefined) throw new Error(`dependency graph lacks crate: ${current}`);
    for (const dependency of dependencies) queue.push(dependency);
  }
  return visited;
}

export function checkLayering(graph: DependencyGraph): string[] {
  const errors: string[] = [];
  for (const root of ["leanbun-core", "leanbun-evidence", ...MAINLINE_ROOTS]) {
    if (!graph.has(root)) errors.push(`required workspace crate is missing: ${root}`);
  }
  if (errors.length > 0) return errors;

  const coreDependencies = graph.get("leanbun-core") ?? new Set<string>();
  if (coreDependencies.size !== 0) {
    errors.push(`leanbun-core must have no workspace dependencies: ${[...coreDependencies].sort()}`);
  }

  const evidenceClosure = closure(graph, "leanbun-evidence");
  for (const dependency of [...evidenceClosure].sort()) {
    if (
      dependency !== "leanbun-evidence" &&
      dependency !== "leanbun-codec" &&
      dependency !== "leanbun-core"
    ) {
      errors.push(`leanbun-evidence has a forbidden reverse dependency on ${dependency}`);
    }
  }

  if (graph.has("leanbun-codec")) {
    const codecClosure = closure(graph, "leanbun-codec");
    for (const dependency of [...codecClosure].sort()) {
      if (dependency !== "leanbun-codec" && dependency !== "leanbun-core") {
        errors.push(`leanbun-codec must remain below evidence and policy: ${dependency}`);
      }
    }
    for (const consumer of [
      "leanbun-evidence",
      "leanbun-lake-bridge",
      "leanbun-managed",
      "leanbun-plan",
    ]) {
      const directDependencies = graph.get(consumer) ?? new Set<string>();
      if (!directDependencies.has("leanbun-codec")) {
        errors.push(`${consumer} must depend directly on leanbun-codec after the split`);
      }
    }
  }

  if (graph.has("leanbun-lock")) {
    const lockDependencies = graph.get("leanbun-lock") ?? new Set<string>();
    if (
      lockDependencies.size !== 1 ||
      !lockDependencies.has("leanbun-core")
    ) {
      errors.push(
        `leanbun-lock must depend only on leanbun-core: ${[...lockDependencies].sort()}`,
      );
    }
  }

  if (graph.has("leanbun-inventory-legacy") && graph.has("leanbun-package")) {
    errors.push("leanbun-package must be removed after leanbun-inventory-legacy exists");
  }

  for (const root of MAINLINE_ROOTS) {
    const directDependencies = graph.get(root) ?? new Set<string>();
    if (graph.has("leanbun-lock") && !directDependencies.has("leanbun-lock")) {
      errors.push(`${root} must depend directly on leanbun-lock after the split`);
    }
    let reachable: Set<string>;
    try {
      reachable = closure(graph, root);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
      continue;
    }
    for (const forbidden of HISTORICAL_CRATES) {
      if (reachable.has(forbidden)) {
        errors.push(`${root} reaches historical crate ${forbidden}`);
      }
    }
    if (graph.has("leanbun-lock") && reachable.has("leanbun-package")) {
      errors.push(`${root} still reaches mixed-generation leanbun-package after leanbun-lock exists`);
    }
  }

  for (const [name, dependencies] of graph) {
    if (name === "leanbun-evidence" || name === "leanbun-core") continue;
    if (!POLICY_CRATES.has(name) && !name.startsWith("leanbun-")) {
      errors.push(`unexpected non-LeanBun workspace crate: ${name}`);
    }
    if (name === "leanbun-inventory-legacy" && dependencies.has("leanbun-lock")) {
      errors.push("leanbun-inventory-legacy must not regain visibility of the current lock model");
    }
  }

  return [...new Set(errors)].sort();
}

export function canonicalGraph(graph: DependencyGraph): string {
  return [...graph]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, dependencies]) => `${name}\t${[...dependencies].sort().join(",")}`)
    .join("\n") + "\n";
}

async function sha256(path: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256");
  for await (const chunk of Bun.file(path).stream()) hasher.update(chunk);
  return hasher.digest("hex");
}

function containedRepositoryPath(path: string): string {
  if (path.length === 0 || isAbsolute(path)) throw new Error(`baseline path is not relative: ${path}`);
  const target = resolve(repository, path);
  const fromRoot = relative(repository, target);
  if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new Error(`baseline path escapes repository: ${path}`);
  }
  return target;
}

async function verifyProtectedBaseline(graph: DependencyGraph): Promise<void> {
  const lines = (await readFile(protectedBaseline, "utf8")).trimEnd().split("\n");
  if (lines[0] !== "sha256\tpath") throw new Error("invalid pre-refactor SHA-256 header");
  const seen = new Set<string>();
  for (const [index, line] of lines.slice(1).entries()) {
    const fields = line.split("\t");
    if (fields.length !== 2 || !/^[0-9a-f]{64}$/.test(fields[0])) {
      throw new Error(`invalid pre-refactor SHA-256 row ${index + 2}`);
    }
    const [expected, path] = fields;
    if (!path || seen.has(path)) throw new Error(`duplicate or empty baseline path: ${path}`);
    seen.add(path);
    if (graph.has("leanbun-lock") && path === "rust/crates/leanbun-package/src/lib.rs") {
      continue;
    }
    const currentPath =
      graph.has("leanbun-lock") && path === "rust/crates/leanbun-package/src/lock_v1.rs"
        ? "rust/crates/leanbun-lock/src/lock_v1.rs"
        : graph.has("leanbun-inventory-legacy") &&
            path === "rust/crates/leanbun-package/src/snapshot.rs"
          ? "rust/crates/leanbun-inventory-legacy/src/snapshot.rs"
        : path;
    const actual = await sha256(containedRepositoryPath(currentPath));
    if (actual !== expected) throw new Error(`protected M31/M42 baseline changed: ${path}`);
  }
  if (seen.size < 8) throw new Error("pre-refactor SHA-256 baseline is unexpectedly small");
}

async function verifyApiCensus(graph: DependencyGraph): Promise<void> {
  const lines = (await readFile(apiCensus, "utf8")).trimEnd().split("\n");
  if (lines[0] !== "target_crate\tsymbol\tcurrent_source") {
    throw new Error("invalid public API census header");
  }
  const seen = new Set<string>();
  const counts = new Map<string, number>();
  for (const [index, line] of lines.slice(1).entries()) {
    const fields = line.split("\t");
    if (fields.length !== 3 || !fields.every((field) => field.length > 0)) {
      throw new Error(`invalid public API census row ${index + 2}`);
    }
    const [target, symbol, source] = fields;
    if (!new Set(["leanbun-lock", "leanbun-inventory-legacy"]).has(target)) {
      throw new Error(`unknown API census target: ${target}`);
    }
    const key = `${target}\0${symbol}`;
    if (seen.has(key)) throw new Error(`duplicate API census symbol: ${target}/${symbol}`);
    seen.add(key);
    counts.set(target, (counts.get(target) ?? 0) + 1);
    const currentSource =
      graph.has("leanbun-lock") && target === "leanbun-lock"
        ? "rust/crates/leanbun-lock/src/lock_v1.rs"
        : graph.has("leanbun-inventory-legacy") && target === "leanbun-inventory-legacy"
          ? source.replace(
              "rust/crates/leanbun-package/",
              "rust/crates/leanbun-inventory-legacy/",
            )
        : source;
    if (!(await Bun.file(containedRepositoryPath(currentSource)).exists())) {
      throw new Error(`API census source is missing: ${currentSource}`);
    }
  }
  if ((counts.get("leanbun-lock") ?? 0) < 10 || (counts.get("leanbun-inventory-legacy") ?? 0) < 10) {
    throw new Error("public API census does not enumerate both target surfaces");
  }
}

async function loadCurrentCargoMetadata(): Promise<unknown> {
  const cargo = process.env.CARGO ?? "cargo";
  const result = Bun.spawnSync({
    cmd: [cargo, "metadata", "--manifest-path", rustManifest, "--no-deps", "--format-version", "1"],
    cwd: repository,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
      CARGO_NET_OFFLINE: "true",
      LC_ALL: "C.UTF-8",
      LANG: "C.UTF-8",
    },
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(`cargo metadata failed: ${result.stderr.toString().trim()}`);
  }
  return JSON.parse(result.stdout.toString());
}

export async function loadCurrentCargoGraph(): Promise<Map<string, Set<string>>> {
  return graphFromCargoMetadata(await loadCurrentCargoMetadata());
}

export async function checkCurrentWorkspace(): Promise<string> {
  const metadata = await loadCurrentCargoMetadata();
  const graph = graphFromCargoMetadata(metadata);
  const defaultMembers = defaultMemberNamesFromCargoMetadata(metadata);
  const errors = [...checkLayering(graph), ...checkDefaultMembers(graph, defaultMembers)];
  if (errors.length > 0) throw new Error(`crate layering rejected:\n${errors.join("\n")}`);
  const dependencyBaseline = graph.has("leanbun-codec")
    ? dependencyBaselines.codecSplit
    : graph.has("leanbun-inventory-legacy")
      ? dependencyBaselines.inventorySplit
    : graph.has("leanbun-lock")
      ? dependencyBaselines.lockSplit
      : dependencyBaselines.preSplit;
  const expectedGraph = await readFile(dependencyBaseline, "utf8");
  const actualGraph = canonicalGraph(graph);
  if (actualGraph !== expectedGraph) {
    throw new Error("Cargo dependency graph differs from the reviewed M43 baseline");
  }
  await verifyProtectedBaseline(graph);
  await verifyApiCensus(graph);
  return `crate-layering=passed workspace-crates=${graph.size} default-mainline=${defaultMembers.size} historical-members=${HISTORICAL_CRATES.length} mainline-roots=${MAINLINE_ROOTS.length}`;
}

if (import.meta.main) {
  try {
    console.log(await checkCurrentWorkspace());
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
