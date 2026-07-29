import { chmod, mkdir, readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const repository = resolve(import.meta.dir, "..");
const developmentRoot = join(repository, ".leanbun-dev");
const sandboxProfile = join(repository, "config/leanbun-dev.sb");
const localProviderConfig =
  process.env.LEANBUN_LOCAL_PROVIDER_CONFIG ??
  join(repository, "config/leanbun-local-provider.json");

type LocalProviderConfig = {
  bun: string;
  elanHome: string;
  stackName: string;
  packageSet: string;
  downloadCache: string;
  registry: string;
  overrides: string;
};

async function loadLocalProviderConfig(path: string): Promise<Readonly<LocalProviderConfig>> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(
      `cannot read local provider config ${path}; copy config/leanbun-local-provider.example.json first: ${error}`,
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("local provider config must be a JSON object");
  }
  const record = value as Record<string, unknown>;
  const fields = [
    "bun",
    "elanHome",
    "stackName",
    "packageSet",
    "downloadCache",
    "registry",
    "overrides",
  ] as const;
  if (
    Object.keys(record).some((field) => !fields.includes(field as (typeof fields)[number])) ||
    fields.some((field) => typeof record[field] !== "string" || record[field].length === 0)
  ) {
    throw new Error("local provider config has missing, empty or unknown fields");
  }
  for (const field of fields.filter((field) => field !== "stackName")) {
    if (!isAbsolute(record[field] as string)) {
      throw new Error(`local provider config ${field} must be absolute`);
    }
  }
  return Object.freeze(record as LocalProviderConfig);
}

const production = await loadLocalProviderConfig(localProviderConfig);

const development = Object.freeze({
  bun: join(developmentRoot, "bun/bin/bun"),
  bunCache: join(developmentRoot, "bun/install/cache"),
  bunRuntimeCache: join(developmentRoot, "bun/runtime-cache"),
  elanHome: join(developmentRoot, "lean/elan-home"),
  packageSet: join(developmentRoot, "lean/package-set"),
  downloadCache: join(developmentRoot, "lean/download-cache/mathlib"),
  registry: join(developmentRoot, "lean/registry/manifest.json"),
  sourceOverrides: join(developmentRoot, "lean/registry/production-overrides.json"),
  overrides: join(developmentRoot, "lean/overrides/package-overrides.json"),
  state: join(developmentRoot, "state"),
  temp: join(developmentRoot, "tmp"),
  xdgCache: join(developmentRoot, "xdg/cache"),
  xdgConfig: join(developmentRoot, "xdg/config"),
  xdgData: join(developmentRoot, "xdg/data"),
  marker: join(developmentRoot, "READY.json"),
});

type JsonObject = Record<string, unknown>;

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function assertWithin(root: string, candidate: string, label: string): void {
  if (!isWithin(root, candidate)) {
    throw new Error(`${label} escapes development root: ${candidate}`);
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function sha256(path: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256");
  const stream = Bun.file(path).stream();
  for await (const chunk of stream) hasher.update(chunk);
  return hasher.digest("hex");
}

async function run(
  executable: string,
  args: readonly string[],
  options: { cwd?: string; env?: Record<string, string>; timeout?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  const process = Bun.spawn({
    cmd: [executable, ...args],
    cwd: options.cwd ?? repository,
    env: options.env,
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
    timeout: options.timeout ?? 30_000,
    killSignal: "SIGTERM",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`${executable} ${args.join(" ")} failed (${exitCode}): ${stderr.trim()}`);
  }
  return { stdout, stderr };
}

async function cloneTree(source: string, destination: string): Promise<void> {
  assertWithin(developmentRoot, destination, "clone destination");
  if (await pathExists(destination)) {
    throw new Error(`partial or existing development path requires inspection: ${destination}`);
  }
  await mkdir(dirname(destination), { recursive: true });
  await run("/bin/cp", ["-cR", source, destination], { timeout: 300_000 });
}

async function copyFile(source: string, destination: string, mode?: number): Promise<void> {
  assertWithin(developmentRoot, destination, "copy destination");
  await mkdir(dirname(destination), { recursive: true });
  await Bun.write(destination, Bun.file(source));
  if (mode !== undefined) await chmod(destination, mode);
}

function rewriteOverridePaths(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(rewriteOverridePaths);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as JsonObject).map(([key, item]) => [key, rewriteOverridePaths(item)]),
    );
  }
  if (typeof value === "string" && value.startsWith(production.packageSet)) {
    return development.packageSet + value.slice(production.packageSet.length);
  }
  return value;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  assertWithin(developmentRoot, path, "JSON destination");
  await mkdir(dirname(path), { recursive: true });
  await Bun.write(path, `${JSON.stringify(value, null, 2)}\n`);
}

function isolatedEnvironment(): Record<string, string> {
  const systemPath = "/usr/bin:/bin:/usr/sbin:/sbin";
  return {
    PATH: `${dirname(development.bun)}:${join(development.elanHome, "bin")}:${systemPath}`,
    ELAN_HOME: development.elanHome,
    MATHLIB_CACHE_DIR: development.downloadCache,
    BUN_INSTALL_CACHE_DIR: development.bunCache,
    BUN_RUNTIME_TRANSPILER_CACHE_PATH: development.bunRuntimeCache,
    XDG_CACHE_HOME: development.xdgCache,
    XDG_CONFIG_HOME: development.xdgConfig,
    XDG_DATA_HOME: development.xdgData,
    TMPDIR: development.temp,
    DO_NOT_TRACK: "1",
    LC_ALL: "C.UTF-8",
    LANG: "C.UTF-8",
    LEANBUN_ENV: "development",
    LEANBUN_DEV_ROOT: developmentRoot,
    LEANBUN_STATE_ROOT: development.state,
    LEANBUN_PACKAGE_OVERRIDES: development.overrides,
    LEANBUN_PROVIDER_ID: production.stackName,
    LEANBUN_PROVIDER_TOOLCHAIN: "leanprover/lean4:v4.32.0",
    LEANBUN_PROVIDER_LEAN_GITHASH: "8c9756b28d64dab099da31a4c09229a9e6a2ef35",
    LEANBUN_PROVIDER_REGISTRY: development.registry,
    LEANBUN_PROVIDER_OVERRIDES: development.overrides,
    LEANBUN_PROVIDER_PACKAGE_ROOT: join(development.packageSet, "packages"),
    LEANBUN_PROVIDER_CACHE_ROOT: development.downloadCache,
  };
}

async function setup(): Promise<void> {
  if (await pathExists(development.marker)) {
    console.log(`development environment already initialized: ${developmentRoot}`);
    await verify();
    return;
  }
  if (await pathExists(developmentRoot)) {
    const entries = Array.from(new Bun.Glob("**/*").scanSync({ cwd: developmentRoot, dot: true }));
    if (entries.length > 0) {
      throw new Error(
        `development root exists without READY.json; inspect it before retrying: ${developmentRoot}`,
      );
    }
  }

  await mkdir(developmentRoot, { recursive: true });
  for (const path of [
    development.bunCache,
    development.bunRuntimeCache,
    development.state,
    development.temp,
    development.xdgCache,
    development.xdgConfig,
    development.xdgData,
  ]) {
    assertWithin(developmentRoot, path, "development directory");
    await mkdir(path, { recursive: true });
  }

  await copyFile(production.bun, development.bun, 0o755);
  await cloneTree(production.elanHome, development.elanHome);
  await cloneTree(production.packageSet, development.packageSet);
  await cloneTree(production.downloadCache, development.downloadCache);
  await copyFile(production.registry, development.registry, 0o644);
  await copyFile(production.overrides, development.sourceOverrides, 0o644);

  const productionOverrides = JSON.parse(await readFile(production.overrides, "utf8"));
  const developmentOverrides = rewriteOverridePaths(productionOverrides);
  await writeJson(development.overrides, developmentOverrides);

  const marker = {
    schemaVersion: 1,
    createdAt: new Date().toISOString(),
    repository,
    developmentRoot,
    production: {
      stackName: production.stackName,
      registrySha256: await sha256(production.registry),
      overridesSha256: await sha256(production.overrides),
      bunSha256: await sha256(production.bun),
    },
    development: {
      registrySha256: await sha256(development.registry),
      sourceOverridesSha256: await sha256(development.sourceOverrides),
      bunSha256: await sha256(development.bun),
    },
  };
  await writeJson(development.marker, marker);
  await verify();
}

async function gitHead(directory: string): Promise<string> {
  return (await run("/usr/bin/git", ["-C", directory, "rev-parse", "HEAD"])).stdout.trim();
}

async function verify(): Promise<void> {
  const marker = JSON.parse(await readFile(development.marker, "utf8")) as JsonObject;
  const canonicalDevelopmentRoot = await realpath(developmentRoot);
  if (canonicalDevelopmentRoot !== developmentRoot) {
    throw new Error(`development root is not canonical: ${canonicalDevelopmentRoot}`);
  }

  for (const [label, path] of Object.entries(development)) {
    if (label === "marker" || label === "state" || label === "temp" || label.startsWith("xdg")) continue;
    assertWithin(developmentRoot, path, label);
  }

  const productionRegistryHash = await sha256(production.registry);
  const productionOverridesHash = await sha256(production.overrides);
  const markerProduction = marker.production as JsonObject;
  if (markerProduction.registrySha256 !== productionRegistryHash) {
    throw new Error("production registry changed after environment creation");
  }
  if (markerProduction.overridesSha256 !== productionOverridesHash) {
    throw new Error("production override changed after environment creation");
  }

  const overrideData = JSON.parse(await readFile(development.overrides, "utf8")) as {
    packages?: Array<{ name?: string; dir?: string }>;
  };
  const productionOverrideData = JSON.parse(await readFile(production.overrides, "utf8")) as {
    packages?: Array<{ name?: string; dir?: string }>;
  };
  const registryData = JSON.parse(await readFile(production.registry, "utf8")) as {
    packages?: Array<{ name?: string; rev?: string }>;
  };
  if (!overrideData.packages?.length) throw new Error("development override has no packages");
  if (!productionOverrideData.packages?.length) throw new Error("production override has no packages");
  if (!registryData.packages?.length) throw new Error("production registry has no packages");
  const developmentDirectories = new Map(overrideData.packages.map((entry) => [entry.name, entry.dir]));
  const productionDirectories = new Map(
    productionOverrideData.packages.map((entry) => [entry.name, entry.dir]),
  );
  for (const entry of overrideData.packages) {
    if (typeof entry.dir !== "string" || !isWithin(development.packageSet, entry.dir)) {
      throw new Error(`override escapes cloned package set: ${entry.name ?? "<unknown>"}`);
    }
    await stat(entry.dir);
  }
  for (const expected of registryData.packages) {
    if (typeof expected.name !== "string" || typeof expected.rev !== "string") {
      throw new Error("registry package lacks name or revision");
    }
    const productionDirectory = productionDirectories.get(expected.name);
    const developmentDirectory = developmentDirectories.get(expected.name);
    if (typeof productionDirectory !== "string" || typeof developmentDirectory !== "string") {
      throw new Error(`package missing from override: ${expected.name}`);
    }
    const [productionHead, developmentHead] = await Promise.all([
      gitHead(productionDirectory),
      gitHead(developmentDirectory),
    ]);
    if (productionHead !== expected.rev) {
      throw new Error(`production package revision drifted: ${expected.name}`);
    }
    if (developmentHead !== expected.rev) {
      throw new Error(`development package revision drifted: ${expected.name}`);
    }
  }

  const environment = isolatedEnvironment();
  const [bunRevision, leanVersion, lakeVersion] = await Promise.all([
    run(development.bun, ["--revision"], { env: environment }),
    run(join(development.elanHome, "bin/lean"), ["--version"], { env: environment }),
    run(join(development.elanHome, "bin/lake"), ["--version"], { env: environment }),
  ]);

  console.log(`verified development environment: ${developmentRoot}`);
  console.log(`bun=${bunRevision.stdout.trim()}`);
  console.log(`lean=${leanVersion.stdout.trim()}`);
  console.log(`lake=${lakeVersion.stdout.trim()}`);
  const mathlibRevision = registryData.packages.find((entry) => entry.name === "mathlib")?.rev;
  console.log(`mathlib=${mathlibRevision ?? "missing"}`);
  console.log(`overrides=${development.overrides}`);
}

async function spawnDevelopmentTool(tool: "bun" | "lean" | "lake", args: string[]): Promise<number> {
  await verify();
  const environment = isolatedEnvironment();
  const executable =
    tool === "bun" ? development.bun : join(development.elanHome, `bin/${tool}`);
  const commandArgs = tool === "bun" ? ["--no-install", "--no-env-file", ...args] : args;
  const process = Bun.spawn({
    cmd: [
      "/usr/bin/sandbox-exec",
      "-D",
      `LEANBUN_REPOSITORY=${repository}`,
      "-f",
      sandboxProfile,
      executable,
      ...commandArgs,
    ],
    cwd: repository,
    env: environment,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  return await process.exited;
}

function help(): void {
  console.log(`LeanBun isolated development environment

Usage:
  ./scripts/dev setup
  ./scripts/dev verify
  ./scripts/dev test [bun test args...]
  ./scripts/dev check
  ./scripts/dev bun <args...>
  ./scripts/dev lean <args...>
  ./scripts/dev lake <args...>

State root: ${developmentRoot}`);
}

const [command = "help", ...args] = process.argv.slice(2);

try {
  let exitCode = 0;
  if (command === "setup") await setup();
  else if (command === "verify") await verify();
  else if (command === "test") exitCode = await spawnDevelopmentTool("bun", ["test", ...args]);
  else if (command === "check") {
    exitCode = await spawnDevelopmentTool("bun", ["test", "--rerun-each", "2", ...args]);
  } else if (command === "bun" || command === "lean" || command === "lake") {
    exitCode = await spawnDevelopmentTool(command, args);
  } else help();
  process.exitCode = exitCode;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
