import { lstat, mkdir, realpath } from "node:fs/promises";
import { join } from "node:path";
import { canonicalizeDirectory, isWithin } from "./filesystem";
import type { CanonicalPath } from "../domain/model";

export interface BuildSandboxSpec {
  project: CanonicalPath;
  projectBuildRoot: CanonicalPath;
  projectConfigRoot: CanonicalPath;
  controlTempRoot: CanonicalPath;
  protectedRoots: readonly CanonicalPath[];
  profile: string;
  profileSha256: string;
}

export interface SandboxedProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  terminationReason: "exit" | "timeout" | "signal";
  triggerSignal?: "SIGINT" | "SIGTERM" | "ABORT";
  processGroupId: number;
  terminationEscalated: boolean;
}

export interface SandboxedProcessControl {
  timeoutMs?: number;
  terminationGraceMs?: number;
  signal?: AbortSignal;
}

function sbplString(value: string): string {
  return JSON.stringify(value);
}

function hashText(value: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex");
}

async function directDirectory(path: string, parent: CanonicalPath): Promise<CanonicalPath> {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== "EEXIST"
    ) {
      throw error;
    }
  }
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`sandbox write root is not a direct directory: ${path}`);
  }
  const canonical = (await realpath(path)) as CanonicalPath;
  if (canonical !== path || !isWithin(parent, canonical)) {
    throw new Error(`sandbox write root escapes parent: ${path} -> ${canonical}`);
  }
  return canonical;
}

export async function prepareBuildSandbox(
  projectInput: string,
  protectedRootInputs: readonly string[],
): Promise<BuildSandboxSpec> {
  const project = await canonicalizeDirectory(projectInput);
  const lake = await directDirectory(join(project, ".lake"), project);
  const control = await directDirectory(join(project, ".leanbun"), project);
  const projectBuildRoot = await directDirectory(join(lake, "build"), lake);
  const projectConfigRoot = await directDirectory(join(lake, "config"), lake);
  const controlTempRoot = await directDirectory(join(control, "tmp"), control);
  const protectedRoots = await Promise.all(protectedRootInputs.map(canonicalizeDirectory));
  for (const root of protectedRoots) {
    if (
      isWithin(root, projectBuildRoot) ||
      isWithin(projectBuildRoot, root) ||
      isWithin(root, projectConfigRoot) ||
      isWithin(projectConfigRoot, root) ||
      isWithin(root, controlTempRoot) ||
      isWithin(controlTempRoot, root)
    ) {
      throw new Error(`protected and writable sandbox roots overlap: ${root}`);
    }
  }
  const profile = [
    "(version 1)",
    "(allow default)",
    "(deny network*)",
    "(deny file-write*)",
    `(allow file-write* (subpath ${sbplString(projectBuildRoot)}))`,
    `(allow file-write* (subpath ${sbplString(projectConfigRoot)}))`,
    `(allow file-write* (subpath ${sbplString(controlTempRoot)}))`,
    '(allow file-write* (literal "/dev/null") (literal "/dev/tty")',
    '  (literal "/dev/stdin") (literal "/dev/stdout") (literal "/dev/stderr"))',
    "",
  ].join("\n");
  return {
    project,
    projectBuildRoot,
    projectConfigRoot,
    controlTempRoot,
    protectedRoots,
    profile,
    profileSha256: hashText(profile),
  };
}

export async function runSandboxedProcess(
  spec: BuildSandboxSpec,
  executable: string,
  args: readonly string[],
  env: Record<string, string>,
  control: SandboxedProcessControl = {},
): Promise<SandboxedProcessResult> {
  return await runDetachedProcess(
    "/usr/bin/sandbox-exec",
    ["-p", spec.profile, executable, ...args],
    spec.project,
    env,
    control,
  );
}

export async function runDetachedProcess(
  executable: string,
  args: readonly string[],
  cwd: CanonicalPath,
  env: Record<string, string>,
  control: SandboxedProcessControl = {},
): Promise<SandboxedProcessResult> {
  const timeoutMs = control.timeoutMs ?? 30_000;
  const terminationGraceMs = control.terminationGraceMs ?? 1_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(terminationGraceMs) || terminationGraceMs < 0) {
    throw new Error("sandboxed process timeout or termination grace is invalid");
  }
  const child = Bun.spawn({
    cmd: [executable, ...args],
    cwd,
    env,
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
    detached: true,
  });
  const processGroupId = child.pid;
  let exited = false;
  let terminationReason: SandboxedProcessResult["terminationReason"] = "exit";
  let triggerSignal: SandboxedProcessResult["triggerSignal"];
  let terminationEscalated = false;
  let escalationTimer: ReturnType<typeof setTimeout> | undefined;
  const signalGroup = (signal: "SIGTERM" | "SIGKILL") => {
    try {
      process.kill(-processGroupId, signal);
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error
        ? String(error.code)
        : undefined;
      if (code !== "ESRCH") throw error;
    }
  };
  const terminate = (
    reason: "timeout" | "signal",
    origin?: "SIGINT" | "SIGTERM" | "ABORT",
  ) => {
    if (terminationReason !== "exit" || exited) return;
    terminationReason = reason;
    triggerSignal = origin;
    signalGroup("SIGTERM");
    escalationTimer = setTimeout(() => {
      if (exited) return;
      terminationEscalated = true;
      signalGroup("SIGKILL");
    }, terminationGraceMs);
  };
  const abortListener = () => {
    const reason = control.signal?.reason;
    terminate(
      "signal",
      reason === "SIGINT" || reason === "SIGTERM" ? reason : "ABORT",
    );
  };
  control.signal?.addEventListener("abort", abortListener, { once: true });
  if (control.signal?.aborted) abortListener();
  const timeout = setTimeout(() => terminate("timeout"), timeoutMs);
  const exitedPromise = child.exited.then((exitCode) => {
    exited = true;
    return exitCode;
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    exitedPromise,
  ]);
  clearTimeout(timeout);
  if (escalationTimer !== undefined) clearTimeout(escalationTimer);
  control.signal?.removeEventListener("abort", abortListener);
  return {
    exitCode,
    stdout,
    stderr,
    terminationReason,
    ...(triggerSignal === undefined ? {} : { triggerSignal }),
    processGroupId,
    terminationEscalated,
  };
}
