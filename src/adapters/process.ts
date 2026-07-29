import type { CanonicalPath } from "../domain/model";
import { isWithin } from "./filesystem";

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  startedAt: string;
  finishedAt: string;
  timedOut: boolean;
  outputExceeded: boolean;
}

const gitExecutable = "/usr/bin/git";
const outputLimit = 64 * 1024;
const timeoutMilliseconds = 5_000;

async function collectBounded(
  stream: ReadableStream<Uint8Array>,
  limit: number,
  onExceeded: () => void,
): Promise<{ text: string; exceeded: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let exceeded = false;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      const remaining = limit - total;
      if (result.value.byteLength > remaining) {
        if (remaining > 0) chunks.push(result.value.subarray(0, remaining));
        total = limit;
        exceeded = true;
        onExceeded();
        await reader.cancel("output limit exceeded");
        break;
      }
      chunks.push(result.value);
      total += result.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return {
    text: new TextDecoder().decode(Buffer.concat(chunks, total)),
    exceeded,
  };
}

async function runApprovedGit(
  directory: CanonicalPath,
  operation: "head" | "status",
): Promise<CommandResult> {
  const args =
    operation === "head"
      ? ["-C", directory, "rev-parse", "HEAD"]
      : ["-C", directory, "status", "--porcelain=v1", "--untracked-files=normal"];
  const startedAt = new Date().toISOString();
  let timedOut = false;
  let outputExceeded = false;
  let forceKill: ReturnType<typeof setTimeout> | undefined;
  const child = Bun.spawn({
    cmd: [gitExecutable, ...args],
    cwd: directory,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      LC_ALL: "C",
      LANG: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
    },
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
  });
  const terminate = () => {
    outputExceeded = true;
    child.kill("SIGTERM");
    forceKill ??= setTimeout(() => child.kill("SIGKILL"), 250);
  };
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    forceKill ??= setTimeout(() => child.kill("SIGKILL"), 250);
  }, timeoutMilliseconds);
  const [stdout, stderr, exitCode] = await Promise.all([
    collectBounded(child.stdout, outputLimit, terminate),
    collectBounded(child.stderr, outputLimit, terminate),
    child.exited,
  ]);
  clearTimeout(timeout);
  if (forceKill !== undefined) clearTimeout(forceKill);
  return {
    exitCode,
    stdout: stdout.text,
    stderr: stderr.text,
    startedAt,
    finishedAt: new Date().toISOString(),
    timedOut,
    outputExceeded: outputExceeded || stdout.exceeded || stderr.exceeded,
  };
}

export function readGitHead(directory: CanonicalPath): Promise<CommandResult> {
  return runApprovedGit(directory, "head");
}

export function readGitStatus(directory: CanonicalPath): Promise<CommandResult> {
  return runApprovedGit(directory, "status");
}

export interface WorkingDirectoryProcess {
  pid: number;
  command: string;
  cwd: string;
}

export interface WorkingDirectoryProcessAudit {
  status: "complete" | "unknown";
  processes: readonly WorkingDirectoryProcess[];
  message?: string;
}

export function parseLsofWorkingDirectories(text: string): readonly WorkingDirectoryProcess[] {
  const records: WorkingDirectoryProcess[] = [];
  let pid: number | undefined;
  let command = "";
  for (const line of text.split("\n")) {
    const tag = line[0];
    const value = line.slice(1);
    if (tag === "p") {
      pid = Number(value);
      command = "";
    } else if (tag === "c") {
      command = value;
    } else if (tag === "n" && pid !== undefined && Number.isSafeInteger(pid) && pid > 0) {
      records.push({ pid, command, cwd: value });
    }
  }
  return records;
}

export async function auditProjectWorkingDirectoryProcesses(
  project: CanonicalPath,
): Promise<WorkingDirectoryProcessAudit> {
  let timedOut = false;
  const child = Bun.spawn({
    cmd: ["/usr/sbin/lsof", "-a", "-d", "cwd", "-Fpcn"],
    cwd: "/",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C", LANG: "C" },
    stdin: null,
    stdout: "pipe",
    stderr: "pipe",
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, timeoutMilliseconds);
  const [stdout, stderr, exitCode] = await Promise.all([
    collectBounded(child.stdout, 1024 * 1024, () => child.kill("SIGKILL")),
    collectBounded(child.stderr, outputLimit, () => child.kill("SIGKILL")),
    child.exited,
  ]);
  clearTimeout(timeout);
  if (timedOut || stdout.exceeded || stderr.exceeded || exitCode !== 0) {
    return {
      status: "unknown",
      processes: [],
      message: timedOut
        ? "lsof cwd audit timed out"
        : stdout.exceeded || stderr.exceeded
          ? "lsof cwd audit exceeded its output limit"
          : `lsof cwd audit exited ${exitCode}: ${stderr.text.trim()}`,
    };
  }
  return {
    status: "complete",
    processes: parseLsofWorkingDirectories(stdout.text).filter(
      (entry) => entry.pid !== process.pid && isWithin(project, entry.cwd),
    ),
  };
}
