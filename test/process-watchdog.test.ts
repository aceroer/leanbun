import { afterEach, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repository = resolve(import.meta.dir, "..");
const watchdogPath = join(repository, "scripts/process-watchdog");
const workerPath = join(repository, "test/helpers/process-tree-worker.ts");
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ESRCH"
    );
  }
}

async function waitForPid(path: string): Promise<number> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const pid = Number((await readFile(path, "utf8")).trim());
      if (Number.isSafeInteger(pid) && pid > 1) return pid;
    } catch (error) {
      if (
        typeof error !== "object" ||
        error === null ||
        !("code" in error) ||
        error.code !== "ENOENT"
      ) {
        throw error;
      }
    }
    await Bun.sleep(20);
  }
  throw new Error(`worker did not publish a child pid: ${path}`);
}

async function runWatchdogCase(parentPid: number, timeoutSeconds: number, expectedReason: string) {
  const root = await mkdtemp(join(tmpdir(), "leanbun-process-watchdog-"));
  temporaryRoots.push(root);
  const pidFile = join(root, "child.pid");
  const worker = Bun.spawn({
    cmd: [process.execPath, workerPath, pidFile, "ignore-term"],
    cwd: repository,
    stdin: null,
    stdout: "ignore",
    stderr: "ignore",
    detached: true,
  });
  const descendantPid = await waitForPid(pidFile);
  const watchdog = Bun.spawn({
    cmd: [
      "/bin/sh",
      watchdogPath,
      String(parentPid),
      String(worker.pid),
      String(timeoutSeconds),
      "1",
      "regression-fixture",
    ],
    cwd: repository,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C.UTF-8", LANG: "C.UTF-8" },
    stdin: null,
    stdout: "ignore",
    stderr: "pipe",
    detached: true,
  });
  const stderrPromise = new Response(watchdog.stderr).text();
  const watchdogExit = await watchdog.exited;
  const stderr = await stderrPromise;
  await worker.exited;

  expect(watchdogExit).toBe(expectedReason === "timeout" ? 124 : 125);
  expect(stderr).toContain(`reason=${expectedReason}`);
  expect(stderr).toContain("escalation=SIGKILL");
  expect(processExists(worker.pid)).toBeFalse();
  expect(processExists(descendantPid)).toBeFalse();
}

test.serial("test watchdog terminates and reaps a timed-out Bun process group", async () => {
  await runWatchdogCase(process.pid, 1, "timeout");
});

test.serial("test watchdog reaps a Bun process group after its supervisor disappears", async () => {
  await runWatchdogCase(999_999, 30, "parent-exited");
});
