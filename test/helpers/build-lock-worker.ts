import { writeFile } from "node:fs/promises";
import { acquireBuildLock, BuildLockStoreError, releaseBuildLock } from "../../src/adapters/build-lock-store";
import { canonicalizeDirectory } from "../../src/adapters/filesystem";
import { projectId } from "../../src/domain/identity";

const [stateArgument, projectArgument, executionId, output, start, holdArgument, imageArgument, releaseSignal] = Bun.argv.slice(2);
if ([stateArgument, projectArgument, executionId, output, start, holdArgument].some((value) => value === undefined)) {
  throw new Error("usage: build-lock-worker <state> <project> <execution-id> <output> <start> <hold-ms>");
}

while (!(await Bun.file(start!).exists())) await Bun.sleep(5);
const [stateRoot, project] = await Promise.all([
  canonicalizeDirectory(stateArgument!),
  canonicalizeDirectory(projectArgument!),
]);
try {
  const lock = await acquireBuildLock(stateRoot, {
    executionId: executionId!,
    projectId: projectId(project),
    projectPath: project,
    imageId: imageArgument ?? "2".repeat(64),
    target: "Fixture",
    coordinatorPid: process.pid,
    acquiredAt: new Date().toISOString(),
  });
  await writeFile(output!, `acquired:${lock.document.executionId}\n`, { mode: 0o600 });
  const deadline = Date.now() + Number(holdArgument);
  while (Date.now() < deadline && (releaseSignal === undefined || !(await Bun.file(releaseSignal).exists()))) {
    await Bun.sleep(Math.min(25, Math.max(1, deadline - Date.now())));
  }
  await releaseBuildLock(stateRoot, lock.document);
} catch (error) {
  if (error instanceof BuildLockStoreError && error.code === "BUILD_LOCK_BUSY") {
    await writeFile(output!, `busy:${error.owner?.executionId ?? "unknown"}\n`, { mode: 0o600 });
  } else {
    throw error;
  }
}
