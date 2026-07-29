import {
  assessBunRuntime,
  currentBunProvenance,
  supportedBun,
  type BunProvenance,
} from "./adapters/runtime";
import { inspectProject } from "./application/inspect-project";
import { preflightBuild } from "./application/preflight-build";
import { buildImageEvidence } from "./application/image-evidence";
import { sealImage } from "./application/seal-image";
import { bindProject } from "./application/bind-project";
import { probeBuildSandbox } from "./application/sandbox-probe";
import { runLakeBuildProbe } from "./application/lake-build-probe";
import { runControlledBuildProbe } from "./application/controlled-build-probe";
import { recoverStaleExecution } from "./application/recover-execution";
import { checkReuseCandidate } from "./application/reuse-candidate";
import { runReuseTransaction } from "./application/reuse-transaction";
import { join } from "node:path";
import { dependencyProviderFromEnvironment } from "./adapters/dependency-library";
import { FilesystemEvidenceError } from "./adapters/filesystem";
import { ExecutionRecordStoreError } from "./adapters/execution-record-store";
import { BuildLockStoreError } from "./adapters/build-lock-store";
import { diagnostic } from "./domain/diagnostics";
import { renderJsonReport } from "./reporting/json";

export const leanbunBuild = Object.freeze({
  name: "leanbun",
  version: "0.0.0-dev",
  inspectMode: "filesystem-only" as const,
  bun: supportedBun,
});

function usage(): string {
  return [
    "LeanBun development scaffold",
    "",
    "Usage:",
    "  leanbun --version",
    "  leanbun --help",
    "  leanbun inspect <project> [--provider=dependency-library]",
    "      [--artifacts=none|summary|full] [--hash=none|metadata|sha256]",
    "  leanbun build preflight <project> <target>",
    "  leanbun build verify <project> <target>",
    "  leanbun build sandbox-probe <project> <protected-root>",
    "  leanbun build lake-probe <project> <target> <protected-root>",
    "  leanbun build controlled-probe <project> <target>",
    "  leanbun build recover <execution-id>",
    "  leanbun build reuse-check <project> <target>",
    "  leanbun build reuse <project> <target>",
    "  leanbun image evidence [--artifacts=skip|full]",
    "  leanbun image seal [--allow-missing-artifact=<package>]...",
    "  leanbun project bind <project> --image=<sha256> --target=<target>...",
    "",
    `Runtime: Bun ${supportedBun.display} (exact revision required)`,
    "Inspect mode reads files only; no Lake command is enabled.",
  ].join("\n");
}

export async function main(
  args: readonly string[],
  bunProvenance: BunProvenance = currentBunProvenance(),
): Promise<number> {
  const runtime = assessBunRuntime(bunProvenance);
  if (!runtime.supported) {
    console.error(JSON.stringify(runtime.diagnostic));
    return 70;
  }
  const command = args[0] ?? "--help";
  if (command === "--version" || command === "-v") {
    console.log(`${leanbunBuild.name} ${leanbunBuild.version}`);
    return 0;
  }
  if (command === "--help" || command === "-h") {
    console.log(usage());
    return 0;
  }
  if (command === "inspect") {
    const project = args[1];
    let provider: "dependency-library" | undefined;
    let artifactMode: "none" | "summary" | "full" = "summary";
    let hashMode: "none" | "metadata" | "sha256" = "metadata";
    let invalidOption: string | undefined;
    for (const argument of args.slice(2)) {
      if (argument === "--provider=dependency-library" && provider === undefined) {
        provider = "dependency-library";
      } else if (/^--artifacts=(none|summary|full)$/.test(argument)) {
        artifactMode = argument.slice("--artifacts=".length) as typeof artifactMode;
      } else if (/^--hash=(none|metadata|sha256)$/.test(argument)) {
        hashMode = argument.slice("--hash=".length) as typeof hashMode;
      } else {
        invalidOption = argument;
      }
    }
    if (project === undefined || invalidOption !== undefined) {
      console.error(
        "usage: leanbun inspect <project> [--provider=dependency-library] " +
          "[--artifacts=none|summary|full] [--hash=none|metadata|sha256]",
      );
      return 2;
    }
    if (hashMode === "sha256" && artifactMode !== "full") artifactMode = "full";
    try {
      const report = await inspectProject({
        project,
        hashMode,
        artifactMode,
        ...(provider === undefined ? {} : { provider }),
      });
      process.stdout.write(renderJsonReport(report));
      return report.diagnostics.some((value) => value.severity === "error") ? 1 : 0;
    } catch (error) {
      const code =
        error instanceof FilesystemEvidenceError && error.code === "PROJECT_NOT_DIRECTORY"
          ? "PROJECT_NOT_DIRECTORY"
          : "PROJECT_NOT_FOUND";
      console.error(
        JSON.stringify(
          diagnostic(code, "error", "project inspection could not start", [
            error instanceof Error ? error.message : String(error),
          ]),
        ),
      );
      return 2;
    }
  }
  if (command === "build") {
    const buildMode = args[1];
    if (buildMode === "reuse") {
      const developmentRoot = process.env.LEANBUN_DEV_ROOT;
      const stateRoot = process.env.LEANBUN_STATE_ROOT;
      if (args.length !== 4 || developmentRoot === undefined || stateRoot === undefined) {
        console.error("usage: leanbun build reuse <project> <target>");
        return 2;
      }
      try {
        const cancellation = new AbortController();
        const onSigint = () => cancellation.abort("SIGINT");
        const onSigterm = () => cancellation.abort("SIGTERM");
        process.once("SIGINT", onSigint);
        process.once("SIGTERM", onSigterm);
        let report: Awaited<ReturnType<typeof runReuseTransaction>>;
        try {
          report = await runReuseTransaction(args[2]!, args[3]!, {
            developmentRoot,
            stateRoot,
            signal: cancellation.signal,
          });
        } finally {
          process.removeListener("SIGINT", onSigint);
          process.removeListener("SIGTERM", onSigterm);
        }
        process.stdout.write(renderJsonReport(report));
        return report.status === "reused" ? 0 : 1;
      } catch (error) {
        console.error(JSON.stringify(diagnostic(
          error instanceof ExecutionRecordStoreError
            ? "EXECUTION_RECORD_FAILED"
            : error instanceof BuildLockStoreError
              ? error.code
              : "REUSE_TRANSACTION_FAILED",
          "error",
          "reuse transaction could not complete",
          [error instanceof Error ? error.message : String(error)],
        )));
        return 2;
      }
    }
    if (buildMode === "reuse-check") {
      const stateRoot = process.env.LEANBUN_STATE_ROOT;
      if (args.length !== 4 || stateRoot === undefined) {
        console.error("usage: leanbun build reuse-check <project> <target>");
        return 2;
      }
      try {
        const report = await checkReuseCandidate(args[2]!, args[3]!, { stateRoot });
        process.stdout.write(renderJsonReport(report));
        return report.status === "eligible" ? 0 : 1;
      } catch (error) {
        console.error(JSON.stringify(diagnostic(
          error instanceof ExecutionRecordStoreError
            ? "EXECUTION_RECORD_FAILED"
            : error instanceof BuildLockStoreError
              ? error.code
              : "BUILD_INSPECTION_FAILED",
          "error",
          "reuse candidate check could not complete",
          [error instanceof Error ? error.message : String(error)],
        )));
        return 2;
      }
    }
    if (buildMode === "recover") {
      const developmentRoot = process.env.LEANBUN_DEV_ROOT;
      const stateRoot = process.env.LEANBUN_STATE_ROOT;
      if (args.length !== 3 || developmentRoot === undefined || stateRoot === undefined) {
        console.error("usage: leanbun build recover <execution-id>");
        return 2;
      }
      try {
        const report = await recoverStaleExecution(args[2]!, { developmentRoot, stateRoot });
        process.stdout.write(renderJsonReport(report));
        return report.status === "blocked" ? 1 : 0;
      } catch (error) {
        console.error(JSON.stringify(diagnostic(
          error instanceof ExecutionRecordStoreError
            ? "EXECUTION_RECORD_FAILED"
            : error instanceof BuildLockStoreError
              ? error.code
              : "EXECUTION_RECOVERY_BLOCKED",
          "error",
          "execution recovery could not complete",
          [error instanceof Error ? error.message : String(error)],
        )));
        return 2;
      }
    }
    if (buildMode === "sandbox-probe") {
      const developmentRoot = process.env.LEANBUN_DEV_ROOT;
      if (args.length !== 4 || developmentRoot === undefined) {
        console.error("usage: leanbun build sandbox-probe <project> <protected-root>");
        return 2;
      }
      try {
        const report = await probeBuildSandbox(args[2]!, [args[3]!], developmentRoot);
        process.stdout.write(renderJsonReport(report));
        return report.status === "passed" ? 0 : 1;
      } catch (error) {
        console.error(
          JSON.stringify(
            diagnostic("BUILD_SANDBOX_FAILED", "error", "sandbox probe could not start", [
              error instanceof Error ? error.message : String(error),
            ]),
          ),
        );
        return 2;
      }
    }
    if (buildMode === "lake-probe") {
      const developmentRoot = process.env.LEANBUN_DEV_ROOT;
      const elanHome = process.env.ELAN_HOME;
      const toolchain = process.env.LEANBUN_PROVIDER_TOOLCHAIN;
      if (args.length !== 5 || developmentRoot === undefined || elanHome === undefined || toolchain === undefined) {
        console.error("usage: leanbun build lake-probe <project> <target> <protected-root>");
        return 2;
      }
      try {
        const report = await runLakeBuildProbe(args[2]!, args[3]!, [args[4]!], {
          developmentRoot,
          elanHome,
          toolchain,
          lake: join(elanHome, "bin/lake"),
        });
        process.stdout.write(renderJsonReport(report));
        return report.status === "passed" ? 0 : 1;
      } catch (error) {
        console.error(JSON.stringify(diagnostic("LAKE_EXECUTION_FAILED", "error", "Lake probe could not start", [error instanceof Error ? error.message : String(error)])));
        return 2;
      }
    }
    if (buildMode === "controlled-probe") {
      const developmentRoot = process.env.LEANBUN_DEV_ROOT;
      const stateRoot = process.env.LEANBUN_STATE_ROOT;
      const elanHome = process.env.ELAN_HOME;
      if (args.length !== 4 || developmentRoot === undefined || stateRoot === undefined || elanHome === undefined) {
        console.error("usage: leanbun build controlled-probe <project> <target>");
        return 2;
      }
      try {
        const cancellation = new AbortController();
        const onSigint = () => cancellation.abort("SIGINT");
        const onSigterm = () => cancellation.abort("SIGTERM");
        process.once("SIGINT", onSigint);
        process.once("SIGTERM", onSigterm);
        let report: Awaited<ReturnType<typeof runControlledBuildProbe>>;
        try {
          report = await runControlledBuildProbe(args[2]!, args[3]!, {
            developmentRoot,
            stateRoot,
            elanHome,
            lake: join(elanHome, "bin/lake"),
            signal: cancellation.signal,
          });
        } finally {
          process.removeListener("SIGINT", onSigint);
          process.removeListener("SIGTERM", onSigterm);
        }
        process.stdout.write(renderJsonReport(report));
        return report.status === "passed" ? 0 : 1;
      } catch (error) {
        console.error(JSON.stringify(diagnostic(
          error instanceof ExecutionRecordStoreError
            ? "EXECUTION_RECORD_FAILED"
            : error instanceof BuildLockStoreError
              ? error.code
              : "CONTROLLED_BUILD_FAILED",
          "error",
          "controlled build probe could not complete",
          [error instanceof Error ? error.message : String(error)],
        )));
        return 2;
      }
    }
    if (
      (buildMode !== "preflight" && buildMode !== "verify") ||
      args[2] === undefined ||
      args[3] === undefined ||
      args.length !== 4
    ) {
      console.error("usage: leanbun build <preflight|verify> <project> <target>");
      return 2;
    }
    try {
      const report = await preflightBuild(args[2], args[3], {
        verifyAttestation: buildMode === "verify",
      });
      process.stdout.write(renderJsonReport(report));
      return report.status === "approved" ? 0 : 3;
    } catch (error) {
      console.error(
        JSON.stringify(
          diagnostic("BUILD_INSPECTION_FAILED", "error", "build preflight could not start", [
            error instanceof Error ? error.message : String(error),
          ]),
        ),
      );
      return 2;
    }
  }
  if (command === "project") {
    const project = args[2];
    let requestedImageId: string | undefined;
    const targets: string[] = [];
    let invalidOption: string | undefined;
    for (const argument of args.slice(3)) {
      if (argument.startsWith("--image=") && argument.length > "--image=".length && requestedImageId === undefined) {
        requestedImageId = argument.slice("--image=".length);
      } else if (argument.startsWith("--target=") && argument.length > "--target=".length) {
        targets.push(argument.slice("--target=".length));
      } else {
        invalidOption = argument;
      }
    }
    if (
      args[1] !== "bind" ||
      project === undefined ||
      requestedImageId === undefined ||
      targets.length === 0 ||
      invalidOption !== undefined
    ) {
      console.error("usage: leanbun project bind <project> --image=<sha256> --target=<target>...");
      return 2;
    }
    const provider = dependencyProviderFromEnvironment();
    const stateRoot = process.env.LEANBUN_STATE_ROOT;
    if (provider === undefined || stateRoot === undefined) {
      console.error(
        JSON.stringify(
          diagnostic(
            "PROVIDER_UNAVAILABLE",
            "error",
            "dependency provider or LeanBun state root is not configured",
          ),
        ),
      );
      return 2;
    }
    try {
      const report = await bindProject(project, requestedImageId, targets, provider, { stateRoot });
      process.stdout.write(renderJsonReport(report));
      return report.status === "blocked" ? 1 : 0;
    } catch (error) {
      console.error(
        JSON.stringify(
          diagnostic("BINDING_WRITE_FAILED", "error", "project bind could not start", [
            error instanceof Error ? error.message : String(error),
          ]),
        ),
      );
      return 2;
    }
  }
  if (command === "image") {
    if (args[1] === "seal") {
      const allowedMissingArtifactRoots: string[] = [];
      let invalidOption: string | undefined;
      for (const argument of args.slice(2)) {
        const prefix = "--allow-missing-artifact=";
        if (argument.startsWith(prefix) && argument.length > prefix.length) {
          allowedMissingArtifactRoots.push(argument.slice(prefix.length));
        } else {
          invalidOption = argument;
        }
      }
      if (invalidOption !== undefined) {
        console.error("usage: leanbun image seal [--allow-missing-artifact=<package>]...");
        return 2;
      }
      const provider = dependencyProviderFromEnvironment();
      const stateRoot = process.env.LEANBUN_STATE_ROOT;
      if (provider === undefined || stateRoot === undefined) {
        console.error(
          JSON.stringify(
            diagnostic(
              "PROVIDER_UNAVAILABLE",
              "error",
              "dependency provider or LeanBun state root is not configured",
            ),
          ),
        );
        return 2;
      }
      const report = await sealImage(provider, { stateRoot, allowedMissingArtifactRoots });
      process.stdout.write(renderJsonReport(report));
      return report.status === "blocked" ? 1 : 0;
    }
    const artifactArgument = args[2] ?? "--artifacts=skip";
    if (
      args[1] !== "evidence" ||
      args.length > 3 ||
      (artifactArgument !== "--artifacts=skip" && artifactArgument !== "--artifacts=full")
    ) {
      console.error("usage: leanbun image evidence [--artifacts=skip|full]");
      return 2;
    }
    const provider = dependencyProviderFromEnvironment();
    if (provider === undefined) {
      console.error(
        JSON.stringify(
          diagnostic("PROVIDER_UNAVAILABLE", "error", "dependency provider is not configured"),
        ),
      );
      return 2;
    }
    const report = await buildImageEvidence(
      provider,
      artifactArgument === "--artifacts=full" ? "full" : "skip",
    );
    process.stdout.write(renderJsonReport(report));
    return report.status === "blocked" ? 1 : 0;
  }
  console.error(`unsupported command in development scaffold: ${command}`);
  return 2;
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}
