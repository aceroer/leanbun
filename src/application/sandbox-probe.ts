import { join } from "node:path";
import {
  prepareBuildSandbox,
  runSandboxedProcess,
  type BuildSandboxSpec,
} from "../adapters/build-sandbox";
import { canonicalizeDirectory, isWithin } from "../adapters/filesystem";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type { CanonicalPath } from "../domain/model";

export interface SandboxProbeObservations {
  projectBuildWrite: "allowed" | "denied";
  projectConfigWrite: "allowed" | "denied";
  controlTempWrite: "allowed" | "denied";
  projectSourceWrite: "allowed" | "denied";
  projectControlWrite: "allowed" | "denied";
  protectedWrites: readonly ("allowed" | "denied")[];
  networkListen: "allowed" | "denied";
}

export interface SandboxProbeReport {
  schemaVersion: 1;
  mode: "build-sandbox-probe";
  buildExecution: "not-attempted";
  status: "passed" | "failed";
  project: CanonicalPath;
  protectedRoots: readonly CanonicalPath[];
  projectBuildRoot?: CanonicalPath;
  projectConfigRoot?: CanonicalPath;
  controlTempRoot?: CanonicalPath;
  profileSha256?: string;
  observations?: SandboxProbeObservations;
  diagnostics: readonly Diagnostic[];
}

export function sandboxProbePassed(value: SandboxProbeObservations): boolean {
  return (
    value.projectBuildWrite === "allowed" &&
    value.projectConfigWrite === "allowed" &&
    value.controlTempWrite === "allowed" &&
    value.projectSourceWrite === "denied" &&
    value.projectControlWrite === "denied" &&
    value.protectedWrites.length > 0 &&
    value.protectedWrites.every((item) => item === "denied") &&
    value.networkListen === "denied"
  );
}

export async function probeBuildSandbox(
  projectInput: string,
  protectedRootInputs: readonly string[],
  developmentRootInput: string,
): Promise<SandboxProbeReport> {
  const developmentRoot = await canonicalizeDirectory(developmentRootInput);
  const project = await canonicalizeDirectory(projectInput);
  const protectedRoots = await Promise.all(protectedRootInputs.map(canonicalizeDirectory));
  const diagnostics: Diagnostic[] = [];
  const base = {
    schemaVersion: 1 as const,
    mode: "build-sandbox-probe" as const,
    buildExecution: "not-attempted" as const,
    project,
    protectedRoots,
  };
  if (
    protectedRoots.length === 0 ||
    !isWithin(developmentRoot, project) ||
    protectedRoots.some(
      (root) => !isWithin(developmentRoot, root) || isWithin(project, root) || isWithin(root, project),
    )
  ) {
    diagnostics.push(
      diagnostic(
        "BUILD_SANDBOX_INVALID",
        "error",
        "sandbox probe project and protected roots must be disjoint children of LEANBUN_DEV_ROOT",
      ),
    );
    return { ...base, status: "failed", diagnostics };
  }

  let spec: BuildSandboxSpec | undefined;
  try {
    spec = await prepareBuildSandbox(project, protectedRoots);
    const worker = join(import.meta.dir, "../workers/build-sandbox-probe.ts");
    const result = await runSandboxedProcess(
      spec,
      process.execPath,
      ["--no-install", "--no-env-file", "run", worker],
      {
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        LC_ALL: "C.UTF-8",
        LANG: "C.UTF-8",
        TMPDIR: spec.controlTempRoot,
        BUN_INSTALL_CACHE_DIR: spec.controlTempRoot,
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: spec.controlTempRoot,
        LEANBUN_PROBE_PROJECT: spec.project,
        LEANBUN_PROBE_BUILD_ROOT: spec.projectBuildRoot,
        LEANBUN_PROBE_CONFIG_ROOT: spec.projectConfigRoot,
        LEANBUN_PROBE_TEMP_ROOT: spec.controlTempRoot,
        LEANBUN_PROBE_PROTECTED_ROOTS: JSON.stringify(spec.protectedRoots),
      },
    );
    let observations: SandboxProbeObservations | undefined;
    try {
      observations = JSON.parse(result.stdout) as SandboxProbeObservations;
    } catch {
      observations = undefined;
    }
    if (result.exitCode !== 0 || observations === undefined || !sandboxProbePassed(observations)) {
      diagnostics.push(
        diagnostic("BUILD_SANDBOX_FAILED", "error", "build sandbox probe did not enforce policy", [
          `exitCode=${result.exitCode}`,
          result.stderr.trim(),
          result.stdout.trim(),
        ]),
      );
      return {
        ...base,
        status: "failed",
        projectBuildRoot: spec.projectBuildRoot,
        projectConfigRoot: spec.projectConfigRoot,
        controlTempRoot: spec.controlTempRoot,
        profileSha256: spec.profileSha256,
        ...(observations === undefined ? {} : { observations }),
        diagnostics,
      };
    }
    diagnostics.push(
      diagnostic(
        "BUILD_SANDBOX_PROBE_PASSED",
        "info",
        "sandbox allowed only project build and controlled temporary writes",
      ),
    );
    return {
      ...base,
      status: "passed",
      projectBuildRoot: spec.projectBuildRoot,
      projectConfigRoot: spec.projectConfigRoot,
      controlTempRoot: spec.controlTempRoot,
      profileSha256: spec.profileSha256,
      observations,
      diagnostics,
    };
  } catch (error) {
    diagnostics.push(
      diagnostic("BUILD_SANDBOX_FAILED", "error", "build sandbox probe could not run", [
        error instanceof Error ? error.message : String(error),
      ]),
    );
    return {
      ...base,
      status: "failed",
      ...(spec === undefined
        ? {}
        : {
            projectBuildRoot: spec.projectBuildRoot,
            projectConfigRoot: spec.projectConfigRoot,
            controlTempRoot: spec.controlTempRoot,
            profileSha256: spec.profileSha256,
          }),
      diagnostics,
    };
  }
}
