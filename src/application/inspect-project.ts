import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  canonicalizeContained,
  canonicalizeDirectory,
  FilesystemEvidenceError,
  readStableText,
  type StableTextFile,
} from "../adapters/filesystem";
import {
  parseLakeDocument,
  type LakeDocument,
  type ParseResult,
} from "../adapters/manifest";
import { currentBunProvenance } from "../adapters/runtime";
import { observeArtifacts, type ArtifactRootSpec } from "../adapters/artifacts";
import {
  dependencyProviderFromEnvironment,
  inspectDependencyProvider,
  type ProviderInspection,
} from "../adapters/dependency-library";
import {
  diagnostic,
  diagnosticCodes,
  type Diagnostic,
  type DiagnosticCode,
} from "../domain/diagnostics";
import type {
  CanonicalPath,
  InspectReport,
  InspectRequest,
  Observed,
  PackageEvidence,
} from "../domain/model";

export const projectInputLimits = Object.freeze({
  toolchainBytes: 16 * 1024,
  jsonBytes: 4 * 1024 * 1024,
});

function knownDiagnosticCode(code: string): DiagnosticCode {
  return diagnosticCodes.includes(code as DiagnosticCode)
    ? (code as DiagnosticCode)
    : "EVIDENCE_READ_FAILED";
}

function observationDiagnostic(observation: Observed<unknown>, label: string): Diagnostic | undefined {
  if (observation.status === "ok") {
    if (observation.stability === "changed") {
      return diagnostic(
        "EVIDENCE_CHANGED_DURING_READ",
        "error",
        `${label} changed while it was being read`,
        [observation.source],
      );
    }
    return undefined;
  }
  return diagnostic(
    knownDiagnosticCode(observation.error.code),
    "error",
    `${label} could not be read`,
    [observation.source, observation.error.message],
  );
}

function textObservation(observation: Observed<StableTextFile>): Observed<string> {
  if (observation.status === "error") return observation;
  return { ...observation, value: observation.value.text.trim() };
}

async function validatePackagePaths(
  root: CanonicalPath,
  document: LakeDocument | undefined,
  label: string,
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  for (const packageRecord of document?.packages ?? []) {
    if (packageRecord.type !== "path" || packageRecord.dir === undefined) continue;
    try {
      await canonicalizeContained(root, packageRecord.dir);
    } catch (error) {
      const code =
        error instanceof FilesystemEvidenceError
          ? knownDiagnosticCode(error.code)
          : "EVIDENCE_READ_FAILED";
      diagnostics.push(
        diagnostic(code, "error", `${label} package path is not allowed`, [
          `package=${packageRecord.name}`,
          `dir=${packageRecord.dir}`,
          error instanceof Error ? error.message : String(error),
        ]),
      );
    }
  }
  return diagnostics;
}

function packageEvidence(document: LakeDocument | undefined): PackageEvidence[] {
  return [...(document?.packages ?? [])]
    .sort((left, right) => left.name.localeCompare(right.name, "en"))
    .map((value) => {
      const evidence: PackageEvidence = { name: value.name, state: "unchecked" };
      if (value.rev !== undefined) evidence.expectedRevision = value.rev;
      return evidence;
    });
}

function canonicalJson(value: unknown): string {
  if (value === undefined) return "undefined";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function matchProjectProvider(
  manifest: LakeDocument | undefined,
  override: LakeDocument | undefined,
  provider: ProviderInspection,
): { packages: PackageEvidence[]; diagnostics: Diagnostic[]; overrideMatched: boolean } {
  const diagnostics: Diagnostic[] = [];
  const projectPackages = new Map((manifest?.packages ?? []).map((value) => [value.name, value]));
  const providerPackages = new Map(
    (provider.registryDocument?.packages ?? []).map((value) => [value.name, value]),
  );
  if (projectPackages.size > 0) {
    for (const [name, expected] of providerPackages) {
      const actual = projectPackages.get(name);
      if (actual === undefined) {
        diagnostics.push(
          diagnostic("MANIFEST_PROVIDER_MISMATCH", "error", "project manifest lacks provider package", [
            `package=${name}`,
          ]),
        );
        continue;
      }
      for (const field of ["rev", "url", "subDir", "manifestFile", "configFile"] as const) {
        if (canonicalJson(actual.raw[field]) !== canonicalJson(expected.raw[field])) {
          diagnostics.push(
            diagnostic(
              "MANIFEST_PROVIDER_MISMATCH",
              "error",
              "project manifest field differs from provider registry",
              [
                `package=${name}`,
                `field=${field}`,
                `project=${canonicalJson(actual.raw[field])}`,
                `provider=${canonicalJson(expected.raw[field])}`,
              ],
            ),
          );
        }
      }
    }
    for (const name of projectPackages.keys()) {
      if (!providerPackages.has(name)) {
        diagnostics.push(
          diagnostic("MANIFEST_PROVIDER_MISMATCH", "error", "project has an unregistered package", [
            `package=${name}`,
          ]),
        );
      }
    }
  }

  const overrideMatched =
    override !== undefined &&
    provider.overrideDocument !== undefined &&
    canonicalJson(override.raw) === canonicalJson(provider.overrideDocument.raw);
  if (override !== undefined && !overrideMatched) {
    diagnostics.push(
      diagnostic("OVERRIDE_DRIFTED", "error", "project override differs from provider override"),
    );
  }

  const packages = provider.packages.map((providerPackage) => {
    const projectPackage = projectPackages.get(providerPackage.name);
    const value: PackageEvidence = {
      ...providerPackage,
      ...(projectPackage?.rev === undefined ? {} : { expectedRevision: projectPackage.rev }),
    };
    if (
      projectPackage !== undefined &&
      projectPackage.rev !== undefined &&
      projectPackage.rev !== providerPackage.providerRevision
    ) {
      value.state = "mismatched";
    }
    return value;
  });
  return { packages, diagnostics, overrideMatched };
}

export async function inspectProject(request: InspectRequest): Promise<InspectReport> {
  const project = await canonicalizeDirectory(request.project);
  const diagnostics: Diagnostic[] = [];

  const toolchainRead = await readStableText(
    join(project, "lean-toolchain"),
    projectInputLimits.toolchainBytes,
  );
  const toolchainDiagnostic = observationDiagnostic(toolchainRead, "lean-toolchain");
  if (toolchainDiagnostic !== undefined) diagnostics.push(toolchainDiagnostic);
  if (toolchainRead.status === "ok" && toolchainRead.value.text.trim() === "") {
    diagnostics.push(
      diagnostic("TOOLCHAIN_INVALID", "error", "lean-toolchain is empty", [toolchainRead.source]),
    );
  }

  const manifestRead = await readStableText(
    join(project, "lake-manifest.json"),
    projectInputLimits.jsonBytes,
  );
  const manifestReadDiagnostic = observationDiagnostic(manifestRead, "lake-manifest.json");
  if (manifestReadDiagnostic !== undefined) diagnostics.push(manifestReadDiagnostic);
  const manifestParse: ParseResult =
    manifestRead.status === "ok"
      ? parseLakeDocument(manifestRead.value.text, "manifest")
      : { diagnostics: [] };
  diagnostics.push(...manifestParse.diagnostics);
  diagnostics.push(...(await validatePackagePaths(project, manifestParse.document, "manifest")));

  const overrideRead = await readStableText(
    join(project, ".lake/package-overrides.json"),
    projectInputLimits.jsonBytes,
  );
  const overrideMissing =
    overrideRead.status === "error" && overrideRead.error.code === "EVIDENCE_MISSING";
  if (overrideMissing) {
    diagnostics.push(
      diagnostic("OVERRIDE_MISSING", "warning", "project package override is missing", [
        resolve(project, ".lake/package-overrides.json"),
      ]),
    );
  } else {
    const overrideReadDiagnostic = observationDiagnostic(overrideRead, "package-overrides.json");
    if (overrideReadDiagnostic !== undefined) diagnostics.push(overrideReadDiagnostic);
  }
  const overrideParse: ParseResult =
    overrideRead.status === "ok"
      ? parseLakeDocument(overrideRead.value.text, "override")
      : { diagnostics: [] };
  diagnostics.push(...overrideParse.diagnostics);
  if (request.provider === undefined) {
    diagnostics.push(...(await validatePackagePaths(project, overrideParse.document, "override")));
  }

  let providerInspection: ProviderInspection | undefined;
  if (request.provider === "dependency-library") {
    const providerConfig = dependencyProviderFromEnvironment();
    if (providerConfig === undefined) {
      diagnostics.push(
        diagnostic("PROVIDER_UNAVAILABLE", "error", "dependency provider is not configured"),
      );
    } else {
      try {
        providerInspection = await inspectDependencyProvider(providerConfig);
        diagnostics.push(...providerInspection.diagnostics);
      } catch (error) {
        diagnostics.push(
          diagnostic("PROVIDER_UNAVAILABLE", "error", "dependency provider inspection failed", [
            error instanceof Error ? error.message : String(error),
          ]),
        );
      }
    }
  }

  let packages = packageEvidence(manifestParse.document);
  let overrideState: "registered" | "missing" | "drifted" | "unchecked" =
    overrideRead.status !== "ok"
      ? overrideMissing
        ? "missing"
        : "unchecked"
      : overrideParse.document === undefined
        ? "drifted"
        : "registered";
  if (providerInspection !== undefined) {
    const match = matchProjectProvider(
      manifestParse.document,
      overrideParse.document,
      providerInspection,
    );
    packages = match.packages;
    diagnostics.push(...match.diagnostics);
    if (overrideRead.status === "ok") overrideState = match.overrideMatched ? "registered" : "drifted";
    if (
      toolchainRead.status === "ok" &&
      toolchainRead.value.text.trim() !== providerInspection.evidence.toolchain
    ) {
      diagnostics.push(
        diagnostic("TOOLCHAIN_MISMATCH", "error", "project toolchain differs from provider", [
          `project=${toolchainRead.value.text.trim()}`,
          `provider=${providerInspection.evidence.toolchain}`,
        ]),
      );
    }
  }

  const artifactRoots: ArtifactRootSpec[] = [
    { owner: "project", path: join(project, ".lake/build"), role: "project" },
  ];
  if (providerInspection !== undefined) {
    for (const packageValue of providerInspection.packages) {
      if (packageValue.path !== undefined) {
        artifactRoots.push({
          owner: packageValue.name,
          path: join(packageValue.path, ".lake/build"),
          role: "package",
        });
      }
    }
    artifactRoots.push({
      owner: "mathlib-cache",
      path: providerInspection.evidence.cacheRoot,
      role: "cache",
    });
  }
  const artifactObservation = await observeArtifacts(
    artifactRoots,
    request.artifactMode ?? "none",
    request.hashMode,
  );
  diagnostics.push(...artifactObservation.diagnostics);

  diagnostics.push(
    diagnostic(
      "LAKE_EXECUTION_NOT_ATTEMPTED",
      "info",
      "inspection used filesystem evidence only; no Lake workspace command was executed",
    ),
  );

  const bun = currentBunProvenance();
  const bunPath = (await realpath(process.execPath)) as CanonicalPath;
  return {
    schemaVersion: 1,
    mode: "filesystem-only",
    project: { path: project, toolchain: textObservation(toolchainRead) },
    runtime: {
      bun: { path: bunPath, version: `${bun.version}+${bun.revision.slice(0, 9)}` },
    },
    manifest: {
      path: manifestRead.source,
      ...(manifestRead.status === "ok" && request.hashMode === "sha256"
        ? { sha256: manifestRead.value.sha256 }
        : {}),
      ...(manifestParse.document === undefined
        ? {}
        : {
            lakeSchema: manifestParse.document.version,
            raw: manifestParse.document.raw,
          }),
    },
    overrides: {
      ...(overrideRead.status === "ok" ? { path: overrideRead.source } : {}),
      state: overrideState,
      ...(overrideParse.document === undefined ? {} : { raw: overrideParse.document.raw }),
    },
    ...(providerInspection === undefined ? {} : { provider: providerInspection.evidence }),
    packages,
    artifacts: artifactObservation.evidence,
    diagnostics,
  };
}
