import { canonicalizeContained, canonicalizeDirectory, readStableText } from "./filesystem";
import { parseLakeDocument, type LakeDocument } from "./manifest";
import { readGitHead, readGitStatus, type CommandResult } from "./process";
import { diagnostic, type Diagnostic } from "../domain/diagnostics";
import type {
  CanonicalPath,
  PackageEvidence,
  ProviderEvidence,
} from "../domain/model";

export interface DependencyProviderConfig {
  id: string;
  toolchain: string;
  registry: string;
  overrides: string;
  packageRoot: string;
  cacheRoot: string;
}

export interface ProviderInspection {
  evidence: ProviderEvidence;
  packages: readonly PackageEvidence[];
  registryDocument?: LakeDocument;
  overrideDocument?: LakeDocument;
  diagnostics: readonly Diagnostic[];
}

const jsonLimit = 4 * 1024 * 1024;

export function dependencyProviderFromEnvironment(): DependencyProviderConfig | undefined {
  const id = process.env.LEANBUN_PROVIDER_ID;
  const toolchain = process.env.LEANBUN_PROVIDER_TOOLCHAIN;
  const registry = process.env.LEANBUN_PROVIDER_REGISTRY;
  const overrides = process.env.LEANBUN_PROVIDER_OVERRIDES;
  const packageRoot = process.env.LEANBUN_PROVIDER_PACKAGE_ROOT;
  const cacheRoot = process.env.LEANBUN_PROVIDER_CACHE_ROOT;
  if (
    id === undefined ||
    toolchain === undefined ||
    registry === undefined ||
    overrides === undefined ||
    packageRoot === undefined ||
    cacheRoot === undefined
  ) {
    return undefined;
  }
  return { id, toolchain, registry, overrides, packageRoot, cacheRoot };
}

function commandDiagnostic(
  packageName: string,
  operation: string,
  result: CommandResult,
): Diagnostic | undefined {
  if (result.timedOut) {
    return diagnostic("COMMAND_TIMEOUT", "error", `Git ${operation} timed out`, [
      `package=${packageName}`,
    ]);
  }
  if (result.outputExceeded) {
    return diagnostic("COMMAND_OUTPUT_LIMIT", "error", `Git ${operation} exceeded output limit`, [
      `package=${packageName}`,
    ]);
  }
  if (result.exitCode !== 0) {
    return diagnostic("GIT_EVIDENCE_FAILED", "error", `Git ${operation} failed`, [
      `package=${packageName}`,
      `exitCode=${result.exitCode}`,
      result.stderr.trim(),
    ]);
  }
  return undefined;
}

export async function inspectDependencyProvider(
  config: DependencyProviderConfig,
): Promise<ProviderInspection> {
  const diagnostics: Diagnostic[] = [];
  const packageRoot = await canonicalizeDirectory(config.packageRoot);
  const cacheRoot = await canonicalizeDirectory(config.cacheRoot);
  const [registryRead, overrideRead] = await Promise.all([
    readStableText(config.registry, jsonLimit),
    readStableText(config.overrides, jsonLimit),
  ]);
  const registryParse =
    registryRead.status === "ok"
      ? parseLakeDocument(registryRead.value.text, "manifest")
      : { diagnostics: [], document: undefined };
  const overrideParse =
    overrideRead.status === "ok"
      ? parseLakeDocument(overrideRead.value.text, "override")
      : { diagnostics: [], document: undefined };

  if (registryRead.status === "error") {
    diagnostics.push(
      diagnostic("PROVIDER_UNAVAILABLE", "error", "provider registry cannot be read", [
        registryRead.source,
        registryRead.error.message,
      ]),
    );
  }
  if (overrideRead.status === "error") {
    diagnostics.push(
      diagnostic("PROVIDER_UNAVAILABLE", "error", "provider override cannot be read", [
        overrideRead.source,
        overrideRead.error.message,
      ]),
    );
  }
  for (const value of [...registryParse.diagnostics, ...overrideParse.diagnostics]) {
    diagnostics.push(
      diagnostic("PROVIDER_SCHEMA_INVALID", value.severity, value.message, value.evidence),
    );
  }

  const overrideByName = new Map(
    (overrideParse.document?.packages ?? []).map((value) => [value.name, value]),
  );
  const packages: PackageEvidence[] = [];
  for (const expected of [...(registryParse.document?.packages ?? [])].sort((left, right) =>
    left.name.localeCompare(right.name, "en"),
  )) {
    const evidence: PackageEvidence = {
      name: expected.name,
      state: "unchecked",
      ...(expected.rev === undefined ? {} : { providerRevision: expected.rev }),
    };
    const override = overrideByName.get(expected.name);
    if (override === undefined || override.type !== "path" || override.dir === undefined) {
      evidence.state = "missing";
      diagnostics.push(
        diagnostic("OVERRIDE_MISSING", "error", "provider package override is missing", [
          `package=${expected.name}`,
        ]),
      );
      packages.push(evidence);
      continue;
    }
    try {
      const directory = await canonicalizeContained(packageRoot, override.dir);
      evidence.path = directory;
      const [head, status] = await Promise.all([
        readGitHead(directory),
        readGitStatus(directory),
      ]);
      const headDiagnostic = commandDiagnostic(expected.name, "rev-parse", head);
      const statusDiagnostic = commandDiagnostic(expected.name, "status", status);
      if (headDiagnostic !== undefined) diagnostics.push(headDiagnostic);
      if (statusDiagnostic !== undefined) diagnostics.push(statusDiagnostic);
      if (headDiagnostic !== undefined || statusDiagnostic !== undefined) {
        evidence.state = "unchecked";
      } else {
        evidence.actualRevision = head.stdout.trim();
        evidence.dirty = status.stdout.length > 0;
        if (evidence.actualRevision !== expected.rev) {
          evidence.state = "mismatched";
          diagnostics.push(
            diagnostic("PACKAGE_REVISION_MISMATCH", "error", "provider package revision differs", [
              `package=${expected.name}`,
              `expected=${expected.rev ?? "<missing>"}`,
              `actual=${evidence.actualRevision}`,
            ]),
          );
        } else if (evidence.dirty) {
          evidence.state = "dirty";
          diagnostics.push(
            diagnostic("PACKAGE_DIRTY", "warning", "provider package working tree is dirty", [
              `package=${expected.name}`,
              ...status.stdout.trimEnd().split("\n"),
            ]),
          );
        } else {
          evidence.state = "matched";
        }
      }
    } catch (error) {
      evidence.state = "missing";
      diagnostics.push(
        diagnostic("PROVIDER_PACKAGE_MISSING", "error", "provider package path is invalid", [
          `package=${expected.name}`,
          `dir=${override.dir}`,
          error instanceof Error ? error.message : String(error),
        ]),
      );
    }
    packages.push(evidence);
  }

  const registryNames = new Set(registryParse.document?.packages.map((value) => value.name) ?? []);
  for (const extra of overrideParse.document?.packages ?? []) {
    if (!registryNames.has(extra.name)) {
      diagnostics.push(
        diagnostic("OVERRIDE_DRIFTED", "error", "provider override has an unregistered package", [
          `package=${extra.name}`,
        ]),
      );
    }
  }

  const hasDrift = diagnostics.some(
    (value) => value.severity === "error" || value.code === "PACKAGE_DIRTY",
  );
  return {
    evidence: {
      id: config.id,
      toolchain: config.toolchain,
      state: hasDrift ? "drifted" : "matched",
      packageRoot,
      cacheRoot,
      registry: {
        path: registryRead.source,
        ...(registryRead.status === "ok" ? { sha256: registryRead.value.sha256 } : {}),
      },
      overrides: {
        path: overrideRead.source,
        ...(overrideRead.status === "ok" ? { sha256: overrideRead.value.sha256 } : {}),
      },
      packageCount: packages.length,
    },
    packages,
    ...(registryParse.document === undefined
      ? {}
      : { registryDocument: registryParse.document }),
    ...(overrideParse.document === undefined
      ? {}
      : { overrideDocument: overrideParse.document }),
    diagnostics,
  };
}
