import { diagnostic, type Diagnostic } from "../domain/diagnostics";

export interface LakePackageRecord {
  name: string;
  type?: string;
  rev?: string;
  dir?: string;
  raw: Record<string, unknown>;
}

export interface LakeDocument {
  version: string;
  packages: readonly LakePackageRecord[];
  raw: Record<string, unknown>;
}

export interface ParseResult {
  document?: LakeDocument;
  diagnostics: readonly Diagnostic[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseLakeDocument(text: string, label: "manifest" | "override"): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    return {
      diagnostics: [
        diagnostic(
          "JSON_MALFORMED",
          "error",
          `${label} is not valid JSON`,
          [error instanceof Error ? error.message : String(error)],
        ),
      ],
    };
  }
  if (!isRecord(raw) || typeof raw.version !== "string" || !Array.isArray(raw.packages)) {
    return {
      diagnostics: [
        diagnostic(
          "MANIFEST_SHAPE_INVALID",
          "error",
          `${label} requires a string version and packages array`,
        ),
      ],
    };
  }

  const versionMatch = /^(\d+)\.(\d+)\.(\d+)$/.exec(raw.version);
  const major = versionMatch === null ? Number.NaN : Number(versionMatch[1]);
  if (major !== 1) {
    return {
      diagnostics: [
        diagnostic(
          "MANIFEST_SCHEMA_UNSUPPORTED",
          "error",
          `${label} schema ${raw.version} is not supported`,
          [`supported major=1`, `observed=${raw.version}`],
        ),
      ],
    };
  }

  const diagnostics: Diagnostic[] = [];
  const packages: LakePackageRecord[] = [];
  for (const [index, value] of raw.packages.entries()) {
    if (!isRecord(value) || typeof value.name !== "string") {
      diagnostics.push(
        diagnostic(
          "MANIFEST_SHAPE_INVALID",
          "error",
          `${label} package ${index} has no string name`,
        ),
      );
      continue;
    }
    const record: LakePackageRecord = { name: value.name, raw: value };
    if (typeof value.type === "string") record.type = value.type;
    if (typeof value.rev === "string") record.rev = value.rev;
    if (typeof value.dir === "string") record.dir = value.dir;
    packages.push(record);
  }
  return { document: { version: raw.version, packages, raw }, diagnostics };
}
