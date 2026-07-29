import type { Diagnostic } from "./diagnostics";

declare const canonicalPathBrand: unique symbol;
declare const sha256Brand: unique symbol;

export type CanonicalPath = string & { readonly [canonicalPathBrand]: true };
export type Sha256 = string & { readonly [sha256Brand]: true };
export type HashMode = "none" | "metadata" | "sha256";
export type ArtifactMode = "none" | "summary" | "full";
export type EvidenceStability = "stable" | "changed" | "unchecked";

interface ObservationBase {
  observedAt: string;
  source: CanonicalPath;
  stability: EvidenceStability;
}

export type Observed<T> =
  | (ObservationBase & { status: "ok"; value: T })
  | (ObservationBase & {
      status: "error";
      error: { code: string; message: string };
    });

export interface InspectRequest {
  project: string;
  provider?: "dependency-library";
  hashMode: HashMode;
  artifactMode?: ArtifactMode;
}

export interface ProjectEvidence {
  path: CanonicalPath;
  toolchain: Observed<string>;
}

export interface RuntimeComponentEvidence {
  path: CanonicalPath;
  version: string;
}

export interface RuntimeEvidence {
  bun: RuntimeComponentEvidence;
  lean?: RuntimeComponentEvidence;
  lake?: RuntimeComponentEvidence;
}

export interface ManifestEvidence {
  path: CanonicalPath;
  sha256?: Sha256;
  lakeSchema?: string;
  raw?: unknown;
}

export interface OverrideEvidence {
  path?: CanonicalPath;
  state: "registered" | "missing" | "drifted" | "unchecked";
  raw?: unknown;
}

export interface PackageEvidence {
  name: string;
  path?: CanonicalPath;
  expectedRevision?: string;
  providerRevision?: string;
  actualRevision?: string;
  dirty?: boolean;
  state: "matched" | "missing" | "mismatched" | "dirty" | "unchecked";
}

export interface ProviderEvidence {
  id: string;
  toolchain: string;
  state: "matched" | "drifted" | "unavailable";
  packageRoot: CanonicalPath;
  cacheRoot: CanonicalPath;
  registry: { path: CanonicalPath; sha256?: Sha256 };
  overrides: { path: CanonicalPath; sha256?: Sha256 };
  packageCount: number;
}

export type ArtifactKind = "olean" | "ilean" | "trace" | "hash" | "ltar";

export interface ArtifactFileEvidence {
  path: CanonicalPath;
  root: CanonicalPath;
  owner: string;
  kind: ArtifactKind;
  size: number;
  modifiedAt: string;
  stability: EvidenceStability;
  sha256?: Sha256;
}

export interface ArtifactRootSummary {
  owner: string;
  root: CanonicalPath;
  missing: boolean;
  counts: Record<ArtifactKind, number>;
}

export interface ArtifactEvidence {
  mode: ArtifactMode;
  complete: boolean;
  total: number;
  counts: Record<ArtifactKind, number>;
  roots: readonly ArtifactRootSummary[];
  observed: readonly ArtifactFileEvidence[];
  unverifiedHashFiles: readonly CanonicalPath[];
}

export interface InspectReport {
  schemaVersion: 1;
  mode: "filesystem-only";
  project: ProjectEvidence;
  runtime: RuntimeEvidence;
  manifest: ManifestEvidence;
  overrides: OverrideEvidence;
  provider?: ProviderEvidence;
  packages: readonly PackageEvidence[];
  artifacts: ArtifactEvidence;
  diagnostics: readonly Diagnostic[];
}
