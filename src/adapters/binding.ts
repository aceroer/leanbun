import { join } from "node:path";
import { isWithin, readStableText } from "./filesystem";
import type { ImageAttestationV1, ProjectBindingV1 } from "../domain/build";
import { validBuildTarget } from "../domain/identity";
import type { CanonicalPath, Sha256 } from "../domain/model";

const documentLimit = 1024 * 1024;
const shaPattern = /^[0-9a-f]{64}$/;
const gitRevisionPattern = /^[0-9a-f]{40}$/;

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

export type LoadedDocument<T> =
  | { status: "missing"; path: string }
  | { status: "invalid"; path: string; message: string; sha256?: Sha256 }
  | { status: "valid"; path: CanonicalPath; sha256: Sha256; document: T };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validBinding(value: unknown): value is ProjectBindingV1 {
  if (!isRecord(value)) return false;
  const targets = value.allowedTargets;
  if (!Array.isArray(targets) || !targets.every((target): target is string => validBuildTarget(target))) {
    return false;
  }
  const canonicalTargets = [...new Set(targets)].sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right)),
  );
  return (
    value.schemaVersion === 1 &&
    value.policyVersion === 1 &&
    typeof value.projectId === "string" &&
    shaPattern.test(value.projectId) &&
    typeof value.projectPath === "string" &&
    typeof value.imageId === "string" &&
    shaPattern.test(value.imageId) &&
    typeof value.providerId === "string" &&
    validTimestamp(value.boundAt) &&
    typeof value.manifestSha256 === "string" &&
    shaPattern.test(value.manifestSha256) &&
    typeof value.toolchain === "string" &&
    targets.length > 0 &&
    targets.length === canonicalTargets.length &&
    targets.every((target, index) => target === canonicalTargets[index]) &&
    validTimestamp(value.lastVerifiedAt)
  );
}

function validIdentity(value: unknown): boolean {
  if (!isRecord(value) || value.schemaVersion !== 1) return false;
  return (
    typeof value.leanToolchain === "string" &&
    value.leanToolchain.length > 0 &&
    typeof value.leanCompilerGithash === "string" &&
    gitRevisionPattern.test(value.leanCompilerGithash) &&
    typeof value.mathlibRevision === "string" &&
    gitRevisionPattern.test(value.mathlibRevision) &&
    typeof value.canonicalManifestHash === "string" &&
    shaPattern.test(value.canonicalManifestHash) &&
    typeof value.packageSourceTreeHash === "string" &&
    shaPattern.test(value.packageSourceTreeHash) &&
    typeof value.buildRelevantConfigHash === "string" &&
    shaPattern.test(value.buildRelevantConfigHash) &&
    typeof value.targetPlatform === "string" &&
    value.targetPlatform.length > 0
  );
}

function validAttestation(value: unknown): value is ImageAttestationV1 {
  if (
    !isRecord(value) ||
    !isRecord(value.provider) ||
    !isRecord(value.artifactPolicy) ||
    !Array.isArray(value.artifactPolicy.missingRoots)
  ) {
    return false;
  }
  const missingRoots = value.artifactPolicy.missingRoots;
  if (!missingRoots.every((root): root is string => typeof root === "string" && root.length > 0)) {
    return false;
  }
  const canonicalMissingRoots = [...new Set(missingRoots)].sort((left, right) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right)),
  );
  return (
    value.schemaVersion === 1 &&
    typeof value.imageId === "string" &&
    shaPattern.test(value.imageId) &&
    typeof value.providerId === "string" &&
    value.status === "sealed" &&
    validIdentity(value.identity) &&
    typeof value.provider.registrySha256 === "string" &&
    shaPattern.test(value.provider.registrySha256) &&
    typeof value.provider.overridesSha256 === "string" &&
    shaPattern.test(value.provider.overridesSha256) &&
    typeof value.dependencyTreeHash === "string" &&
    shaPattern.test(value.dependencyTreeHash) &&
    typeof value.artifactTreeHash === "string" &&
    shaPattern.test(value.artifactTreeHash) &&
    typeof value.artifactCount === "number" &&
    Number.isSafeInteger(value.artifactCount) &&
    value.artifactCount >= 0 &&
    missingRoots.length === canonicalMissingRoots.length &&
    missingRoots.every((root, index) => root === canonicalMissingRoots[index]) &&
    validTimestamp(value.sealedAt)
  );
}

async function loadJson<T>(
  path: string,
  allowedRoot: CanonicalPath,
  validate: (value: unknown) => value is T,
): Promise<LoadedDocument<T>> {
  const observation = await readStableText(path, documentLimit);
  if (observation.status === "error") {
    return observation.error.code === "EVIDENCE_MISSING"
      ? { status: "missing", path }
      : { status: "invalid", path, message: observation.error.message };
  }
  if (!isWithin(allowedRoot, observation.source)) {
    return {
      status: "invalid",
      path,
      message: `document escapes allowed root: ${observation.source}`,
      sha256: observation.value.sha256,
    };
  }
  let value: unknown;
  try {
    value = JSON.parse(observation.value.text);
  } catch (error) {
    return {
      status: "invalid",
      path,
      message: error instanceof Error ? error.message : String(error),
      sha256: observation.value.sha256,
    };
  }
  if (!validate(value)) {
    return {
      status: "invalid",
      path,
      message: "document does not match schema version 1",
      sha256: observation.value.sha256,
    };
  }
  return {
    status: "valid",
    path: observation.source,
    sha256: observation.value.sha256,
    document: value,
  };
}

export function loadProjectBinding(project: CanonicalPath): Promise<LoadedDocument<ProjectBindingV1>> {
  return loadJson(join(project, ".leanbun/binding.json"), project, validBinding);
}

export function loadImageAttestation(
  stateRoot: CanonicalPath,
  imageId: string,
): Promise<LoadedDocument<ImageAttestationV1>> {
  if (!shaPattern.test(imageId)) {
    return Promise.resolve({
      status: "invalid",
      path: join(stateRoot, "attestations", imageId),
      message: "image id is not a SHA-256 value",
    });
  }
  return loadJson(join(stateRoot, "attestations", `${imageId}.json`), stateRoot, validAttestation);
}
