import type { ImageIdentityV1 } from "./build";

function hashText(value: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex");
}

export function projectId(projectPath: string): string {
  return hashText(`leanbun-project-v1\0${projectPath}`);
}

export function imageId(identity: ImageIdentityV1): string {
  return hashText(
    JSON.stringify({
      schemaVersion: identity.schemaVersion,
      leanToolchain: identity.leanToolchain,
      leanCompilerGithash: identity.leanCompilerGithash,
      mathlibRevision: identity.mathlibRevision,
      canonicalManifestHash: identity.canonicalManifestHash,
      packageSourceTreeHash: identity.packageSourceTreeHash,
      buildRelevantConfigHash: identity.buildRelevantConfigHash,
      targetPlatform: identity.targetPlatform,
    }),
  );
}

export function validBuildTarget(target: string): boolean {
  return (
    target.length > 0 &&
    target.length <= 256 &&
    !target.startsWith("-") &&
    !target.includes("..") &&
    !/[\u0000-\u001f\u007f]/.test(target)
  );
}
