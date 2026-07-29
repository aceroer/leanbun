import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import type { ImageAttestationV1 } from "../domain/build";
import { imageId } from "../domain/identity";
import type { CanonicalPath, Sha256 } from "../domain/model";
import { loadImageAttestation } from "./binding";
import { isWithin } from "./filesystem";

const shaPattern = /^[0-9a-f]{64}$/;

export class AttestationStoreError extends Error {
  constructor(
    readonly code:
      | "ATTESTATION_SEAL_BUSY"
      | "ATTESTATION_SEAL_CONFLICT"
      | "ATTESTATION_SEAL_FAILED",
    message: string,
  ) {
    super(message);
  }
}

export interface StoredAttestation {
  status: "sealed" | "already-sealed";
  path: CanonicalPath;
  sha256: Sha256;
  document: ImageAttestationV1;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined;
}

function hashBytes(value: Uint8Array): Sha256 {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(value);
  return hasher.digest("hex") as Sha256;
}

function canonicalBytes(document: ImageAttestationV1): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
}

function sameEvidence(left: ImageAttestationV1, right: ImageAttestationV1): boolean {
  return JSON.stringify({ ...left, sealedAt: "" }) === JSON.stringify({ ...right, sealedAt: "" });
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function prepareAttestationDirectory(stateRoot: CanonicalPath): Promise<CanonicalPath> {
  const directory = join(stateRoot, "attestations");
  let created = false;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
  }
  const metadata = await lstat(directory);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new AttestationStoreError(
      "ATTESTATION_SEAL_FAILED",
      `attestation store is not a direct directory: ${directory}`,
    );
  }
  const canonical = await realpath(directory);
  if (canonical !== directory || !isWithin(stateRoot, canonical)) {
    throw new AttestationStoreError(
      "ATTESTATION_SEAL_FAILED",
      `attestation store escapes state root: ${directory} -> ${canonical}`,
    );
  }
  if (created) await syncDirectory(stateRoot);
  return canonical as CanonicalPath;
}

/**
 * Publish one immutable attestation. The cooperative lock prevents another
 * LeanBun seal transaction from replacing the same image between the
 * existence check and rename. A stale lock is never removed automatically.
 */
export async function storeImageAttestation(
  stateRoot: CanonicalPath,
  document: ImageAttestationV1,
): Promise<StoredAttestation> {
  if (!shaPattern.test(document.imageId)) {
    throw new AttestationStoreError("ATTESTATION_SEAL_FAILED", "image id is not SHA-256");
  }
  if (
    imageId(document.identity) !== document.imageId ||
    document.provider.registrySha256 !== document.identity.canonicalManifestHash
  ) {
    throw new AttestationStoreError(
      "ATTESTATION_SEAL_FAILED",
      "attestation identity or canonical registry hash is internally inconsistent",
    );
  }
  const directory = await prepareAttestationDirectory(stateRoot);
  const target = join(directory, `${document.imageId}.json`);
  const lock = join(directory, `${document.imageId}.lock`);
  const nonce = crypto.randomUUID();
  const temporary = join(directory, `.${document.imageId}.${process.pid}.${nonce}.tmp`);
  let lockHandle: Awaited<ReturnType<typeof open>> | undefined;
  let temporaryHandle: Awaited<ReturnType<typeof open>> | undefined;
  let published = false;
  try {
    try {
      lockHandle = await open(
        lock,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (errorCode(error) === "EEXIST") {
        throw new AttestationStoreError(
          "ATTESTATION_SEAL_BUSY",
          `attestation seal lock already exists: ${lock}`,
        );
      }
      throw error;
    }
    await lockHandle.writeFile(
      `${JSON.stringify({ pid: process.pid, imageId: document.imageId, startedAt: new Date().toISOString() })}\n`,
    );
    await lockHandle.sync();

    const existing = await loadImageAttestation(stateRoot, document.imageId);
    if (existing.status === "valid") {
      if (!sameEvidence(existing.document, document)) {
        throw new AttestationStoreError(
          "ATTESTATION_SEAL_CONFLICT",
          `sealed image already exists with different evidence: ${target}`,
        );
      }
      return {
        status: "already-sealed",
        path: existing.path,
        sha256: existing.sha256,
        document: existing.document,
      };
    }
    if (existing.status === "invalid") {
      throw new AttestationStoreError(
        "ATTESTATION_SEAL_CONFLICT",
        `attestation target exists but is invalid: ${target}: ${existing.message}`,
      );
    }

    const bytes = canonicalBytes(document);
    temporaryHandle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    await temporaryHandle.chmod(0o444);
    await temporaryHandle.sync();
    await temporaryHandle.close();
    temporaryHandle = undefined;

    await rename(temporary, target);
    published = true;
    await syncDirectory(directory);

    const verified = await loadImageAttestation(stateRoot, document.imageId);
    const expectedSha = hashBytes(bytes);
    if (
      verified.status !== "valid" ||
      verified.sha256 !== expectedSha ||
      JSON.stringify(verified.document) !== JSON.stringify(document)
    ) {
      throw new AttestationStoreError(
        "ATTESTATION_SEAL_FAILED",
        `published attestation failed immediate readback verification: ${target}`,
      );
    }
    const mode = (await lstat(target)).mode & 0o777;
    if (mode !== 0o444) {
      throw new AttestationStoreError(
        "ATTESTATION_SEAL_FAILED",
        `published attestation mode is ${mode.toString(8)}, expected 444: ${target}`,
      );
    }
    return {
      status: "sealed",
      path: verified.path,
      sha256: verified.sha256,
      document: verified.document,
    };
  } catch (error) {
    if (error instanceof AttestationStoreError) throw error;
    throw new AttestationStoreError(
      "ATTESTATION_SEAL_FAILED",
      error instanceof Error ? error.message : String(error),
    );
  } finally {
    await temporaryHandle?.close().catch(() => undefined);
    if (!published) await unlink(temporary).catch(() => undefined);
    await lockHandle?.close().catch(() => undefined);
    if (lockHandle !== undefined) {
      await unlink(lock).catch(() => undefined);
      await syncDirectory(directory).catch(() => undefined);
    }
  }
}
