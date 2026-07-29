import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { diagnostic, diagnosticCodes } from "../src/domain/diagnostics";
import { imageId, projectId, validBuildTarget } from "../src/domain/identity";

const goldenRoot = new URL("../rust/golden/", import.meta.url);
const rustRoot = new URL("../rust/", import.meta.url);
const configRoot = new URL("../config/", import.meta.url);

test("Rust diagnostic vocabulary matches the Bun oracle", async () => {
  const expected = (await readFile(new URL("diagnostic-codes.txt", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  expect(expected).toEqual([...diagnosticCodes]);
});

test("Rust canonical diagnostic JSON matches JSON.stringify", async () => {
  const expected = (await readFile(new URL("diagnostic.json", goldenRoot), "utf8")).trimEnd();
  const value = diagnostic(
    "EVIDENCE_READ_FAILED",
    "error",
    'cannot read "fixture"\nnext',
    ["fixture", "路径"],
  );
  expect(JSON.stringify(value)).toBe(expected);
});

test("Rust target cases match the Bun validator", async () => {
  const lines = (await readFile(new URL("target-cases.txt", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expectedText, encoding, payload = ""] = line.split("\t");
    const value =
      encoding === "hex"
        ? Buffer.from(payload, "hex").toString("utf8")
        : encoding === "repeat-a"
          ? "a".repeat(Number(payload))
          : encoding === "repeat-grin"
            ? "😀".repeat(Number(payload))
            : payload;
    expect(validBuildTarget(value), line).toBe(expectedText === "true");
  }
});

test("Rust SHA-256 cases match Bun CryptoHasher", async () => {
  const lines = (await readFile(new URL("sha256-cases.txt", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [encoding, payload, expected] = line.split("\t");
    const input =
      encoding === "repeat-a"
        ? Buffer.from("a".repeat(Number(payload)), "utf8")
        : Buffer.from(payload, "hex");
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(input);
    expect(hasher.digest("hex"), line).toBe(expected);
  }
});

const providerRootFields = new Set(["version", "packagesDir", "packages"]);
const providerPackageFields = new Set([
  "configFile",
  "inherited",
  "inputRev",
  "manifestFile",
  "name",
  "rev",
  "scope",
  "subDir",
  "type",
  "url",
]);

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, maximumBytes = 256): value is string {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function validProviderRegistryContract(text: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!record(value) || Object.keys(value).some((field) => !providerRootFields.has(field))) {
    return false;
  }
  if (!boundedString(value.version) || !/^\d+\.\d+\.\d+$/.test(value.version)) return false;
  if (Number(value.version.split(".")[0]) !== 1) return false;
  if (!boundedString(value.packagesDir) || value.packagesDir.length === 0) return false;
  if (!Array.isArray(value.packages) || value.packages.length > 4096) return false;

  const names = new Set<string>();
  for (const entry of value.packages) {
    if (!record(entry) || Object.keys(entry).some((field) => !providerPackageFields.has(field))) {
      return false;
    }
    if (!boundedString(entry.name) || entry.name.length === 0 || names.has(entry.name)) return false;
    names.add(entry.name);
    if (!boundedString(entry.type) || entry.type !== "git") return false;
    if (!boundedString(entry.rev) || !/^[0-9a-f]{40}$/.test(entry.rev)) return false;
    if (entry.url !== undefined && !boundedString(entry.url, 4096)) return false;
    if (entry.subDir !== undefined && entry.subDir !== null && !boundedString(entry.subDir)) {
      return false;
    }
    for (const field of ["scope", "manifestFile", "inputRev", "configFile"] as const) {
      if (entry[field] !== undefined && !boundedString(entry[field])) return false;
    }
    if (entry.inherited !== undefined && typeof entry.inherited !== "boolean") return false;
  }
  return true;
}

test("Rust provider registry decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("provider-registry-cases.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expected, label, json] = line.split("\t", 3);
    expect(validProviderRegistryContract(json), label).toBe(expected === "true");
  }
});

const providerOverrideRootFields = new Set(["version", "packages"]);
const providerOverridePackageFields = new Set([
  "configFile",
  "dir",
  "inherited",
  "manifestFile",
  "name",
  "type",
]);

function validProviderOverrideContract(text: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!record(value) || Object.keys(value).some((field) => !providerOverrideRootFields.has(field))) {
    return false;
  }
  if (!boundedString(value.version) || !/^\d+\.\d+\.\d+$/.test(value.version)) return false;
  if (Number(value.version.split(".")[0]) !== 1) return false;
  if (!Array.isArray(value.packages) || value.packages.length > 4096) return false;

  const names = new Set<string>();
  for (const entry of value.packages) {
    if (
      !record(entry) ||
      Object.keys(entry).some((field) => !providerOverridePackageFields.has(field))
    ) {
      return false;
    }
    if (!boundedString(entry.name) || entry.name.length === 0 || names.has(entry.name)) return false;
    names.add(entry.name);
    if (!boundedString(entry.type) || entry.type !== "path") return false;
    if (!boundedString(entry.dir, 4096) || !isAbsolute(entry.dir)) return false;
    for (const field of ["manifestFile", "configFile"] as const) {
      if (entry[field] !== undefined && !boundedString(entry[field])) return false;
    }
    if (entry.inherited !== undefined && typeof entry.inherited !== "boolean") return false;
  }
  return true;
}

test("Rust provider override decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("provider-override-cases.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expected, label, json] = line.split("\t", 3);
    expect(validProviderOverrideContract(json), label).toBe(expected === "true");
  }
});

const projectManifestRootFields = new Set([
  "fixedToolchain",
  "lakeDir",
  "name",
  "packages",
  "packagesDir",
  "version",
]);
const projectManifestPackageFields = new Set([
  "configFile",
  "dir",
  "inherited",
  "inputRev",
  "manifestFile",
  "name",
  "rev",
  "scope",
  "subDir",
  "type",
  "url",
]);

function validProjectManifestContract(text: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!record(value) || Object.keys(value).some((field) => !projectManifestRootFields.has(field))) {
    return false;
  }
  if (!boundedString(value.version) || !/^\d+\.\d+\.\d+$/.test(value.version)) return false;
  if (Number(value.version.split(".")[0]) !== 1) return false;
  if (!boundedString(value.packagesDir, 4096) || value.packagesDir.length === 0) return false;
  if (!boundedString(value.name) || value.name.length === 0) return false;
  if (!boundedString(value.lakeDir, 4096) || value.lakeDir.length === 0) return false;
  if (typeof value.fixedToolchain !== "boolean") return false;
  if (!Array.isArray(value.packages) || value.packages.length > 4096) return false;

  const names = new Set<string>();
  for (const entry of value.packages) {
    if (
      !record(entry) ||
      Object.keys(entry).some((field) => !projectManifestPackageFields.has(field))
    ) {
      return false;
    }
    if (!boundedString(entry.name) || entry.name.length === 0 || names.has(entry.name)) return false;
    names.add(entry.name);
    if (!boundedString(entry.type)) return false;
    if (entry.type === "git") {
      if (entry.dir !== undefined) return false;
      if (!boundedString(entry.rev) || !/^[0-9a-f]{40}$/.test(entry.rev)) return false;
      if (entry.url !== undefined && !boundedString(entry.url, 4096)) return false;
      if (entry.subDir !== undefined && entry.subDir !== null && !boundedString(entry.subDir)) {
        return false;
      }
      for (const field of ["scope", "manifestFile", "inputRev", "configFile"] as const) {
        if (entry[field] !== undefined && !boundedString(entry[field])) return false;
      }
    } else if (entry.type === "path") {
      if (!boundedString(entry.dir, 4096) || entry.dir.length === 0) return false;
      for (const forbidden of ["rev", "url", "subDir", "scope", "inputRev"] as const) {
        if (entry[forbidden] !== undefined) return false;
      }
      for (const field of ["manifestFile", "configFile"] as const) {
        if (entry[field] !== undefined && !boundedString(entry[field])) return false;
      }
    } else {
      return false;
    }
    if (entry.inherited !== undefined && typeof entry.inherited !== "boolean") return false;
  }
  return true;
}

test("Rust project manifest decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("project-manifest-cases.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expected, label, json] = line.split("\t", 3);
    expect(validProjectManifestContract(json), label).toBe(expected === "true");
  }
});

const projectBindingFields = new Set([
  "allowedTargets",
  "boundAt",
  "imageId",
  "lastVerifiedAt",
  "manifestSha256",
  "policyVersion",
  "projectId",
  "projectPath",
  "providerId",
  "schemaVersion",
  "toolchain",
]);
const lowercaseSha256 = /^[0-9a-f]{64}$/;

function validCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/.exec(value);
  if (match === null) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const [year, month, day, hour, minute, second] =
    [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  if (year === 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    return false;
  }
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const maximumDay = month === 2 ? (leap ? 29 : 28) : [4, 6, 9, 11].includes(month) ? 30 : 31;
  return day >= 1 && day <= maximumDay;
}

function validProjectBindingContract(text: string, expectedProjectPath: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!record(value) || Object.keys(value).some((field) => !projectBindingFields.has(field))) {
    return false;
  }
  if (Object.keys(value).length !== projectBindingFields.size) return false;
  if (value.schemaVersion !== 1 || value.policyVersion !== 1) return false;
  if (value.projectPath !== expectedProjectPath || value.projectId !== projectId(expectedProjectPath)) {
    return false;
  }
  if (typeof value.imageId !== "string" || !lowercaseSha256.test(value.imageId)) return false;
  if (typeof value.manifestSha256 !== "string" || !lowercaseSha256.test(value.manifestSha256)) {
    return false;
  }
  for (const field of ["providerId", "toolchain"] as const) {
    if (!boundedString(value[field]) || value[field].length === 0 || /[\u0000-\u001f\u007f-\u009f]/u.test(value[field])) {
      return false;
    }
  }
  if (!validCanonicalTimestamp(value.boundAt) || !validCanonicalTimestamp(value.lastVerifiedAt)) {
    return false;
  }
  if (value.lastVerifiedAt < value.boundAt) return false;
  if (!Array.isArray(value.allowedTargets) || value.allowedTargets.length < 1 || value.allowedTargets.length > 256) {
    return false;
  }
  const targets = value.allowedTargets;
  if (!targets.every((target): target is string => typeof target === "string" && validBuildTarget(target))) {
    return false;
  }
  const canonical = [...new Set(targets)].sort((left, right) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  return targets.length === canonical.length && targets.every((target, index) => target === canonical[index]);
}

test("Rust project binding decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("project-binding-cases.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expected, label, json] = line.split("\t", 3);
    expect(validProjectBindingContract(json, "/fixture/project"), label).toBe(expected === "true");
  }
});

const attestationRootFields = new Set([
  "artifactCount",
  "artifactPolicy",
  "artifactTreeHash",
  "dependencyTreeHash",
  "identity",
  "imageId",
  "provider",
  "providerId",
  "schemaVersion",
  "sealedAt",
  "status",
]);
const imageIdentityFields = new Set([
  "buildRelevantConfigHash",
  "canonicalManifestHash",
  "leanCompilerGithash",
  "leanToolchain",
  "mathlibRevision",
  "packageSourceTreeHash",
  "schemaVersion",
  "targetPlatform",
]);
const attestationProviderFields = new Set(["overridesSha256", "registrySha256"]);
const artifactPolicyFields = new Set(["missingRoots"]);
const lowercaseGitRevision = /^[0-9a-f]{40}$/;

function exactFields(value: Record<string, unknown>, fields: Set<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.size && keys.every((field) => fields.has(field));
}

function validImageAttestationContract(text: string, requestedImageId: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!record(value) || !exactFields(value, attestationRootFields)) return false;
  if (value.schemaVersion !== 1 || value.status !== "sealed" || value.imageId !== requestedImageId) {
    return false;
  }
  if (!boundedString(value.providerId) || value.providerId.length === 0 || /[\u0000-\u001f\u007f-\u009f]/u.test(value.providerId)) {
    return false;
  }
  if (!record(value.identity) || !exactFields(value.identity, imageIdentityFields)) return false;
  const identity = value.identity;
  if (identity.schemaVersion !== 1) return false;
  if (!boundedString(identity.leanToolchain) || identity.leanToolchain.length === 0) return false;
  if (!boundedString(identity.targetPlatform) || identity.targetPlatform.length === 0) return false;
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(identity.leanToolchain) || /[\u0000-\u001f\u007f-\u009f]/u.test(identity.targetPlatform)) {
    return false;
  }
  if (typeof identity.leanCompilerGithash !== "string" || !lowercaseGitRevision.test(identity.leanCompilerGithash)) return false;
  if (typeof identity.mathlibRevision !== "string" || !lowercaseGitRevision.test(identity.mathlibRevision)) return false;
  for (const field of ["canonicalManifestHash", "packageSourceTreeHash", "buildRelevantConfigHash"] as const) {
    if (typeof identity[field] !== "string" || !lowercaseSha256.test(identity[field])) return false;
  }
  const derived = imageId({
    schemaVersion: 1,
    leanToolchain: identity.leanToolchain,
    leanCompilerGithash: identity.leanCompilerGithash,
    mathlibRevision: identity.mathlibRevision,
    canonicalManifestHash: identity.canonicalManifestHash,
    packageSourceTreeHash: identity.packageSourceTreeHash,
    buildRelevantConfigHash: identity.buildRelevantConfigHash,
    targetPlatform: identity.targetPlatform,
  });
  if (derived !== requestedImageId) return false;

  if (!record(value.provider) || !exactFields(value.provider, attestationProviderFields)) return false;
  if (typeof value.provider.registrySha256 !== "string" || !lowercaseSha256.test(value.provider.registrySha256)) return false;
  if (typeof value.provider.overridesSha256 !== "string" || !lowercaseSha256.test(value.provider.overridesSha256)) return false;
  if (value.provider.registrySha256 !== identity.canonicalManifestHash) return false;
  for (const field of ["dependencyTreeHash", "artifactTreeHash"] as const) {
    if (typeof value[field] !== "string" || !lowercaseSha256.test(value[field])) return false;
  }
  if (!Number.isSafeInteger(value.artifactCount) || (value.artifactCount as number) < 0) return false;
  if (!record(value.artifactPolicy) || !exactFields(value.artifactPolicy, artifactPolicyFields)) return false;
  if (!Array.isArray(value.artifactPolicy.missingRoots) || value.artifactPolicy.missingRoots.length > 4096) return false;
  const roots = value.artifactPolicy.missingRoots;
  if (!roots.every((root): root is string => boundedString(root) && root.length > 0 && !/[\u0000-\u001f\u007f-\u009f]/u.test(root))) {
    return false;
  }
  const canonicalRoots = [...new Set(roots)].sort((left, right) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (roots.length !== canonicalRoots.length || !roots.every((root, index) => root === canonicalRoots[index])) return false;
  return validCanonicalTimestamp(value.sealedAt);
}

test("Rust image attestation decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("image-attestation-cases.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  for (const line of lines) {
    const [expected, label, requested, json] = line.split("\t", 4);
    expect(validImageAttestationContract(json, requested), label).toBe(expected === "true");
  }
});

const executionRecordFields = new Set([
  "attestationSha256", "bindingSha256", "buildLockKey", "coordinatorPid",
  "dependencyArtifactBefore", "executionId", "finishedAt", "imageId", "outcome",
  "profileSha256", "projectId", "projectPath", "projectProtectedBefore",
  "projectProtectedRecordCount", "recordType", "reusePolicySha256", "schemaVersion",
  "startedAt", "status", "target",
]);
const executionOutcomeFields = new Set([
  "attestationStable", "bindingStable", "buildExecution", "dependencyArtifactAfter",
  "dependencyArtifactCount", "failureMessage", "failureStage", "inspectionStable",
  "lakeExitCode", "processGroupId", "processGroupReaped", "projectProtectedRecordsStable",
  "reuseEvidence", "reusedFromExecutionId", "terminationEscalated", "terminationReason",
  "triggerSignal",
]);
const executionIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function validSafeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function validStrictReuseTree(value: unknown, schema: string): boolean {
  if (!record(value) || !exactFields(value, new Set(["byteCount", "entryCount", "fileCount", "schema", "treeHash"]))) return false;
  return value.schema === schema && typeof value.treeHash === "string" && lowercaseSha256.test(value.treeHash) &&
    validSafeCount(value.entryCount) && validSafeCount(value.fileCount) && validSafeCount(value.byteCount) &&
    value.fileCount <= value.entryCount;
}

function validStrictReuseEvidence(value: unknown): boolean {
  return record(value) && exactFields(value, new Set(["projectInput", "projectOutput", "schemaVersion"])) &&
    value.schemaVersion === 1 &&
    validStrictReuseTree(value.projectInput, "leanbun-project-input-tree-v1") &&
    validStrictReuseTree(value.projectOutput, "leanbun-project-output-tree-v1");
}

function validStrictExecutionOutcome(value: unknown, status: "completed" | "failed" | "reused"): boolean {
  if (!record(value) || Object.keys(value).some((field) => !executionOutcomeFields.has(field))) return false;
  if (value.buildExecution !== status) return false;
  if (value.lakeExitCode !== undefined && (!Number.isSafeInteger(value.lakeExitCode))) return false;
  for (const field of ["projectProtectedRecordsStable", "bindingStable", "attestationStable", "inspectionStable", "terminationEscalated", "processGroupReaped"] as const) {
    if (value[field] !== undefined && typeof value[field] !== "boolean") return false;
  }
  if (value.dependencyArtifactAfter !== undefined && (typeof value.dependencyArtifactAfter !== "string" || !lowercaseSha256.test(value.dependencyArtifactAfter))) return false;
  if (value.dependencyArtifactCount !== undefined && !validSafeCount(value.dependencyArtifactCount)) return false;
  if (value.terminationReason !== undefined && !["exit", "timeout", "signal"].includes(String(value.terminationReason))) return false;
  if (value.triggerSignal !== undefined && !["SIGINT", "SIGTERM", "ABORT"].includes(String(value.triggerSignal))) return false;
  if ((value.triggerSignal !== undefined) !== (value.terminationReason === "signal")) return false;
  if (value.processGroupId !== undefined && (!Number.isSafeInteger(value.processGroupId) || (value.processGroupId as number) <= 0)) return false;
  if (value.failureStage !== undefined && !["sandbox-execution", "post-build-verification", "reuse-verification", "recovery", "internal"].includes(String(value.failureStage))) return false;
  if (value.failureMessage !== undefined && (typeof value.failureMessage !== "string" || value.failureMessage.length > 1024)) return false;
  if (status === "failed" && value.failureStage === undefined) return false;
  if (status !== "failed" && (value.failureStage !== undefined || value.failureMessage !== undefined)) return false;
  if (value.reuseEvidence !== undefined && !validStrictReuseEvidence(value.reuseEvidence)) return false;
  if (status === "reused") {
    if (!validStrictReuseEvidence(value.reuseEvidence) || typeof value.reusedFromExecutionId !== "string" || !executionIdPattern.test(value.reusedFromExecutionId)) return false;
    if ([value.lakeExitCode, value.terminationReason, value.triggerSignal, value.processGroupId, value.terminationEscalated, value.processGroupReaped].some((item) => item !== undefined)) return false;
  } else if (value.reusedFromExecutionId !== undefined) return false;
  return true;
}

function canonicalAbsolutePath(value: unknown): value is string {
  if (typeof value !== "string" || !isAbsolute(value) || Buffer.byteLength(value) > 4096) return false;
  if (value === "/") return true;
  if (value !== "/" && (value.endsWith("/") || value.includes("//"))) return false;
  return !/[\u0000-\u001f\u007f-\u009f]/u.test(value) &&
    value.split("/").slice(1).every((part) => part.length > 0 && part !== "." && part !== "..");
}

function validExecutionRecordContract(text: string, requestedExecutionId: string): boolean {
  let value: unknown;
  try { value = JSON.parse(text); } catch { return false; }
  if (!record(value) || Object.keys(value).some((field) => !executionRecordFields.has(field))) return false;
  if (value.schemaVersion !== 1 || value.recordType !== "controlled-build-execution") return false;
  if (value.executionId !== requestedExecutionId || !executionIdPattern.test(requestedExecutionId)) return false;
  if (!canonicalAbsolutePath(value.projectPath) || value.projectId !== projectId(value.projectPath)) return false;
  if (typeof value.target !== "string" || !validBuildTarget(value.target)) return false;
  for (const field of ["imageId", "bindingSha256", "attestationSha256", "dependencyArtifactBefore"] as const) {
    if (typeof value[field] !== "string" || !lowercaseSha256.test(value[field])) return false;
  }
  const profile = value.profileSha256;
  const reuse = value.reusePolicySha256;
  if ((profile === undefined) === (reuse === undefined)) return false;
  if (profile !== undefined && (typeof profile !== "string" || !lowercaseSha256.test(profile))) return false;
  if (reuse !== undefined && (typeof reuse !== "string" || !lowercaseSha256.test(reuse))) return false;
  if (value.buildLockKey !== undefined && (typeof value.buildLockKey !== "string" || !lowercaseSha256.test(value.buildLockKey))) return false;
  const recovery = [value.coordinatorPid, value.projectProtectedBefore, value.projectProtectedRecordCount];
  const present = recovery.filter((item) => item !== undefined).length;
  if (present !== 0 && (present !== 3 || !Number.isSafeInteger(value.coordinatorPid) || (value.coordinatorPid as number) <= 0 || typeof value.projectProtectedBefore !== "string" || !lowercaseSha256.test(value.projectProtectedBefore) || !validSafeCount(value.projectProtectedRecordCount))) return false;
  if (!validCanonicalTimestamp(value.startedAt)) return false;
  if (value.status === "running") return value.finishedAt === null && value.outcome === null;
  if (value.status !== "completed" && value.status !== "failed" && value.status !== "reused") return false;
  if (value.status === "completed" && profile === undefined) return false;
  if (value.status === "reused" && reuse === undefined) return false;
  if (!validCanonicalTimestamp(value.finishedAt) || value.finishedAt < value.startedAt) return false;
  return validStrictExecutionOutcome(value.outcome, value.status);
}

test("Rust execution record decoder matches the Bun contract oracle", async () => {
  const lines = (await readFile(new URL("execution-record-cases.tsv", goldenRoot), "utf8"))
    .trimEnd().split("\n");
  for (const line of lines) {
    const [expected, label, requested, json] = line.split("\t", 4);
    expect(validExecutionRecordContract(json, requested), label).toBe(expected === "true");
  }
});

const buildLockFields = new Set([
  "acquiredAt", "coordinatorPid", "executionId", "imageId", "key", "projectId",
  "projectPath", "recordType", "schemaVersion", "target",
]);

function strictBuildLockKey(project: string, image: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(JSON.stringify({
    schema: "leanbun-build-lock-v1",
    projectId: project,
    imageId: image,
  }));
  return hasher.digest("hex");
}

function validBuildLockContract(text: string, requestedKey: string): boolean {
  let value: unknown;
  try { value = JSON.parse(text); } catch { return false; }
  if (!record(value) || !exactFields(value, buildLockFields)) return false;
  if (value.schemaVersion !== 1 || value.recordType !== "build-execution-lock") return false;
  if (typeof value.key !== "string" || !lowercaseSha256.test(value.key) || value.key !== requestedKey) return false;
  if (typeof value.executionId !== "string" || !executionIdPattern.test(value.executionId)) return false;
  if (!canonicalAbsolutePath(value.projectPath) || value.projectId !== projectId(value.projectPath)) return false;
  if (typeof value.imageId !== "string" || !lowercaseSha256.test(value.imageId)) return false;
  if (value.key !== strictBuildLockKey(value.projectId, value.imageId)) return false;
  if (typeof value.target !== "string" || !validBuildTarget(value.target)) return false;
  if (!Number.isSafeInteger(value.coordinatorPid) || (value.coordinatorPid as number) <= 0) return false;
  return validCanonicalTimestamp(value.acquiredAt);
}

test("Rust build lock decoder matches the strict Bun contract oracle", async () => {
  const lines = (await readFile(new URL("build-lock-cases.tsv", goldenRoot), "utf8"))
    .trimEnd().split("\n");
  for (const line of lines) {
    const [expected, label, requested, json] = line.split("\t", 4);
    expect(validBuildLockContract(json, requested), label).toBe(expected === "true");
  }
});

test("Rust build lock transitions match the Bun ownership oracle", async () => {
  const lines = (await readFile(new URL("build-lock-transition-cases.tsv", goldenRoot), "utf8"))
    .trimEnd().split("\n");
  for (const line of lines) {
    const [expected, label, operation, observedExecution, requestedExecution] = line.split("\t");
    let actual: string;
    if (operation === "acquire") {
      actual = observedExecution === "absent" ? "publish-new" : "busy";
    } else if (observedExecution === "absent") {
      actual = "already-released";
    } else {
      actual = observedExecution === requestedExecution ? "remove-owned" : "conflict";
    }
    expect(actual, label).toBe(expected);
  }
});

test("Rust package drift classification matches the Bun external evidence oracle", async () => {
  const lines = (await readFile(new URL("package-drift-cases.tsv", goldenRoot), "utf8"))
    .trimEnd().split("\n");
  for (const line of lines) {
    const [expected, label, checkout, manifestRevision, providerRevision, overrideMatches, path, actualRevision, dirty] = line.split("\t");
    const findings: string[] = [];
    if (manifestRevision !== providerRevision) findings.push("revision-mismatch");
    if (overrideMatches !== "true") findings.push("override-mismatch");
    if (checkout === "unobserved") findings.push("unobserved");
    if (checkout === "missing") findings.push("missing");
    if (checkout === "present") {
      if (actualRevision !== manifestRevision) findings.push("revision-mismatch");
      if (dirty === "true") findings.push("dirty");
      if (path !== "match") findings.push("path-mismatch");
    }
    const order = new Map([
      ["missing", 0], ["revision-mismatch", 1], ["dirty", 2], ["path-mismatch", 3],
      ["override-mismatch", 4], ["unobserved", 5], ["matched", 6],
    ]);
    findings.sort((left, right) => order.get(left)! - order.get(right)!);
    expect(findings.length === 0 ? "matched" : findings.join(","), label).toBe(expected);
  }
});

test("Rust Lake update plans match the non-executing Bun plan oracle", async () => {
  const lines = (await readFile(new URL("lake-update-plan-cases.tsv", goldenRoot), "utf8"))
    .trimEnd().split("\n");
  const csv = (value: string): string[] => value === "<empty>" ? [] : value.split(",");
  const validSelector = (value: string): boolean =>
    value.length > 0 && Buffer.byteLength(value) <= 256 && !value.startsWith("-") &&
    !/[\s/\\\u0000-\u001f\u007f]/u.test(value);
  for (const line of lines) {
    const [expected, label, version, requestedText, inventoryText, gitText, expectedArguments] = line.split("\t");
    const requested = csv(requestedText);
    const inventory = new Set(csv(inventoryText));
    const git = new Set(csv(gitText));
    const selected = new Set(requested);
    const accepted = version === "5.0.0-src+8c9756b" && requested.length > 0 &&
      selected.size === requested.length && requested.every((name) =>
        validSelector(name) && inventory.has(name) && git.has(name));
    expect(accepted, label).toBe(expected === "true");
    if (accepted) {
      const args = ["--keep-toolchain", "update", ...[...selected].sort()];
      expect(args.join(","), label).toBe(expectedArguments);
    }
  }
});

test("Lake update contract facts cover the Rust plan effects and fixed risks", async () => {
  const sourceLines = (await readFile(
    new URL("lake-update-contract-sources-v1.tsv", configRoot),
    "utf8",
  )).trimEnd().split("\n");
  const sourceIds = new Set<string>();
  for (const line of sourceLines) {
    const [id, kind, path, sha256, extra] = line.split("\t");
    expect(extra, line).toBeUndefined();
    expect(/^[a-z0-9-]+$/.test(id), line).toBeTrue();
    expect(sourceIds.has(id), line).toBeFalse();
    sourceIds.add(id);
    expect(["lean-source", "html-reference"].includes(kind), line).toBeTrue();
    expect(path.startsWith("/") || path.split("/").some((part) => ["", ".", ".."].includes(part)), line).toBeFalse();
    expect(/^[0-9a-f]{64}$/.test(sha256), line).toBeTrue();
  }

  const factLines = (await readFile(
    new URL("lake-update-contract-v1.tsv", configRoot),
    "utf8",
  )).trimEnd().split("\n");
  const factIds = new Set<string>();
  const requirements = new Set<string>();
  const effects = new Set<string>();
  const risks = new Set<string>();
  const mitigations = new Set<string>();
  for (const line of factLines) {
    const fields = line.split("\t");
    expect(fields.length, line).toBe(8);
    const [id, source, startText, endText, requirement, effect, risk, mitigation] = fields;
    expect(/^[a-z0-9-]+$/.test(id), line).toBeTrue();
    expect(factIds.has(id), line).toBeFalse();
    factIds.add(id);
    expect(sourceIds.has(source), line).toBeTrue();
    const start = Number(startText);
    const end = Number(endText);
    expect(Number.isSafeInteger(start) && start > 0 && Number.isSafeInteger(end) && end >= start, line).toBeTrue();
    if (requirement !== "none") requirements.add(requirement);
    if (effect !== "none") effects.add(effect);
    if (risk !== "none") risks.add(risk);
    if (mitigation !== "none") mitigations.add(mitigation);
  }

  expect([...requirements].sort()).toEqual([
    "canonical-update-command", "explicit-packages", "keep-toolchain",
  ]);
  expect([...effects].sort()).toEqual([
    "CreateOrModifyLakeDirectory", "CreateOrModifyPackageCheckouts",
    "ExecutePostUpdateHooks", "FetchRemotePackageContent",
    "LoadAndExecuteProjectConfiguration", "ReadPackageOverrides", "RewriteManifest",
  ].sort());
  expect([...risks].sort()).toEqual([
    "CheckoutMutation", "LakeInternalStateMutation", "ManifestRewrite",
    "NetworkAndRemoteContent", "PostUpdateHookExecution",
    "UntrustedProjectConfigurationExecution",
  ].sort());
  expect([...mitigations].sort()).toEqual([
    "include-keep-toolchain", "reject-bare-update",
    "require-explicit-packages", "use-canonical-update-command",
  ]);
  expect([...sourceIds].every((source) =>
    factLines.some((line) => line.split("\t")[1] === source)
  )).toBeTrue();
});

test("Rust Lake command plan report matches canonical JSON.stringify", async () => {
  const expected = (await readFile(
    new URL("lake-command-plan-report.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const value: unknown = JSON.parse(expected);
  expect(JSON.stringify(value)).toBe(expected);
  expect(record(value)).toBeTrue();
  if (!record(value)) return;
  expect(value.schemaVersion).toBe(1);
  expect(value.reportType).toBe("lake-command-plan");
  expect(value.inventorySnapshotSha256).toBe(
    "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
  );
  expect(value.executableSha256).toBe(
    "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
  );
  expect(value.executableByteLength).toBe(7);
  expect(value.executableUnixMode).toBe(493);
  expect(value.executableRegularFile).toBeTrue();
  expect(value.executableSymlinkFree).toBeTrue();
  expect(value.arguments).toEqual(["--keep-toolchain", "update", "mathlib"]);
  expect(value.environmentKeys).toEqual([
    "ELAN_HOME", "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT", "HOME", "PATH",
  ]);
  expect(value.executionAuthority).toBe("withheld");
  expect(Array.isArray(value.expectedEffects) && value.expectedEffects.length).toBe(7);
  expect(Array.isArray(value.risks) && value.risks.length).toBe(8);
  expect(value.mitigations).toEqual([
    "require-explicit-packages", "reject-bare-update",
    "use-canonical-update-command", "include-keep-toolchain",
  ]);
  expect(record(value.contract) && Array.isArray(value.contract.sources) && value.contract.sources.length).toBe(6);
});

test("Rust package inventory snapshot digest matches the Bun canonical oracle", async () => {
  const expected = (await readFile(
    new URL("package-inventory-snapshot.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const value: unknown = JSON.parse(expected);
  expect(JSON.stringify(value)).toBe(expected);
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(expected);
  expect(hasher.digest("hex")).toBe(
    "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
  );
  expect(record(value)).toBeTrue();
  if (!record(value)) return;
  expect(value.driftSummary).toBe("unobserved");
  expect(Array.isArray(value.packages) && value.packages.length).toBe(1);
  const changed = structuredClone(value);
  if (record(changed) && Array.isArray(changed.packages) && record(changed.packages[0])) {
    changed.packages[0].checkout = { state: "missing" };
    changed.packages[0].findings = [
      { kind: "missing", field: "checkout", expected: null, observed: null },
    ];
    changed.driftSummary = "drifted";
  }
  const changedHasher = new Bun.CryptoHasher("sha256");
  changedHasher.update(JSON.stringify(changed));
  expect(changedHasher.digest("hex")).not.toBe(
    "56207c2c37c4fc3085597c426c050a3c6202c2e81a2d9dc40ee8f762147389e2",
  );
});

test("Rust Lake approval request identity matches the pending Bun oracle", async () => {
  const report = (await readFile(
    new URL("lake-command-plan-report.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const expected = (await readFile(
    new URL("lake-command-approval-request.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const value: unknown = JSON.parse(expected);
  expect(JSON.stringify(value)).toBe(expected);
  expect(record(value)).toBeTrue();
  if (!record(value)) return;

  const sha256 = (input: string | Buffer): string => {
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(input);
    return hasher.digest("hex");
  };
  const planReportSha256 = sha256(report);
  const projectIdDigest = sha256(Buffer.concat([
    Buffer.from("leanbun-project-v1\0", "utf8"),
    Buffer.from(String(value.projectPath), "utf8"),
  ]));
  const identity = {
    schema: "leanbun-lake-command-approval-request-v1",
    planReportSha256,
    projectId: projectIdDigest,
    nonce: value.nonce,
    issuedAtUnixMs: value.issuedAtUnixMs,
    expiresAtUnixMs: value.expiresAtUnixMs,
  };
  expect(value.requestId).toBe(sha256(JSON.stringify(identity)));
  expect(value.planReportSha256).toBe(planReportSha256);
  const reportValue: unknown = JSON.parse(report);
  expect(record(reportValue)).toBeTrue();
  if (record(reportValue)) {
    expect(value.inventorySnapshotSha256).toBe(reportValue.inventorySnapshotSha256);
  }
  expect(value.projectId).toBe(projectIdDigest);
  expect(value.approvalState).toBe("pending");
  expect(value.executionAuthority).toBe("withheld");
  expect(value.packages).toEqual(["mathlib"]);
  expect(value.networkRequired).toBeTrue();
  expect(Number.isSafeInteger(value.issuedAtUnixMs)).toBeTrue();
  expect(Number.isSafeInteger(value.expiresAtUnixMs)).toBeTrue();
  expect(Number(value.expiresAtUnixMs) - Number(value.issuedAtUnixMs)).toBeLessThanOrEqual(900_000);
});

test("Rust Lake command preflight remains ready only for explicit approval", async () => {
  const expected = (await readFile(
    new URL("lake-command-preflight.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const approvalText = (await readFile(
    new URL("lake-command-approval-request.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const reportText = (await readFile(
    new URL("lake-command-plan-report.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const value: unknown = JSON.parse(expected);
  const approval: unknown = JSON.parse(approvalText);
  const report: unknown = JSON.parse(reportText);
  expect(JSON.stringify(value)).toBe(expected);
  expect(record(value) && record(approval) && record(report)).toBeTrue();
  if (!record(value) || !record(approval) || !record(report)) return;
  expect(value.decision).toBe("ready-for-explicit-approval");
  expect(value.executionAuthority).toBe("withheld");
  expect(value.requestId).toBe(approval.requestId);
  expect(value.planReportSha256).toBe(approval.planReportSha256);
  expect(value.inventorySnapshotSha256).toBe(report.inventorySnapshotSha256);
  expect(value.executableSha256).toBe(report.executableSha256);
  expect(Number(value.observedAtUnixMs)).toBe(1_800_000_299_000);
});

test("Rust external Lake grant remains a structural claim in the Bun oracle", async () => {
  const expected = (await readFile(
    new URL("lake-command-approval-grant.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const preflightText = (await readFile(
    new URL("lake-command-preflight.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const requestText = (await readFile(
    new URL("lake-command-approval-request.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const value: unknown = JSON.parse(expected);
  const preflight: unknown = JSON.parse(preflightText);
  const request: unknown = JSON.parse(requestText);
  expect(JSON.stringify(value)).toBe(expected);
  expect(record(value) && record(preflight) && record(request)).toBeTrue();
  if (!record(value) || !record(preflight) || !record(request)) return;
  expect(new Set(Object.keys(value))).toEqual(new Set([
    "schemaVersion", "grantType", "grantId", "requestId", "preflightSha256",
    "principal", "approvalMethod", "confirmation", "grantedAtUnixMs",
    "expiresAtUnixMs", "scope", "requestedAuthority",
  ]));
  const preflightHasher = new Bun.CryptoHasher("sha256");
  preflightHasher.update(preflightText);
  const preflightSha256 = preflightHasher.digest("hex");
  expect(value.requestId).toBe(request.requestId);
  expect(value.requestId).toBe(preflight.requestId);
  expect(value.preflightSha256).toBe(preflightSha256);
  expect(value.confirmation).toBe(`approve:${value.requestId}:${preflightSha256}`);
  const identity = {
    schema: "leanbun-lake-command-approval-grant-v1",
    requestId: value.requestId,
    preflightSha256,
    principal: value.principal,
    approvalMethod: "explicit-request-id-confirmation",
    confirmation: value.confirmation,
    grantedAtUnixMs: value.grantedAtUnixMs,
    expiresAtUnixMs: value.expiresAtUnixMs,
    scope: "single-lake-command",
    requestedAuthority: "single-use-execution",
  };
  const grantHasher = new Bun.CryptoHasher("sha256");
  grantHasher.update(JSON.stringify(identity));
  expect(value.grantId).toBe(grantHasher.digest("hex"));
  expect(Number(value.expiresAtUnixMs) - Number(value.grantedAtUnixMs)).toBeLessThanOrEqual(300_000);
  expect(value.executionAuthority).toBeUndefined();
});

test("Rust trusted approval challenge requires the macOS adapter boundary", async () => {
  const challengeText = (await readFile(
    new URL("lake-command-trusted-approval-challenge.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const contractText = (await readFile(
    new URL("trusted-approval-ingress-contract.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const preflightText = (await readFile(
    new URL("lake-command-preflight.json", goldenRoot),
    "utf8",
  )).trimEnd();
  const challenge: unknown = JSON.parse(challengeText);
  const contract: unknown = JSON.parse(contractText);
  const preflight: unknown = JSON.parse(preflightText);
  expect(JSON.stringify(challenge)).toBe(challengeText);
  expect(JSON.stringify(contract)).toBe(contractText);
  expect(record(challenge) && record(contract) && record(preflight)).toBeTrue();
  if (!record(challenge) || !record(contract) || !record(preflight)) return;

  const preflightHasher = new Bun.CryptoHasher("sha256");
  preflightHasher.update(preflightText);
  const preflightSha256 = preflightHasher.digest("hex");
  expect(challenge.preflightSha256).toBe(preflightSha256);
  const identity = {
    schema: "leanbun-trusted-approval-challenge-v1",
    requestId: challenge.requestId,
    preflightSha256,
    sessionNonceSha256: challenge.sessionNonceSha256,
    issuedAtUnixMs: challenge.issuedAtUnixMs,
    expiresAtUnixMs: challenge.expiresAtUnixMs,
  };
  const challengeHasher = new Bun.CryptoHasher("sha256");
  challengeHasher.update(JSON.stringify(identity));
  const challengeId = challengeHasher.digest("hex");
  expect(challenge.challengeId).toBe(challengeId);
  expect(challenge.confirmation).toBe(
    `approve:${challenge.requestId}:${preflightSha256}:${challengeId}`,
  );
  expect(Number(challenge.expiresAtUnixMs) - Number(challenge.issuedAtUnixMs))
    .toBeLessThanOrEqual(60_000);
  expect(challenge.executionAuthority).toBe("withheld");

  expect(contract.decision).toBe("requires-dedicated-macos-adapter");
  expect(contract.adapterBoundary).toBe("leanbun-approval-macos");
  expect(contract.requirements).toContain("terminal-owned-by-effective-user");
  expect(contract.requirements).toContain("current-process-in-foreground-group");
  expect(contract.requirements).toContain("atomic-single-use-consumption");
  expect(contract.forbiddenSources).toContain("external-json-claim");
  expect(contract.forbiddenSources).toContain("environment-variable");
  expect(contract.forbiddenSources).toContain("pipe-or-redirected-stdin");
  expect(contract.executionAuthority).toBe("withheld");
});

test("Rust macOS approval adapter keeps terminal input byte-bounded", async () => {
  const workspace = await readFile(new URL("Cargo.toml", rustRoot), "utf8");
  const aclSysManifest = await readFile(
    new URL("crates/leanbun-macos-acl-sys/Cargo.toml", rustRoot),
    "utf8",
  );
  const aclSysSource = await readFile(
    new URL("crates/leanbun-macos-acl-sys/src/lib.rs", rustRoot),
    "utf8",
  );
  const manifest = await readFile(
    new URL("crates/leanbun-approval-macos/Cargo.toml", rustRoot),
    "utf8",
  );
  const source = await readFile(
    new URL("crates/leanbun-approval-macos/src/lib.rs", rustRoot),
    "utf8",
  );
  const aclBoundarySource = await readFile(
    new URL("crates/leanbun-approval-macos/src/acl_boundary.rs", rustRoot),
    "utf8",
  );
  const presentationSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/presentation.rs", rustRoot),
    "utf8",
  );
  const replaySource = await readFile(
    new URL("crates/leanbun-approval-macos/src/replay.rs", rustRoot),
    "utf8",
  );
  const proofSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/proof.rs", rustRoot),
    "utf8",
  );
  const executableSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/executable.rs", rustRoot),
    "utf8",
  );
  const freshPlanSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/fresh_plan.rs", rustRoot),
    "utf8",
  );
  const candidateSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/candidate.rs", rustRoot),
    "utf8",
  );
  const executionGrantSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/execution_grant.rs", rustRoot),
    "utf8",
  );
  const launchIntentSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/launch_intent.rs", rustRoot),
    "utf8",
  );
  const launchReservationSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/launch_reservation.rs", rustRoot),
    "utf8",
  );
  const launchPolicySource = await readFile(
    new URL("crates/leanbun-approval-macos/src/launch_policy.rs", rustRoot),
    "utf8",
  );
  const spawnBoundarySource = await readFile(
    new URL("crates/leanbun-approval-macos/src/spawn_boundary.rs", rustRoot),
    "utf8",
  );
  const pathProvenanceSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/path_provenance.rs", rustRoot),
    "utf8",
  );
  const pathEligibilitySource = await readFile(
    new URL("crates/leanbun-approval-macos/src/path_eligibility.rs", rustRoot),
    "utf8",
  );
  const deploymentContractSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/deployment_contract.rs", rustRoot),
    "utf8",
  );
  const coordinatorContractSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/coordinator_contract.rs", rustRoot),
    "utf8",
  );
  const coordinatorRequestSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/coordinator_request.rs", rustRoot),
    "utf8",
  );
  const coordinatorWireSource = await readFile(
    new URL("crates/leanbun-approval-macos/src/coordinator_wire.rs", rustRoot),
    "utf8",
  );
  expect(workspace).toContain('"crates/leanbun-approval-macos"');
  expect(workspace).toContain('"crates/leanbun-macos-acl-sys"');
  expect(aclSysManifest).toContain('name = "leanbun-macos-acl-sys"');
  expect(aclSysManifest).toContain('unsafe_op_in_unsafe_fn = "deny"');
  expect(manifest).toContain('name = "leanbun-approval-macos"');
  expect(manifest).toContain('rustix = { version = "=1.1.4"');
  expect(manifest).toContain('features = ["std", "fs", "process", "termios"]');
  expect(manifest).toContain('getrandom = { version = "=0.4.3"');
  expect(manifest).toContain('leanbun-evidence = { path = "../leanbun-evidence" }');
  expect(manifest).toContain('leanbun-macos-acl-sys = { path = "../leanbun-macos-acl-sys" }');
  expect(manifest).toContain(
    'leanbun-inventory-legacy = { path = "../leanbun-inventory-legacy" }',
  );
  expect(source).toContain("#![forbid(unsafe_code)]");
  expect(source).toContain("io::stdin().is_terminal()");
  expect(source).toContain("io::stderr().is_terminal()");
  expect(source).toContain("/dev/fd/0");
  expect(source).toContain("/dev/fd/2");
  expect(source).toContain("PlatformProofV1::Unverified");
  expect(source).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(source).toContain("rustix::process::geteuid()");
  expect(source).toContain("rustix::process::getpgrp()");
  expect(source).toContain("rustix::process::getsid(None)");
  expect(source).toContain("rustix::termios::tcgetpgrp(&stdin)");
  expect(source).toContain("rustix::termios::tcgetsid(&stdin)");
  expect(presentationSource).toContain("getrandom::fill(&mut nonce)");
  expect(presentationSource).toContain("observe_current_process_terminal_v1()");
  expect(presentationSource).toContain("io::stderr().lock()");
  expect(presentationSource).toContain("stdin.read(&mut buffer[used..])");
  expect(presentationSource).toContain("expected.len() + 2");
  expect(presentationSource).toContain("rustix::io::ioctl_fionread(&stdin)");
  expect(presentationSource).toContain("ExactTerminalResponseClaim");
  expect(presentationSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(replaySource).toContain("OFlags::CREATE");
  expect(replaySource).toContain("OFlags::EXCL");
  expect(replaySource).toContain("OFlags::NOFOLLOW");
  expect(replaySource).toContain("Mode::RWXU");
  expect(replaySource).toContain("rustix::fs::fsync(&self.root)");
  expect(replaySource).toContain("AlreadyConsumed");
  expect(replaySource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(proofSource).toContain("reverify_consumed_lake_command_approval_v1");
  expect(proofSource).toContain("fresh: TrustedFreshLakeUpdatePlanV1");
  expect(proofSource).toContain("lake_command_preflight_v1(");
  expect(proofSource).toContain("FreshFactsReverified");
  expect(proofSource).toContain("executable_observed_at_unix_ms < consumption.consumed_at_unix_ms");
  expect(proofSource).toContain("verified_at_unix_ms >= consumption.challenge_expires_at_unix_ms");
  expect(proofSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(executableSource).toContain("observe_reviewed_lake_executable_v1");
  expect(executableSource).toContain('rustix::fs::openat(\n        &root,\n        "bin"');
  expect(executableSource).toContain('rustix::fs::openat(\n        &bin,\n        "lake"');
  expect(executableSource).toContain("MAX_LAKE_EXECUTABLE_BYTES");
  expect(executableSource).toContain("hasher.update(&chunk[..count])");
  expect(executableSource).toContain("identity(&lake_before) != identity(&lake_after)");
  expect(executableSource).toContain("verify_lake_update_plan_contract_v1(reviewed_plan)");
  expect(freshPlanSource).toContain("derive_trusted_fresh_lake_update_plan_v1");
  expect(freshPlanSource).toContain("read_provider_pair(");
  expect(freshPlanSource).toContain("read_project_input(");
  expect(freshPlanSource).toContain("build_package_inventory(&project, provider.as_ref(), &[])");
  expect(freshPlanSource).toContain("report_dependency_drift(&inventory)");
  expect(freshPlanSource).toContain("packages: &request.packages");
  expect(freshPlanSource).toContain("TrustedFreshLakeUpdatePlanV1");
  expect(candidateSource).toContain("seal_trusted_lake_execution_candidate_v1");
  expect(candidateSource).toContain("reverify_fresh_bundle_v1(consumption, request, fresh)");
  expect(candidateSource).toContain("ExactPlanAndProofSealed");
  expect(candidateSource).toContain("plan: LakeCommandPlanV1");
  expect(candidateSource).toContain("proof: LakeCommandTrustedApprovalProofV1");
  expect(candidateSource).toContain("expires_at_unix_ms");
  expect(candidateSource).toContain("leanbun-lake-execution-candidate-v1");
  expect(candidateSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(executionGrantSource).toContain("grant_trusted_lake_execution_once_v1");
  expect(executionGrantSource).toContain("grant_at_v1(candidate, current_unix_ms()?)");
  expect(executionGrantSource).toContain("lake_command_plan_report_v1(&candidate.plan)");
  expect(executionGrantSource).toContain("candidate.candidate_sha256\n            != candidate_sha256");
  expect(executionGrantSource).toContain("granted_at_unix_ms < candidate.proof.verified_at_unix_ms");
  expect(executionGrantSource).toContain("granted_at_unix_ms >= candidate.expires_at_unix_ms");
  expect(executionGrantSource).toContain("TrustedLakeExecutionAuthorityV1::GrantedOnce");
  expect(executionGrantSource).toContain("leanbun-trusted-lake-execution-grant-v1");
  expect(executionGrantSource).not.toContain(
    "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct TrustedLakeExecutionGrantV1",
  );
  expect(launchIntentSource).toContain("prepare_trusted_lake_launch_intent_v1");
  expect(launchIntentSource).toContain("observe_reviewed_lake_executable_v1");
  expect(launchIntentSource).toContain("grant.grant_sha256 != grant_sha256");
  expect(launchIntentSource).toContain("canonicalize_contained_directory(root, candidate)");
  expect(launchIntentSource).toContain("metadata.uid() != rustix::process::geteuid().as_raw()");
  expect(launchIntentSource).toContain("metadata.mode() & 0o022 != 0");
  expect(launchIntentSource).toContain('environment_entry("GIT_CONFIG_NOSYSTEM", "1".to_owned())');
  expect(launchIntentSource).toContain('environment_entry("GIT_TERMINAL_PROMPT", "0".to_owned())');
  expect(launchIntentSource).toContain("prepared_at_unix_ms >= grant.expires_at_unix_ms");
  expect(launchIntentSource).toContain("leanbun-trusted-lake-launch-intent-v1");
  expect(launchIntentSource).not.toContain(
    "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct TrustedLakeLaunchIntentV1",
  );
  expect(launchReservationSource).toContain("open_trusted_lake_launch_reservation_registry_v1");
  expect(launchReservationSource).toContain("Mode::from_raw_mode(stat.st_mode) != Mode::RWXU");
  expect(launchReservationSource).toContain("OFlags::CREATE | OFlags::EXCL");
  expect(launchReservationSource).toContain("OFlags::NOFOLLOW | OFlags::CLOEXEC");
  expect(launchReservationSource).toContain("slot.write_all(&bytes)");
  expect(launchReservationSource).toContain("slot.sync_all()");
  expect(launchReservationSource).toContain("rustix::fs::fsync(&self.root)");
  expect(launchReservationSource).toContain("durable_at_unix_ms >= intent.expires_at_unix_ms");
  expect(launchReservationSource).toContain(".launch-reserved-v1");
  expect(launchReservationSource).toContain("TrustedLakeLaunchReservationAuthorityV1::ReservedOnce");
  expect(launchReservationSource).not.toContain(
    "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct TrustedLakeLaunchReservationV1",
  );
  expect(spawnBoundarySource).toContain("macos_executable_handoff_contract_v1");
  expect(spawnBoundarySource).toContain("RustStandardCommand");
  expect(spawnBoundarySource).toContain("RustStandardPreExec");
  expect(spawnBoundarySource).toContain("RustixExecveAt");
  expect(spawnBoundarySource).toContain("MacOsPosixSpawn");
  expect(spawnBoundarySource).toContain("BunSystemPosixSpawn");
  expect(spawnBoundarySource).toContain("DevFdExecutablePath");
  expect(spawnBoundarySource).toContain("DeniedNoStableFdBoundExecution");
  expect(spawnBoundarySource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(launchPolicySource).toContain("macos_path_launch_policy_v1");
  expect(launchPolicySource).toContain("SameEffectiveUidConcurrentMutation");
  expect(launchPolicySource).toContain("EveryComponentMutationDeniedToEffectiveUid");
  expect(launchPolicySource).toContain("AccessControlListsAndFileFlagsVerified");
  expect(launchPolicySource).toContain("UserOwnedManagedToolchain");
  expect(launchPolicySource).toContain("UserImmutableFlagOnly");
  expect(launchPolicySource).toContain("DeniedMutableByInScopeActor");
  expect(launchPolicySource).toContain("IsolatedFixtureOnly");
  expect(launchPolicySource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(pathProvenanceSource).toContain("observe_macos_path_provenance_v1");
  expect(pathProvenanceSource).toContain("OFlags::NOFOLLOW");
  expect(pathProvenanceSource).toContain("AtFlags::EACCESS");
  expect(pathProvenanceSource).toContain("rustix::fs::fstatvfs(&fd)");
  expect(pathProvenanceSource).toContain("rustix::fs::fstatfs(&fd)");
  expect(pathProvenanceSource).toContain("stat.st_flags");
  expect(pathProvenanceSource).toContain("MacOsAclCoverageV1::EffectiveUidOnly");
  expect(pathProvenanceSource).toContain("ConservativeMutationAllowScan");
  expect(pathProvenanceSource).toContain("native_mount_ignores_ownership");
  expect(pathProvenanceSource).toContain("observe_fd_acl_v1(fd.as_fd())");
  expect(pathProvenanceSource).toContain("DeniedUserOwnedComponent");
  expect(pathProvenanceSource).toContain("DeniedAclCoverageUnverified");
  expect(pathProvenanceSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(pathEligibilitySource).toContain("assess_reservation_bound_path_eligibility_v1");
  expect(pathEligibilitySource).toContain("reservation_integrity_is_valid_v1(reservation)");
  expect(pathEligibilitySource).toContain("reobserve_reserved_executable_v1(reservation)");
  expect(pathEligibilitySource).toContain(
    "observe_macos_path_provenance_v1(reservation.executable())",
  );
  expect(pathEligibilitySource).toContain("DeniedExecutableIdentityDrift");
  expect(pathEligibilitySource).toContain("DeniedUserOwnedComponent");
  expect(pathEligibilitySource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(pathEligibilitySource).toContain(
    "reservation: &TrustedLakeLaunchReservationV1",
  );
  expect(pathEligibilitySource).not.toContain(
    "reservation: TrustedLakeLaunchReservationV1",
  );
  expect(deploymentContractSource).toContain(
    "macos_stable_executable_deployment_contract_v1",
  );
  expect(deploymentContractSource).toContain(
    "SdkMountReadOnlyDeniesEvenSuperUserWrites",
  );
  expect(deploymentContractSource).toContain("SdkMountUpdateCanChangeFlags");
  expect(deploymentContractSource).toContain("SdkUnmountCanReplaceTopology");
  expect(deploymentContractSource).toContain("RustixMountModuleIsLinuxOnly");
  expect(deploymentContractSource).toContain("RustixFileLocksAreAdvisory");
  expect(deploymentContractSource).toContain("NotAvailableForCustomLeanLake");
  expect(deploymentContractSource).toContain("DeniedUserCanReplaceMountTopology");
  expect(deploymentContractSource).toContain("RequiresPrivilegedUpdaterLease");
  expect(deploymentContractSource).toContain("RequiresPrivilegedMountLifecycleLease");
  expect(deploymentContractSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(coordinatorContractSource).toContain(
    "macos_privileged_coordinator_contract_v1",
  );
  expect(coordinatorContractSource).toContain("SmAppServiceRequiresCodeSigning");
  expect(coordinatorContractSource).toContain(
    "LaunchDaemonRequiresNotarizationAndAdminApproval",
  );
  expect(coordinatorContractSource).toContain("SmJobBlessIsDeprecated");
  expect(coordinatorContractSource).toContain(
    "AuthorizationExecuteWithPrivilegesIsDeprecated",
  );
  expect(coordinatorContractSource).toContain("XpcSupportsPeerCodeSigningRequirement");
  expect(coordinatorContractSource).toContain(
    "ReservationCapabilityIsNotTransportSerializable",
  );
  expect(coordinatorContractSource).toContain("PathAssessmentUsesProcessEffectiveUid");
  expect(coordinatorContractSource).toContain("DeniedPrincipalAndCapabilityMismatch");
  expect(coordinatorContractSource).toContain("ExplicitUnprivilegedThreatPrincipal");
  expect(coordinatorContractSource).toContain("CoordinatorOwnedReplayAndReservationLedger");
  expect(coordinatorContractSource).toContain("DeniedCoordinatorProtocolNotEstablished");
  expect(coordinatorContractSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(coordinatorRequestSource).toContain("prepare_macos_coordinator_request_v1");
  expect(coordinatorRequestSource).toContain(
    '"com.leanbun.execute-reserved-lake-command"',
  );
  expect(coordinatorRequestSource).toContain("PeerPrincipalMismatch");
  expect(coordinatorRequestSource).toContain("MAX_SUPPLEMENTARY_GROUPS");
  expect(coordinatorRequestSource).toContain("MAX_REQUEST_LIFETIME_MS");
  expect(coordinatorRequestSource).toContain("reservation_sha256");
  expect(coordinatorRequestSource).toContain("executable_sha256");
  expect(coordinatorRequestSource).toContain("PendingCoordinatorVerification");
  expect(coordinatorRequestSource).toContain("PlanExecutionAuthorityV1::Withheld");
  expect(coordinatorRequestSource.split("#[cfg(test)]", 1)[0]).not.toContain(
    "AuthorizationExternalForm",
  );
  expect(coordinatorWireSource).toContain("encode_macos_coordinator_request_wire_v1");
  expect(coordinatorWireSource).toContain("decode_macos_coordinator_request_wire_v1");
  expect(coordinatorWireSource).toContain(
    "MAX_MACOS_COORDINATOR_REQUEST_WIRE_BYTES_V1",
  );
  expect(coordinatorWireSource).toContain("WIRE_FIELD_COUNT: u16 = 21");
  expect(coordinatorWireSource).toContain("field_id != expected_id");
  expect(coordinatorWireSource).toContain("cursor.remaining() != 0");
  expect(coordinatorWireSource).toContain("RequestIdentityMismatch");
  expect(coordinatorWireSource).toContain("prepare_macos_coordinator_request_v1");
  expect(coordinatorWireSource).toContain("request.request_sha256()");
  expect(coordinatorWireSource.split("#[cfg(test)]", 1)[0]).not.toContain(
    "AuthorizationExternalForm",
  );
  expect(launchReservationSource).toContain("canonical_reservation_bytes(");
  expect(launchReservationSource).toContain("reobserve_reserved_executable_v1");
  expect(aclBoundarySource).toContain("macos_acl_native_boundary_v1");
  expect(aclBoundarySource).toContain("AclGetFdNp");
  expect(aclBoundarySource).toContain("AclGetPermsetMaskNp");
  expect(aclBoundarySource).toContain("AclStorageFreedExactlyOnce");
  expect(aclBoundarySource).toContain("AnyMutationAllowEntryDenies");
  expect(aclBoundarySource).toContain("AclGetQualifierAndMembership");
  expect(aclBoundarySource).toContain("NotRequiredByConservativePolicy");
  expect(aclBoundarySource).toContain("RequiresSeparateAuditedFfiCrate");
  expect(aclBoundarySource).toContain("PlanExecutionAuthorityV1::Withheld");
  for (const symbol of [
    "acl_get_fd_np", "acl_get_entry", "acl_get_tag_type",
    "acl_get_permset_mask_np", "acl_free",
  ]) {
    expect(aclSysSource, symbol).toContain(`fn ${symbol}`);
  }
  expect(aclSysSource.match(/unsafe \{/g)?.length).toBe(6);
  expect(aclSysSource).toContain("struct AclHandle");
  expect(aclSysSource).toContain("fn release(mut self)");
  expect(aclSysSource).toContain("DeniedMutationAllowEntry");
  expect(aclSysSource).toContain("DeniedUnknownAllowPermission");
  for (const forbidden of [
    "fn acl_set", "fn acl_create", "fn acl_delete", "acl_get_qualifier",
    "acl_to_text", "acl_from_text", "std::process", "Command::new(",
  ]) {
    expect(aclSysSource, forbidden).not.toContain(forbidden);
  }
  const replayRuntimeSource = replaySource.split("#[cfg(test)]", 1)[0] ?? replaySource;
  const proofRuntimeSource = proofSource.split("#[cfg(test)]", 1)[0] ?? proofSource;
  const executableRuntimeSource = executableSource.split("#[cfg(test)]", 1)[0] ?? executableSource;
  const freshPlanRuntimeSource = freshPlanSource.split("#[cfg(test)]", 1)[0] ?? freshPlanSource;
  const candidateRuntimeSource = candidateSource.split("#[cfg(test)]", 1)[0] ?? candidateSource;
  const executionGrantRuntimeSource = executionGrantSource.split("#[cfg(test)]", 1)[0] ?? executionGrantSource;
  const launchIntentRuntimeSource = launchIntentSource.split("#[cfg(test)]", 1)[0] ?? launchIntentSource;
  const launchReservationRuntimeSource = launchReservationSource.split("#[cfg(test)]", 1)[0] ?? launchReservationSource;
  const spawnBoundaryRuntimeSource = spawnBoundarySource.split("#[cfg(test)]", 1)[0] ?? spawnBoundarySource;
  const launchPolicyRuntimeSource = launchPolicySource.split("#[cfg(test)]", 1)[0] ?? launchPolicySource;
  const pathProvenanceRuntimeSource = pathProvenanceSource.split("#[cfg(test)]", 1)[0] ?? pathProvenanceSource;
  const pathEligibilityRuntimeSource = pathEligibilitySource.split("#[cfg(test)]", 1)[0] ?? pathEligibilitySource;
  const deploymentContractRuntimeSource = deploymentContractSource.split("#[cfg(test)]", 1)[0] ?? deploymentContractSource;
  const coordinatorContractRuntimeSource = coordinatorContractSource.split("#[cfg(test)]", 1)[0] ?? coordinatorContractSource;
  const coordinatorRequestRuntimeSource = coordinatorRequestSource.split("#[cfg(test)]", 1)[0] ?? coordinatorRequestSource;
  const coordinatorWireRuntimeSource = coordinatorWireSource.split("#[cfg(test)]", 1)[0] ?? coordinatorWireSource;
  const aclBoundaryRuntimeSource = aclBoundarySource.split("#[cfg(test)]", 1)[0] ?? aclBoundarySource;
  const adapterSource = `${source}\n${presentationSource}\n${replayRuntimeSource}\n${proofRuntimeSource}\n${executableRuntimeSource}\n${freshPlanRuntimeSource}\n${candidateRuntimeSource}\n${executionGrantRuntimeSource}\n${launchIntentRuntimeSource}\n${launchReservationRuntimeSource}\n${spawnBoundaryRuntimeSource}\n${launchPolicyRuntimeSource}\n${pathProvenanceRuntimeSource}\n${pathEligibilityRuntimeSource}\n${deploymentContractRuntimeSource}\n${coordinatorContractRuntimeSource}\n${coordinatorRequestRuntimeSource}\n${coordinatorWireRuntimeSource}\n${aclBoundaryRuntimeSource}`;
  for (const forbidden of [
    "read_line(", "read_to_string(", "std::process::Command", "Command::new(",
    "std::env", "unsafe {", "remove_file(", "remove_dir_all(", "lake update",
  ]) {
    expect(adapterSource, forbidden).not.toContain(forbidden);
  }
});

test("Rust coordinator request identity matches the Bun binary oracle", () => {
  const parts = [Buffer.from("leanbun-macos-coordinator-request-v1\0", "utf8")];
  const field = (key: string, value: Buffer) => {
    const keyBytes = Buffer.from(key, "utf8");
    const keyLength = Buffer.alloc(8);
    const valueLength = Buffer.alloc(8);
    keyLength.writeBigUInt64BE(BigInt(keyBytes.length));
    valueLength.writeBigUInt64BE(BigInt(value.length));
    parts.push(keyLength, keyBytes, valueLength, value);
  };
  const digest = (byte: number) => Buffer.alloc(32, byte);
  const uint32 = (value: number) => {
    const output = Buffer.alloc(4);
    output.writeUInt32BE(value);
    return output;
  };
  const uint64 = (value: number) => {
    const output = Buffer.alloc(8);
    output.writeBigUInt64BE(BigInt(value));
    return output;
  };
  field("operation", Buffer.from("execute-reserved-lake-command"));
  field("authorizationRight", Buffer.from("com.leanbun.execute-reserved-lake-command"));
  field("peerSigningIdentifier", Buffer.from("com.leanbun.cli"));
  field("peerTeamIdentifier", Buffer.from("AB12CD34EF"));
  field("peerCodeRequirementSha256", digest(1));
  field("peerEffectiveUid", uint32(501));
  field("peerAuditSessionId", uint32(42));
  field("threatUid", uint32(501));
  field("threatPrimaryGid", uint32(20));
  field("threatSupplementaryGroups", Buffer.concat([uint32(12), uint32(61), uint32(80)]));
  for (const [key, byte] of [
    ["reservationSha256", 2], ["intentSha256", 3], ["grantSha256", 4],
    ["candidateSha256", 5], ["proofSha256", 6], ["executableSha256", 7],
    ["nonceSha256", 8],
  ] as const) {
    field(key, digest(byte));
  }
  field("issuedAtUnixMs", uint64(1_000));
  field("expiresAtUnixMs", uint64(31_000));
  const actual = new Bun.CryptoHasher("sha256").update(Buffer.concat(parts)).digest("hex");
  expect(actual).toBe("ffcaf2a4cd2d90522bd1f1d357af23558ac623748917ba5d33fae8341fc318e3");
});

test("Rust coordinator canonical wire matches the Bun binary oracle", () => {
  const fields: Buffer[] = [];
  const field = (id: number, value: Buffer) => {
    const header = Buffer.alloc(6);
    header.writeUInt16BE(id, 0);
    header.writeUInt32BE(value.length, 2);
    fields.push(header, value);
  };
  const digest = (byte: number) => Buffer.alloc(32, byte);
  const uint32 = (value: number) => {
    const output = Buffer.alloc(4);
    output.writeUInt32BE(value);
    return output;
  };
  const uint64 = (value: number) => {
    const output = Buffer.alloc(8);
    output.writeBigUInt64BE(BigInt(value));
    return output;
  };
  field(1, Buffer.from([1]));
  field(2, Buffer.from("execute-reserved-lake-command"));
  field(3, Buffer.from("com.leanbun.execute-reserved-lake-command"));
  field(4, Buffer.from("com.leanbun.cli"));
  field(5, Buffer.from("AB12CD34EF"));
  field(6, digest(1));
  field(7, uint32(501));
  field(8, uint32(42));
  field(9, uint32(501));
  field(10, uint32(20));
  field(11, Buffer.concat([uint32(12), uint32(61), uint32(80)]));
  for (const [id, byte] of [
    [12, 2], [13, 3], [14, 4], [15, 5], [16, 6], [17, 7], [18, 8],
  ] as const) {
    field(id, digest(byte));
  }
  field(19, uint64(1_000));
  field(20, uint64(31_000));
  field(21, Buffer.from(
    "ffcaf2a4cd2d90522bd1f1d357af23558ac623748917ba5d33fae8341fc318e3",
    "hex",
  ));
  const wire = Buffer.concat([
    Buffer.from("leanbun-macos-coordinator-wire-v1\0"),
    unsigned16(21),
    ...fields,
  ]);
  expect(wire.length).toBeLessThanOrEqual(4_096);
  const actual = new Bun.CryptoHasher("sha256").update(wire).digest("hex");
  expect(actual).toBe("a9bc33d754e8dbd2ba8f03da85756c9f0fbea445c70b1af5c9228a6cd2c1ae1f");
});

function unsigned16(value: number): Buffer {
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return output;
}

function unsigned64(value: number): Buffer {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function identityBlob(value: Buffer): Buffer {
  return Buffer.concat([unsigned64(value.length), value]);
}

function identityField(key: string, value: Buffer): Buffer {
  const keyBytes = Buffer.from(key, "utf8");
  return Buffer.concat([unsigned16(keyBytes.length), keyBytes, identityBlob(value)]);
}

test("Rust canonical project input identity matches the Bun binary oracle", async () => {
  const lines = (await readFile(new URL("project-input-identity.tsv", goldenRoot), "utf8"))
    .trimEnd()
    .split("\n");
  const scalar = new Map<string, string>();
  const packages: Array<{
    name: string;
    kind: string;
    revision: string;
    path: string;
  }> = [];
  for (const line of lines) {
    const [key, ...values] = line.split("\t");
    if (key === "package") {
      const [name, kind, revision, path] = values;
      packages.push({ name, kind, revision, path });
    } else {
      scalar.set(key, values[0]);
    }
  }
  packages.sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));

  const parts = [Buffer.from("leanbun-project-input-identity-v1\0", "utf8")];
  parts.push(identityField("projectPath", Buffer.from(scalar.get("projectPath")!, "utf8")));
  parts.push(identityField("state", Buffer.from(scalar.get("state")!, "utf8")));
  parts.push(identityField("toolchain", Buffer.from(scalar.get("toolchain")!, "utf8")));
  for (const field of [
    "toolchainSha256",
    "manifestSha256",
    "overrideSha256",
    "providerRegistrySha256",
    "providerOverrideSha256",
  ]) {
    const value = scalar.get(field) ?? "";
    parts.push(identityField(field, Buffer.from(value, "hex")));
  }
  parts.push(identityField("packageCount", unsigned64(packages.length)));
  for (const entry of packages) {
    const record = Buffer.concat([
      identityBlob(Buffer.from(entry.name, "utf8")),
      Buffer.from([entry.kind === "git" ? 0 : 1]),
      identityBlob(Buffer.from(entry.revision, "utf8")),
      identityBlob(Buffer.from(entry.path, "utf8")),
    ]);
    parts.push(identityField("package", record));
  }
  const canonical = Buffer.concat(parts);
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(canonical);
  expect(projectId(scalar.get("projectPath")!)).toBe(scalar.get("projectId"));
  expect(hasher.digest("hex")).toBe(scalar.get("digest"));
});
