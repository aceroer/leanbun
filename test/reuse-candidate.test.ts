import { expect, test } from "bun:test";
import type { StoredExecutionRecord } from "../src/adapters/execution-record-store";
import { compareReuseTree, selectReuseCandidate } from "../src/application/reuse-candidate";
import type { ControlledBuildExecutionRecordV1, ProjectBuildReuseEvidenceV1 } from "../src/domain/build";
import type { CanonicalPath, Sha256 } from "../src/domain/model";

const hash = "1".repeat(64);
const identity = {
  projectId: hash,
  projectPath: "/fixture/project",
  imageId: hash,
  target: "Fixture",
  bindingSha256: hash,
  attestationSha256: hash,
};
const reuseEvidence: ProjectBuildReuseEvidenceV1 = {
  schemaVersion: 1,
  projectInput: {
    schema: "leanbun-project-input-tree-v1",
    treeHash: hash,
    entryCount: 2,
    fileCount: 1,
    byteCount: 4,
  },
  projectOutput: {
    schema: "leanbun-project-output-tree-v1",
    treeHash: hash,
    entryCount: 3,
    fileCount: 2,
    byteCount: 8,
  },
};

function record(
  executionId: string,
  finishedAt: string,
  changes: Partial<ControlledBuildExecutionRecordV1> = {},
): StoredExecutionRecord {
  const document: ControlledBuildExecutionRecordV1 = {
    schemaVersion: 1,
    recordType: "controlled-build-execution",
    executionId,
    status: "completed",
    ...identity,
    profileSha256: hash,
    dependencyArtifactBefore: hash,
    startedAt: "2026-07-23T00:00:00.000Z",
    finishedAt,
    outcome: {
      buildExecution: "completed",
      lakeExitCode: 0,
      projectProtectedRecordsStable: true,
      bindingStable: true,
      attestationStable: true,
      inspectionStable: true,
      terminationReason: "exit",
      processGroupReaped: true,
      reuseEvidence,
    },
    ...changes,
  };
  return {
    path: `/state/${executionId}.json` as CanonicalPath,
    sha256: hash as Sha256,
    document,
  };
}

test("reuse candidate selection chooses the newest fully compatible successful record", () => {
  const older = record("11111111-1111-4111-8111-111111111111", "2026-07-23T00:01:00.000Z");
  const newer = record("22222222-2222-4222-8222-222222222222", "2026-07-23T00:02:00.000Z");
  const wrongImage = record("33333333-3333-4333-8333-333333333333", "2026-07-23T00:03:00.000Z", {
    imageId: "2".repeat(64),
  });
  const noEvidence = record("44444444-4444-4444-8444-444444444444", "2026-07-23T00:04:00.000Z", {
    outcome: { buildExecution: "completed", lakeExitCode: 0 },
  });
  expect(selectReuseCandidate([wrongImage, older, noEvidence, newer], identity)?.document.executionId)
    .toBe(newer.document.executionId);
  expect(selectReuseCandidate([wrongImage, noEvidence], identity)).toBeUndefined();
});

test("reuse tree comparison requires schema, hash and every count", () => {
  const observed = {
    schema: reuseEvidence.projectOutput.schema,
    treeHash: reuseEvidence.projectOutput.treeHash,
    entryCount: reuseEvidence.projectOutput.entryCount,
    fileCount: reuseEvidence.projectOutput.fileCount,
    byteCount: reuseEvidence.projectOutput.byteCount,
    missingRoots: [],
  };
  expect(compareReuseTree(reuseEvidence.projectOutput, observed).matches).toBeTrue();
  expect(compareReuseTree(reuseEvidence.projectOutput, { ...observed, treeHash: "2".repeat(64) }).matches).toBeFalse();
  expect(compareReuseTree(reuseEvidence.projectOutput, { ...observed, fileCount: 3 }).matches).toBeFalse();
  expect(compareReuseTree(reuseEvidence.projectOutput, { ...observed, missingRoots: ["project-output"] }).matches).toBeFalse();
});
