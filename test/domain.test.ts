import { expect, test } from "bun:test";
import { diagnostic, diagnosticCodes } from "../src/domain/diagnostics";

test("diagnostic vocabulary is unique and machine-stable", () => {
  expect(new Set(diagnosticCodes).size).toBe(diagnosticCodes.length);
  expect(diagnosticCodes).toContain("LAKE_EXECUTION_NOT_ATTEMPTED");
  expect(diagnosticCodes).toContain("EVIDENCE_CHANGED_DURING_READ");
});

test("diagnostics copy and freeze evidence", () => {
  const evidence = ["fixture"];
  const value = diagnostic("EVIDENCE_READ_FAILED", "error", "cannot read", evidence);
  evidence.push("mutated");
  expect(value.evidence).toEqual(["fixture"]);
  expect(Object.isFrozen(value)).toBeTrue();
  expect(Object.isFrozen(value.evidence)).toBeTrue();
});
