import { expect, test } from "bun:test";
import {
  checkDefaultMembers,
  checkCurrentWorkspace,
  checkLayering,
  type DependencyGraph,
} from "../scripts/check-crate-layering.ts";

function graph(overrides: Record<string, string[]> = {}): DependencyGraph {
  const values: Record<string, string[]> = {
    "leanbun-core": [],
    "leanbun-evidence": ["leanbun-core"],
    "leanbun-package": ["leanbun-core", "leanbun-evidence"],
    "leanbun-lake-bridge": ["leanbun-core", "leanbun-evidence", "leanbun-package"],
    "leanbun-resolver": ["leanbun-core", "leanbun-lake-bridge", "leanbun-package"],
    "leanbun-store": ["leanbun-core", "leanbun-lake-bridge", "leanbun-package", "leanbun-resolver"],
    "leanbun-generation": [
      "leanbun-core",
      "leanbun-lake-bridge",
      "leanbun-package",
      "leanbun-resolver",
      "leanbun-store",
    ],
    "leanbun-build": [
      "leanbun-core",
      "leanbun-generation",
      "leanbun-lake-bridge",
      "leanbun-package",
      "leanbun-resolver",
      "leanbun-store",
    ],
    "leanbun-managed": [
      "leanbun-build",
      "leanbun-core",
      "leanbun-evidence",
      "leanbun-generation",
      "leanbun-lake-bridge",
      "leanbun-package",
      "leanbun-resolver",
      "leanbun-store",
    ],
    "leanbun-plan": ["leanbun-core", "leanbun-evidence", "leanbun-package"],
    "leanbun-state": ["leanbun-core", "leanbun-evidence"],
    "leanbun-macos-acl-sys": [],
    "leanbun-approval-macos": [
      "leanbun-core",
      "leanbun-evidence",
      "leanbun-macos-acl-sys",
      "leanbun-package",
      "leanbun-plan",
    ],
    ...overrides,
  };
  return new Map(Object.entries(values).map(([name, dependencies]) => [name, new Set(dependencies)]));
}

function m44Graph(overrides: Record<string, string[]> = {}): DependencyGraph {
  return graph({
    "leanbun-lock": ["leanbun-core"],
    "leanbun-package": ["leanbun-core", "leanbun-evidence", "leanbun-lock"],
    "leanbun-lake-bridge": ["leanbun-core", "leanbun-evidence", "leanbun-lock"],
    "leanbun-resolver": ["leanbun-core", "leanbun-lake-bridge", "leanbun-lock"],
    "leanbun-store": ["leanbun-core", "leanbun-lake-bridge", "leanbun-lock", "leanbun-resolver"],
    "leanbun-generation": [
      "leanbun-core",
      "leanbun-lake-bridge",
      "leanbun-lock",
      "leanbun-resolver",
      "leanbun-store",
    ],
    "leanbun-build": [
      "leanbun-core",
      "leanbun-generation",
      "leanbun-lake-bridge",
      "leanbun-lock",
      "leanbun-resolver",
      "leanbun-store",
    ],
    "leanbun-managed": [
      "leanbun-build",
      "leanbun-core",
      "leanbun-evidence",
      "leanbun-generation",
      "leanbun-lake-bridge",
      "leanbun-lock",
      "leanbun-resolver",
      "leanbun-store",
    ],
    ...overrides,
  });
}

function m44bGraph(): DependencyGraph {
  const candidate = new Map(m44Graph());
  candidate.delete("leanbun-package");
  candidate.set("leanbun-inventory-legacy", new Set(["leanbun-core", "leanbun-evidence"]));
  candidate.set(
    "leanbun-plan",
    new Set(["leanbun-core", "leanbun-evidence", "leanbun-inventory-legacy"]),
  );
  candidate.set(
    "leanbun-approval-macos",
    new Set([
      "leanbun-core",
      "leanbun-evidence",
      "leanbun-inventory-legacy",
      "leanbun-macos-acl-sys",
      "leanbun-plan",
    ]),
  );
  return candidate;
}

function m45Graph(): DependencyGraph {
  const candidate = new Map(m44bGraph());
  candidate.set("leanbun-codec", new Set(["leanbun-core"]));
  candidate.set("leanbun-evidence", new Set(["leanbun-codec", "leanbun-core"]));
  for (const consumer of ["leanbun-lake-bridge", "leanbun-managed", "leanbun-plan"]) {
    candidate.get(consumer)?.add("leanbun-codec");
  }
  return candidate;
}

test("current workspace satisfies its reviewed dependency and baseline gates", async () => {
  expect(await checkCurrentWorkspace()).toContain("crate-layering=passed");
});

test("M47 default members contain the complete mainline and exclude historical crates", () => {
  const current = m45Graph();
  const defaults = new Set([
    "leanbun-build",
    "leanbun-codec",
    "leanbun-core",
    "leanbun-evidence",
    "leanbun-generation",
    "leanbun-lake-bridge",
    "leanbun-lock",
    "leanbun-managed",
    "leanbun-resolver",
    "leanbun-store",
  ]);
  expect(checkDefaultMembers(current, defaults)).toEqual([]);

  const historical = new Set(defaults);
  historical.add("leanbun-plan");
  expect(checkDefaultMembers(current, historical)).toContain(
    "historical crate is a default member: leanbun-plan",
  );

  const incomplete = new Set(defaults);
  incomplete.delete("leanbun-managed");
  expect(checkDefaultMembers(current, incomplete)).toContain(
    "default mainline crate is not a default member: leanbun-managed",
  );
});

test("pre-M44 mixed package is an explicit temporary compatibility edge", () => {
  expect(checkLayering(graph())).toEqual([]);
});

test("M44 Phase A requires every mainline root to import the lock crate directly", () => {
  expect(checkLayering(m44Graph())).toEqual([]);
  expect(
    checkLayering(m44Graph({ "leanbun-build": ["leanbun-generation", "leanbun-lake-bridge"] })),
  ).toContain("leanbun-build must depend directly on leanbun-lock after the split");
});

test("M44 Phase B replaces the mixed package with an isolated inventory legacy crate", () => {
  expect(checkLayering(m44bGraph())).toEqual([]);
  expect(
    checkLayering(
      m44Graph({ "leanbun-inventory-legacy": ["leanbun-core", "leanbun-evidence"] }),
    ),
  ).toContain("leanbun-package must be removed after leanbun-inventory-legacy exists");
});

test("M45 keeps the pure codec below evidence and gives parser consumers direct edges", () => {
  expect(checkLayering(m45Graph())).toEqual([]);

  const reverse = new Map(m45Graph());
  reverse.set("leanbun-codec", new Set(["leanbun-core", "leanbun-evidence"]));
  expect(checkLayering(reverse)).toContain(
    "leanbun-codec must remain below evidence and policy: leanbun-evidence",
  );

  const indirect = new Map(m45Graph());
  indirect.get("leanbun-lake-bridge")?.delete("leanbun-codec");
  expect(checkLayering(indirect)).toContain(
    "leanbun-lake-bridge must depend directly on leanbun-codec after the split",
  );
});

test("mainline transitively reaching historical policy is rejected", () => {
  const errors = checkLayering(graph({ "leanbun-store": ["leanbun-resolver", "leanbun-plan"] }));
  expect(errors).toContain("leanbun-store reaches historical crate leanbun-plan");
  expect(errors).toContain("leanbun-generation reaches historical crate leanbun-plan");
});

test("evidence reverse dependency into resolver policy is rejected", () => {
  const errors = checkLayering(graph({ "leanbun-evidence": ["leanbun-core", "leanbun-resolver"] }));
  expect(errors).toContain("leanbun-evidence has a forbidden reverse dependency on leanbun-resolver");
});

test("core gaining a workspace dependency is rejected", () => {
  const errors = checkLayering(graph({ "leanbun-core": ["leanbun-evidence"] }));
  expect(errors.some((error) => error.startsWith("leanbun-core must have no workspace dependencies"))).toBe(true);
});

test("future lock crate must depend only on core and replace mixed package in mainline", () => {
  const candidate = graph({
    "leanbun-lock": ["leanbun-core", "leanbun-evidence"],
    "leanbun-resolver": ["leanbun-core", "leanbun-lock", "leanbun-package"],
  });
  const errors = checkLayering(candidate);
  expect(errors.some((error) => error.startsWith("leanbun-lock must depend only on leanbun-core"))).toBe(true);
  expect(errors).toContain(
    "leanbun-resolver still reaches mixed-generation leanbun-package after leanbun-lock exists",
  );
});

test("future inventory legacy cannot depend on the current lock model", () => {
  const errors = checkLayering(
    graph({
      "leanbun-lock": ["leanbun-core"],
      "leanbun-inventory-legacy": ["leanbun-core", "leanbun-evidence", "leanbun-lock"],
    }),
  );
  expect(errors).toContain(
    "leanbun-inventory-legacy must not regain visibility of the current lock model",
  );
});
