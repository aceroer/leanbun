import { describe, expect, test } from "bun:test";
import { leanbunBuild, main } from "../src/cli";

describe("development scaffold", () => {
  test("pins filesystem-only inspection mode", () => {
    expect(leanbunBuild.inspectMode).toBe("filesystem-only");
  });

  test("requires a project for inspect", async () => {
    expect(await main(["inspect"])).toBe(2);
  });

  test("requires complete build preflight arguments", async () => {
    expect(await main(["build"])).toBe(2);
  });

  test("requires exactly one execution id for recovery", async () => {
    expect(await main(["build", "recover"])).toBe(2);
  });

  test("requires a project and target for reuse check", async () => {
    expect(await main(["build", "reuse-check"])).toBe(2);
  });

  test("requires a project and target for reuse transaction", async () => {
    expect(await main(["build", "reuse"])).toBe(2);
  });

  test("rejects unknown image seal options before evidence collection", async () => {
    expect(await main(["image", "seal", "--unknown"])).toBe(2);
  });

  test("requires explicit image and target for project bind", async () => {
    expect(await main(["project", "bind", "/tmp/example"])).toBe(2);
  });
});
