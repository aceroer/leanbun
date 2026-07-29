import { describe, expect, test } from "bun:test";
import {
  assessBunRuntime,
  currentBunProvenance,
  supportedBun,
} from "../src/adapters/runtime";
import { main } from "../src/cli";

describe("Bun provenance gate", () => {
  test("accepts the isolated exact Bun build", () => {
    const actual = currentBunProvenance();
    expect(actual.version).toBe(supportedBun.version);
    expect(actual.revision).toBe(supportedBun.revision);
    expect(assessBunRuntime(actual)).toEqual({
      supported: true,
      expected: { version: supportedBun.version, revision: supportedBun.revision },
      actual,
    });
  });

  test("rejects a same-version build with another revision", () => {
    const assessment = assessBunRuntime({
      version: supportedBun.version,
      revision: "ffffffffffffffffffffffffffffffffffffffff",
    });
    expect(assessment.supported).toBeFalse();
    expect(assessment.diagnostic?.code).toBe("BUN_RUNTIME_UNSUPPORTED");
  });

  test("CLI refuses an unsupported runtime before dispatch", async () => {
    expect(await main(["--help"], { version: "1.3.13", revision: "unknown" })).toBe(70);
  });
});
