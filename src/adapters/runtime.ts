import { diagnostic, type Diagnostic } from "../domain/diagnostics";

export const supportedBun = Object.freeze({
  version: "1.3.14",
  revision: "0d9b296af33f2b851fcbf4df3e9ec89751734ba4",
  display: "1.3.14+0d9b296af",
});

export interface BunProvenance {
  version: string;
  revision: string;
}

export interface BunRuntimeAssessment {
  supported: boolean;
  expected: BunProvenance;
  actual: BunProvenance;
  diagnostic?: Diagnostic;
}

export function currentBunProvenance(): BunProvenance {
  return { version: Bun.version, revision: Bun.revision };
}

export function assessBunRuntime(actual: BunProvenance): BunRuntimeAssessment {
  const expected = { version: supportedBun.version, revision: supportedBun.revision };
  if (actual.version === expected.version && actual.revision === expected.revision) {
    return { supported: true, expected, actual };
  }
  return {
    supported: false,
    expected,
    actual,
    diagnostic: diagnostic(
      "BUN_RUNTIME_UNSUPPORTED",
      "error",
      `LeanBun requires Bun ${supportedBun.display}`,
      [
        `expected version=${expected.version} revision=${expected.revision}`,
        `actual version=${actual.version} revision=${actual.revision}`,
      ],
    ),
  };
}
