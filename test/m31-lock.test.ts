import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

const fixtureRoot = new URL("fixtures/m31-lock/", import.meta.url);
const encoder = new TextEncoder();

function decodeHex(value: string): string {
  if (value === "-") return "";
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) throw new Error("invalid hex");
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.fromHex(value));
}

function validAtom(value: string, maximum: number, allowEmpty = false): boolean {
  return (allowEmpty || value.length > 0) && encoder.encode(value).length <= maximum && !/[\u0000-\u001f\u007f]/u.test(value);
}

function validRelativePath(value: string, maximum: number): boolean {
  return validAtom(value, maximum) && !value.includes("\\") && value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function validModelFixture(fields: string[]): boolean {
  try {
    const scope = decodeHex(fields[2]!);
    const name = decodeHex(fields[3]!);
    if (!validAtom(scope, 256, true) || !validAtom(name, 256)) return false;
    const location = decodeHex(fields[5]!);
    if (fields[4] === "path") {
      if (location.startsWith("/") || location.startsWith("\\") || location[1] === ":") return false;
      return validRelativePath(location, 4096);
    }
    if (fields[4] !== "git") return false;
    const match = /^https:\/\/([^/]+)\/(.+)$/u.exec(location);
    if (!match) return false;
    const [, host, path] = match;
    if (!host || !path || !/^[a-z0-9.-]+$/u.test(host) || host.split(".").some((label) => label === "" || label.startsWith("-") || label.endsWith("-"))) return false;
    if (path.split("/").some((part) => part === "" || part === "." || part === "..")) return false;
    if (location.includes("?") || location.includes("#") || location.includes("%") || location.includes("\\") || /\s/u.test(location)) return false;
    if (!/^[0-9a-f]{40}$/.test(fields[6]!)) return false;
    return fields[7] === "-" || validRelativePath(decodeHex(fields[7]!), 1024);
  } catch {
    return false;
  }
}

function updateLength(hasher: Bun.CryptoHasher, value: string): void {
  const length = BigInt(encoder.encode(value).length);
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, length, false);
  hasher.update(bytes);
  hasher.update(value);
}

function sha256(parts: Array<string | Uint8Array>): string {
  const hasher = new Bun.CryptoHasher("sha256");
  for (const part of parts) hasher.update(part);
  return hasher.digest("hex");
}

function repeatHex(byte: number): string {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

interface OraclePackage {
  scope: string;
  name: string;
  selected: string;
  exactRevision?: string;
  sourceTree?: string;
  dependencies: Array<{ scope: string; name: string }>;
}

function graphIdentity(packages: OraclePackage[]): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update("leanbun-package-graph-v1\0");
  for (const pkg of packages) {
    updateLength(hasher, pkg.scope);
    updateLength(hasher, pkg.name);
    hasher.update(new Uint8Array([0]));
    updateLength(hasher, "https://github.com/example/package");
    hasher.update(new Uint8Array([1]));
    updateLength(hasher, "main");
    hasher.update(new Uint8Array([0]));
    updateLength(hasher, "https://github.com/example/package");
    updateLength(hasher, pkg.exactRevision ?? "1".repeat(40));
    hasher.update(new Uint8Array([1]));
    updateLength(hasher, "src");
    hasher.update(new Uint8Array([1]));
    hasher.update(Uint8Array.fromHex(repeatHex(1)));
    hasher.update(Uint8Array.fromHex(pkg.sourceTree ?? repeatHex(2)));
    hasher.update(Uint8Array.fromHex(repeatHex(3)));
    hasher.update(new Uint8Array([1]));
    hasher.update(Uint8Array.fromHex(repeatHex(4)));
    hasher.update(Uint8Array.fromHex(pkg.selected));
    for (const dependency of pkg.dependencies) {
      updateLength(hasher, dependency.scope);
        updateLength(hasher, dependency.name);
    }
    hasher.update(Uint8Array.fromHex(repeatHex(5)));
  }
  return hasher.digest("hex");
}

function h(value: string): string {
  return Buffer.from(value).toString("hex");
}

function canonicalText(graph: string): string {
  const url = h("https://github.com/example/package");
  const common = (selected: string, dependencies: string) =>
    `requested\tgit\t${url}\t${h("main")}\n` +
    `resolved\tgit\t${url}\t${"1".repeat(40)}\t${h("src")}\n` +
    `download-integrity\t${repeatHex(1)}\n` +
    `source-tree-sha256\t${repeatHex(2)}\n` +
    `config-sha256\t${repeatHex(3)}\n` +
    `manifest-sha256\t${repeatHex(4)}\n` +
    `selected-source-identity\t${selected}\n` +
    dependencies +
    `provenance-count\t1\nprovenance\t${repeatHex(5)}\nend-package\n`;
  return (
    `leanbun-lock-v1\t1\n` +
    `lean-toolchain\t${h("leanprover/lean4:v4.32.0")}\n` +
    `lean-compiler-githash\t${h("1".repeat(40))}\n` +
    `lake-version\t${h("5.0.0-src+8c9756b")}\n` +
    `root-config-sha256\t${repeatHex(8)}\n` +
    `root-declaration-sha256\t${repeatHex(9)}\n` +
    `package-count\t2\n` +
    `package\t\t${h("alpha")}\n` +
    common(repeatHex(6), `dependency-count\t1\ndependency\t${h("scope")}\t${h("beta")}\n`) +
    `package\t${h("scope")}\t${h("beta")}\n` +
    common(repeatHex(7), "dependency-count\t0\n") +
    `graph-sha256\t${graph}\nend-lock\n`
  );
}

describe("M31 Bun contract oracle", () => {
  test("shared positive and negative bounded model fixtures match", async () => {
    const lines = (await readFile(new URL("model-cases.tsv", fixtureRoot), "utf8")).trimEnd().split("\n");
    for (const line of lines) {
      const fields = line.split("\t");
      expect(fields).toHaveLength(8);
      expect(validModelFixture(fields), fields[1]).toBe(fields[0] === "true");
    }
  });

  test("canonical graph, text, and binary identity match Rust", async () => {
    const expected = new Map(
      (await readFile(new URL("canonical-golden.tsv", fixtureRoot), "utf8"))
        .trimEnd()
        .split("\n")
        .map((line) => line.split("\t") as [string, string]),
    );
    const packages: OraclePackage[] = [
      { scope: "", name: "alpha", selected: repeatHex(6), dependencies: [{ scope: "scope", name: "beta" }] },
      { scope: "scope", name: "beta", selected: repeatHex(7), dependencies: [] },
    ];
    const graph = graphIdentity(packages);
    const text = canonicalText(graph);
    expect(graph).toBe(expected.get("graph"));
    expect(sha256([text])).toBe(expected.get("text-sha256"));
    expect(sha256(["leanbun-lock-identity-v1\0", text])).toBe(expected.get("identity"));
  });

  test("package and edge order normalize, while every semantic field remains bound", () => {
    const normalize = (packages: OraclePackage[]) => packages
      .map((pkg) => ({ ...pkg, dependencies: [...pkg.dependencies].sort((a, b) => Buffer.from(`${a.scope}\0${a.name}`).compare(Buffer.from(`${b.scope}\0${b.name}`))) }))
      .sort((a, b) => Buffer.from(`${a.scope}\0${a.name}`).compare(Buffer.from(`${b.scope}\0${b.name}`)));
    const first: OraclePackage[] = [
      { scope: "scope", name: "beta", selected: repeatHex(7), dependencies: [] },
      { scope: "", name: "alpha", selected: repeatHex(6), dependencies: [{ scope: "z", name: "last" }, { scope: "a", name: "first" }] },
    ];
    const reordered = [...first].reverse().map((pkg) => ({ ...pkg, dependencies: [...pkg.dependencies].reverse() }));
    const baseline = graphIdentity(normalize(first));
    expect(graphIdentity(normalize(reordered))).toBe(baseline);
    expect(graphIdentity(normalize(first.map((pkg, index) => index === 1 ? { ...pkg, exactRevision: "2".repeat(40) } : pkg)))).not.toBe(baseline);
    expect(graphIdentity(normalize(first.map((pkg, index) => index === 1 ? { ...pkg, sourceTree: repeatHex(10) } : pkg)))).not.toBe(baseline);
  });
});
