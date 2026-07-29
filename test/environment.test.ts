import { expect, test } from "bun:test";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, sep } from "node:path";

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

test("development process uses isolated state roots", async () => {
  expect(process.env.LEANBUN_ENV).toBe("development");
  const root = await realpath(process.env.LEANBUN_DEV_ROOT!);
  for (const name of [
    "ELAN_HOME",
    "MATHLIB_CACHE_DIR",
    "BUN_INSTALL_CACHE_DIR",
    "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "TMPDIR",
    "LEANBUN_PACKAGE_OVERRIDES",
    "LEANBUN_PROVIDER_REGISTRY",
    "LEANBUN_PROVIDER_OVERRIDES",
    "LEANBUN_PROVIDER_PACKAGE_ROOT",
    "LEANBUN_PROVIDER_CACHE_ROOT",
    "LEANBUN_STATE_ROOT",
  ]) {
    const value = process.env[name];
    expect(value, `${name} is set`).toBeString();
    expect(isWithin(root, value!), `${name} remains inside development root`).toBeTrue();
  }
  expect(process.env.LEANBUN_PROVIDER_ID).toBe(
    "lean4-v4.32.0_mathlib-81a5d257c8e4",
  );
  expect(process.env.LEANBUN_PROVIDER_TOOLCHAIN).toBe("leanprover/lean4:v4.32.0");
  expect(process.env.LEANBUN_PROVIDER_LEAN_GITHASH).toBe(
    "8c9756b28d64dab099da31a4c09229a9e6a2ef35",
  );
});

test("development override contains no production dependency path", async () => {
  const path = process.env.LEANBUN_PACKAGE_OVERRIDES!;
  const text = await readFile(path, "utf8");
  expect(text).not.toContain("/Dependency libraries/");
  const value = JSON.parse(text) as { packages?: Array<{ dir?: string }> };
  expect(value.packages?.length).toBe(9);
  for (const entry of value.packages ?? []) {
    expect(entry.dir).toStartWith(process.env.LEANBUN_DEV_ROOT!);
  }
});
