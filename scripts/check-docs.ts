import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";

const repository = resolve(import.meta.dir, "..");
const rootAllowlist = new Set([
  "README.adoc",
  "RUST_CONCURRENT_HISTORY_REGRESSION_M42.adoc",
  "TEST_PROJECT_BOUNDARY.adoc",
]);

function insideRepository(path: string): boolean {
  const rel = relative(repository, path);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function repositoryFiles(): string[] {
  const result = Bun.spawnSync({
    cmd: ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.adoc"],
    cwd: repository,
    stdout: "pipe",
    stderr: "inherit",
  });
  if (result.exitCode !== 0) throw new Error("cannot enumerate AsciiDoc files");
  return [...new Set(result.stdout.toString().split("\n").filter(Boolean))]
    .filter((path) => existsSync(join(repository, path)))
    .sort();
}

const files = repositoryFiles();
const rootDocuments = files.filter((path) => dirname(path) === ".");
const errors: string[] = [];

for (const path of rootDocuments) {
  if (!rootAllowlist.has(path)) errors.push(`unexpected root AsciiDoc file: ${path}`);
}
for (const required of rootAllowlist) {
  if (!rootDocuments.includes(required)) errors.push(`required root contract is missing: ${required}`);
}
if (existsSync(join(repository, "doc"))) errors.push("legacy doc/ directory must not return");

let links = 0;
for (const path of files) {
  const content = await readFile(join(repository, path), "utf8");
  for (const match of content.matchAll(/xref:([^\[\s]+)\[/g)) {
    const rawTarget = match[1];
    if (rawTarget === undefined || /^(?:https?:|mailto:|#)/.test(rawTarget)) continue;
    const target = rawTarget.split("#", 1)[0];
    if (target === undefined || !target.endsWith(".adoc") || target.includes("{")) continue;
    links += 1;
    const resolved = normalize(join(repository, dirname(path), target));
    if (!insideRepository(resolved)) {
      errors.push(`${path}: xref escapes repository: ${rawTarget}`);
    } else if (!existsSync(resolved)) {
      errors.push(`${path}: missing xref target: ${rawTarget}`);
    }
  }
}

if (errors.length > 0) {
  for (const error of [...new Set(errors)].sort()) console.error(error);
  process.exit(1);
}

console.log(`docs=passed files=${files.length} xrefs=${links} root-documents=${rootDocuments.length}`);
