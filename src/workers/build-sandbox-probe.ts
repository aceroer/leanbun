import { unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

async function writeProbe(path: string): Promise<"allowed" | "denied"> {
  try {
    await writeFile(path, "leanbun-sandbox-probe\n", { flag: "wx" });
    await unlink(path);
    return "allowed";
  } catch {
    return "denied";
  }
}

const project = process.env.LEANBUN_PROBE_PROJECT!;
const buildRoot = process.env.LEANBUN_PROBE_BUILD_ROOT!;
const configRoot = process.env.LEANBUN_PROBE_CONFIG_ROOT!;
const tempRoot = process.env.LEANBUN_PROBE_TEMP_ROOT!;
const protectedRoots = JSON.parse(process.env.LEANBUN_PROBE_PROTECTED_ROOTS!) as string[];
const nonce = crypto.randomUUID();
let networkListen: "allowed" | "denied" = "denied";
try {
  const server = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: { data() {} },
  });
  networkListen = "allowed";
  server.stop(true);
} catch {
  networkListen = "denied";
}

const result = {
  projectBuildWrite: await writeProbe(join(buildRoot, `.probe-${nonce}`)),
  projectConfigWrite: await writeProbe(join(configRoot, `.probe-${nonce}`)),
  controlTempWrite: await writeProbe(join(tempRoot, `.probe-${nonce}`)),
  projectSourceWrite: await writeProbe(join(project, `.probe-${nonce}`)),
  projectControlWrite: await writeProbe(join(project, ".leanbun", `.probe-${nonce}`)),
  protectedWrites: await Promise.all(
    protectedRoots.map((root) => writeProbe(join(root, `.probe-${nonce}`))),
  ),
  networkListen,
};
process.stdout.write(`${JSON.stringify(result)}\n`);
