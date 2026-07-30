import { test } from "bun:test";
import { join } from "node:path";

test("intentional process-supervisor hang", async () => {
  const developmentRoot = process.env.LEANBUN_DEV_ROOT;
  if (developmentRoot === undefined) throw new Error("LEANBUN_DEV_ROOT is required");
  process.on("SIGTERM", () => undefined);
  const child = Bun.spawn({
    cmd: ["/bin/sleep", "30"],
    stdin: null,
    stdout: "ignore",
    stderr: "ignore",
  });
  await Bun.write(join(developmentRoot, "tmp/supervisor-regression-child.pid"), `${child.pid}\n`);
  await new Promise(() => undefined);
});
