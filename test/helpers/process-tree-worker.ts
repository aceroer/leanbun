const pidFile = process.argv[2];
const ignoreTermination = process.argv[3] === "ignore-term";
if (pidFile === undefined) throw new Error("process-tree-worker requires a pid file");
if (ignoreTermination) process.on("SIGTERM", () => undefined);

const child = Bun.spawn({
  cmd: ["/bin/sleep", "30"],
  stdin: null,
  stdout: "ignore",
  stderr: "ignore",
});
await Bun.write(pidFile, `${child.pid}\n`);
await child.exited;
await new Promise(() => undefined);
