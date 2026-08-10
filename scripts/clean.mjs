import { rm } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

if (process.argv.length < 3) throw new Error("clean requires at least one generated path");

const root = resolve(process.cwd());
for (const requested of process.argv.slice(2)) {
  if (isAbsolute(requested)) throw new Error(`clean refuses absolute path: ${requested}`);
  const target = resolve(root, requested);
  const display = relative(root, target);
  if (display === "" || display === ".." || display.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) {
    throw new Error(`clean refuses path outside its working directory: ${requested}`);
  }
  await rm(target, { recursive: true, force: true, maxRetries: 3 });
}
