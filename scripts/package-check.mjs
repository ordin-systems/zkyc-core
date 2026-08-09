import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("..", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const packages = [
  { directory: ".", workspace: undefined, extra: [] },
  { directory: "apps/core-api", workspace: "@ordin/zkyc-core-api-reference", extra: ["dist/src/server.js"] },
  { directory: "packages/sdk", workspace: "@ordin/zkyc-sdk-reference", extra: [] },
];

function run(command, argumentsList, cwd) {
  const result = spawnSync(command, argumentsList, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} ${argumentsList.join(" ")} failed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

for (const specification of packages) {
  const manifest = JSON.parse(await readFile(join(repository, specification.directory, "package.json"), "utf8"));
  const argumentsList = ["pack", "--dry-run", "--json"];
  if (specification.workspace !== undefined) argumentsList.push("--workspace", specification.workspace);
  const parsed = JSON.parse(run(npmCommand, argumentsList, repository));
  const files = new Set(parsed[0]?.files?.map((entry) => entry.path) ?? []);
  const required = [manifest.main, manifest.types, ...specification.extra]
    .map((path) => String(path).replace(/^\.\//, ""));
  const missing = required.filter((path) => !files.has(path));
  if (missing.length > 0) {
    throw new Error(`${manifest.name} package is missing declared artifacts: ${missing.join(", ")}`);
  }
}

const temporary = await mkdtemp(join(tmpdir(), "zkyc-package-check-"));
try {
  const coreArchive = run(npmCommand, ["pack", "--silent", "--pack-destination", temporary], repository)
    .split("\n").at(-1);
  const apiArchive = run(
    npmCommand,
    ["pack", "--silent", "--workspace", "@ordin/zkyc-core-api-reference", "--pack-destination", temporary],
    repository,
  ).split("\n").at(-1);
  if (coreArchive === undefined || apiArchive === undefined) throw new Error("package archive name was not returned");

  const consumer = join(temporary, "consumer");
  await mkdir(consumer);
  await writeFile(
    join(consumer, "package.json"),
    `${JSON.stringify({ name: "zkyc-package-consumer", version: "1.0.0", private: true, type: "module" })}\n`,
    "utf8",
  );
  run(
    npmCommand,
    [
      "install", "--prefer-offline", "--ignore-scripts", "--package-lock=false",
      join(temporary, coreArchive), join(temporary, apiArchive),
    ],
    consumer,
  );
  run(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "const api = await import('@ordin/zkyc-core-api-reference'); if (typeof api.createReferenceApp !== 'function') process.exit(1);",
    ],
    consumer,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log("package:check passed");
