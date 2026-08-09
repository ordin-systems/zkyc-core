import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scanner = fileURLToPath(new URL("./security-check.mjs", import.meta.url));

test("publication scanner content-scans extensionless hidden files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkyc-security-check-"));
  try {
    const token = `${"gh"}${"p_"}${"A".repeat(24)}`;
    const privatePath = `/${["Users", "reviewer", "private", "file"].join("/")}`;
    await writeFile(join(directory, ".credentials"), `${token}\n${privatePath}\n`, "utf8");
    const result = spawnSync(process.execPath, [scanner, directory], { encoding: "utf8" });
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(result.status, 1);
    assert.match(output, /\.credentials: GitHub classic token/);
    assert.match(output, /\.credentials: absolute macOS private path/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
