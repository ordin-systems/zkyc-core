import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { chmod, copyFile, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const scanner = fileURLToPath(new URL("./security-check.mjs", import.meta.url));
const archiveUtils = fileURLToPath(new URL("./archive-utils.mjs", import.meta.url));

function tarArchive(entries) {
  const blocks = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.content ?? "", "utf8");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.fill(0x20, 148, 156);
    header[156] = (entry.type ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    const checksum = header.reduce((sum, value) => sum + value, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    blocks.push(header, content, Buffer.alloc((512 - (content.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

async function withDirectory(callback) {
  const directory = await mkdtemp(join(tmpdir(), "zkyc-security-check-"));
  try {
    return await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function scan(directory, scannerPath = scanner, includeRoot = true) {
  return spawnSync(process.execPath, includeRoot ? [scannerPath, directory] : [scannerPath], { encoding: "utf8" });
}

function output(result) {
  return `${result.stdout}${result.stderr}`;
}

test("publication scanner finds nested extensionless secrets and private paths", async () => {
  await withDirectory(async (directory) => {
    const nested = join(directory, "nested", "deeper");
    await mkdir(nested, { recursive: true });
    const token = `${"gh"}${"p_"}${"A".repeat(24)}`;
    const privatePath = `/${["Users", "reviewer", "private", "file"].join("/")}`;
    await writeFile(join(nested, ".credentials"), `${token}\n${privatePath}\n`, "utf8");
    const result = scan(directory);
    assert.equal(result.status, 1);
    assert.match(output(result), /nested[/\\]deeper[/\\]\.credentials/);
  });
});

test("publication scanner rejects nested symlinks, generated caches, bytecode, and local credentials", async (context) => {
  if (process.platform === "win32") context.skip("symlink creation is privilege-dependent on Windows");
  await withDirectory(async (directory) => {
    await mkdir(join(directory, "nested", "__pycache__"), { recursive: true });
    await writeFile(join(directory, "nested", "__pycache__", "module.pyc"), "generated", "utf8");
    await writeFile(join(directory, "nested", ".npmrc"), "registry=https://example.invalid", "utf8");
    await symlink(join(directory, "nested", ".npmrc"), join(directory, "nested", "benign-link"));
    const result = scan(directory);
    assert.equal(result.status, 1);
    assert.match(output(result), /benign-link/);
    assert.match(output(result), /__pycache__/);
    assert.match(output(result), /\.npmrc/);
  });
});

test("publication scanner fails closed on malformed, unsafe, and secret-bearing tgz exports", async () => {
  await withDirectory(async (directory) => {
    const token = `${"sk-"}${"B".repeat(24)}`;
    await writeFile(join(directory, "malformed.tgz"), "not gzip", "utf8");
    await writeFile(join(directory, "traversal.tgz"), tarArchive([{ name: "../escape", content: "clean" }]));
    await writeFile(join(directory, "link.tgz"), tarArchive([{ name: "package/link", type: "2" }]));
    await writeFile(join(directory, "export.tgz"), tarArchive([{ name: "package/nested/.credentials", content: token }]));
    const result = scan(directory);
    assert.equal(result.status, 1);
    for (const name of ["malformed.tgz", "traversal.tgz", "link.tgz", "export.tgz"]) {
      assert.match(output(result), new RegExp(name.replace(".", "\\.")));
    }
  });
});

test("publication scanner exits nonzero for an unreadable regular file", { skip: process.getuid?.() === 0 }, async () => {
  await withDirectory(async (directory) => {
    const path = join(directory, "nested.txt");
    await writeFile(path, "clean", "utf8");
    await chmod(path, 0);
    try {
      const result = scan(directory);
      assert.equal(result.status, 1);
      assert.match(output(result), /nested\.txt/);
    } finally {
      await chmod(path, constants.S_IRUSR | constants.S_IWUSR);
    }
  });
});

test("publication scanner ignores only a valid root gitdir pointer and rejects nested git metadata", async () => {
  await withDirectory(async (directory) => {
    await mkdir(join(directory, "administrative-gitdir"));
    await writeFile(join(directory, ".git"), "gitdir: administrative-gitdir\n", "utf8");
    await mkdir(join(directory, "nested", ".git"), { recursive: true });
    await writeFile(join(directory, "nested", ".git", "config"), "safe\n", "utf8");
    const result = scan(directory);
    assert.equal(result.status, 1);
    assert.match(output(result), /nested[/\\]\.git: nested git metadata is forbidden/);
    assert.doesNotMatch(output(result), /^\.git:/m);
  });
});

test("publication scanner rejects malformed root gitdir pointers", async () => {
  await withDirectory(async (directory) => {
    await writeFile(join(directory, ".git"), "gitdir: missing-administrative-directory\n", "utf8");
    const result = scan(directory);
    assert.equal(result.status, 1);
    assert.match(output(result), /^\.git: malformed gitdir administrative pointer$/m);
  });
});

test("publication scripts resolve their own roots when the checkout path contains spaces", async () => {
  await withDirectory(async (temporary) => {
    const project = join(temporary, "project with spaces");
    const scripts = join(project, "scripts");
    await mkdir(scripts, { recursive: true });
    await copyFile(scanner, join(scripts, "security-check.mjs"));
    await copyFile(archiveUtils, join(scripts, "archive-utils.mjs"));
    await writeFile(join(project, "safe.txt"), "safe\n", "utf8");
    const result = scan(project, join(scripts, "security-check.mjs"), false);
    assert.equal(result.status, 0, output(result));
  });
});
