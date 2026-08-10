import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";
import { parseTarGz } from "./archive-utils.mjs";
import { inspectPackageArchive, verifyUiBuild } from "./package-check.mjs";
import { readManifest } from "./package-utils.mjs";

const cleanScript = fileURLToPath(new URL("./clean.mjs", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const packageSpecification = {
  directory: ".",
  workspace: undefined,
  sourceDirectory: "src",
  outputDirectory: "dist/src",
  staticDirectories: [],
  declaredFiles: ["dist/src"],
};

function tarArchive(entries) {
  const blocks = [];
  for (const entry of entries) {
    const content = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content ?? "", "utf8");
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

async function withTemporaryDirectory(callback) {
  const directory = await mkdtemp(join(tmpdir(), "zkyc release tooling with spaces "));
  try {
    return await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function manifest(exportsValue = {
  ".": {
    types: "./dist/src/index.d.ts",
    import: "./dist/src/index.js",
  },
}) {
  return {
    name: "@ordin/test-release-package",
    version: "0.3.0",
    type: "module",
    main: "./dist/src/index.js",
    types: "./dist/src/index.d.ts",
    exports: exportsValue,
    files: ["dist/src"],
  };
}

async function writePackageFixture(root, packageManifest = manifest()) {
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(join(root, "src", "index.ts"), "export const value = 1;\n", "utf8");
  await writeFile(join(root, "package.json"), `${JSON.stringify(packageManifest)}\n`, "utf8");
}

function packageEntries(packageManifest = manifest(), extra = []) {
  return [
    { name: "package/package.json", content: `${JSON.stringify(packageManifest)}\n` },
    { name: "package/dist/src/index.js", content: "export const value = 1;\n" },
    { name: "package/dist/src/index.d.ts", content: "export declare const value = 1;\n" },
    ...extra,
  ];
}

function run(command, argumentsList, cwd) {
  const result = spawnSync(command, argumentsList, { cwd, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.status, 0, `${command} ${argumentsList.join(" ")} failed:\n${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

test("package inspection rejects nested missing export targets", async () => {
  await withTemporaryDirectory(async (root) => {
    const packageManifest = manifest({
      ".": { import: "./dist/src/index.js" },
      "./nested": { import: "./dist/src/missing.js" },
    });
    await writePackageFixture(root, packageManifest);
    const archive = join(root, "package.tgz");
    await writeFile(archive, tarArchive(packageEntries(packageManifest)));
    await assert.rejects(
      inspectPackageArchive(archive, packageSpecification, root),
      /missing source manifest target: dist\/src\/missing\.js/,
    );
  });
});

test("manifest and archive parsers fail closed on malformed input", async () => {
  await withTemporaryDirectory(async (root) => {
    const manifestPath = join(root, "package.json");
    await writeFile(manifestPath, "{ not json\n", "utf8");
    await assert.rejects(readManifest(manifestPath), /cannot parse package manifest/);
    assert.throws(() => parseTarGz(Buffer.from("not a gzip archive"), "malformed.tgz"), /not a valid bounded gzip archive/);
    assert.throws(
      () => parseTarGz(tarArchive([{ name: "../escape", content: "unsafe" }]), "unsafe.tgz"),
      /unsafe path/,
    );
  });
});

test("archive parser accepts zero member padding and rejects nonzero member padding", () => {
  const valid = tarArchive([{ name: "package/file.txt", content: "x" }]);
  assert.equal(parseTarGz(valid, "valid-padding.tgz")[0]?.content.toString("utf8"), "x");

  const malformedTar = gunzipSync(valid);
  const paddingToken = Buffer.from(`${"sk-"}${"Q".repeat(24)}`, "utf8");
  paddingToken.copy(malformedTar, 513);
  const malformed = gzipSync(malformedTar);
  assert.throws(
    () => parseTarGz(malformed, "nonzero-padding.tgz"),
    /nonzero-padding\.tgz has nonzero tar member padding: package\/file\.txt/,
  );
});

test("package inspection rejects malformed packed manifests and stale dist members", async () => {
  await withTemporaryDirectory(async (root) => {
    const packageManifest = manifest();
    await writePackageFixture(root, packageManifest);
    const malformedArchive = join(root, "malformed-manifest.tgz");
    await writeFile(malformedArchive, tarArchive(packageEntries(packageManifest).map((entry) =>
      entry.name === "package/package.json" ? { ...entry, content: "{ broken" } : entry)));
    await assert.rejects(
      inspectPackageArchive(malformedArchive, packageSpecification, root),
      /archive manifest cannot be parsed/,
    );

    const staleArchive = join(root, "stale.tgz");
    await writeFile(staleArchive, tarArchive(packageEntries(packageManifest, [
      { name: "package/dist/src/stale.js", content: "stale\n" },
    ])));
    await assert.rejects(
      inspectPackageArchive(staleArchive, packageSpecification, root),
      /unexpected=\[package\/dist\/src\/stale\.js\]/,
    );
  });
});

test("portable clean removes stale dist in a path with spaces and refuses escapes", async () => {
  await withTemporaryDirectory(async (root) => {
    await mkdir(join(root, "dist", "nested"), { recursive: true });
    await writeFile(join(root, "dist", "nested", "stale.js"), "stale\n", "utf8");
    run(process.execPath, [cleanScript, "dist"], root);
    await assert.rejects(access(join(root, "dist")), { code: "ENOENT" });
    const escaped = spawnSync(process.execPath, [cleanScript, "../outside"], { cwd: root, encoding: "utf8" });
    assert.notEqual(escaped.status, 0);
    assert.match(`${escaped.stdout}${escaped.stderr}`, /outside its working directory/);
  });
});

test("blank consumer installs and imports an SDK archive from a path with spaces", async () => {
  await withTemporaryDirectory(async (root) => {
    const sdk = join(root, "sdk package");
    const artifacts = join(root, "packed artifacts");
    const consumer = join(root, "blank consumer");
    await mkdir(join(sdk, "dist", "src"), { recursive: true });
    await mkdir(artifacts);
    await mkdir(consumer);
    const sdkManifest = {
      name: "@ordin/zkyc-sdk-reference",
      version: "0.3.0",
      type: "module",
      main: "./dist/src/index.js",
      types: "./dist/src/index.d.ts",
      exports: { ".": { types: "./dist/src/index.d.ts", import: "./dist/src/index.js" } },
      files: ["dist/src"],
    };
    await writeFile(join(sdk, "package.json"), `${JSON.stringify(sdkManifest)}\n`, "utf8");
    await writeFile(join(sdk, "dist", "src", "index.js"), "export class ZkycReferenceClient {}\n", "utf8");
    await writeFile(
      join(sdk, "dist", "src", "index.d.ts"),
      "export declare class ZkycReferenceClient {}\n",
      "utf8",
    );
    const archiveName = run(npmCommand, ["pack", "--silent", "--pack-destination", artifacts], sdk)
      .split("\n").at(-1);
    assert.ok(archiveName);
    await writeFile(
      join(consumer, "package.json"),
      `${JSON.stringify({ name: "blank-consumer", private: true, type: "module" })}\n`,
      "utf8",
    );
    run(
      npmCommand,
      [
        "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false",
        join(artifacts, archiveName),
      ],
      consumer,
    );
    run(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        "const sdk = await import('@ordin/zkyc-sdk-reference'); if (typeof sdk.ZkycReferenceClient !== 'function') process.exit(1);",
      ],
      consumer,
    );
  });
});

test("UI build verification accepts namespace constants and rejects external runtime resources", async () => {
  await withTemporaryDirectory(async (root) => {
    const ui = join(root, "apps", "ui", "dist");
    const assets = join(ui, "assets");
    await mkdir(assets, { recursive: true });
    const safeHtml = [
      "<!doctype html>",
      '<link rel="stylesheet" href="/assets/index.css">',
      '<img src="/assets/logo.svg">',
      '<script type="module" src="/assets/index.js"></script>',
      "",
    ].join("\n");
    const safeJavaScript = [
      'const namespaces = ["http://www.w3.org/1998/Math/MathML", "http://www.w3.org/2000/svg"];',
      'void namespaces; fetch("/api/health");',
      "",
    ].join("\n");
    const safeCss = '@font-face { src: url("./font.woff2"); }\n';
    await writeFile(join(ui, "index.html"), safeHtml, "utf8");
    await writeFile(join(assets, "index.js"), safeJavaScript, "utf8");
    await writeFile(join(assets, "index.css"), safeCss, "utf8");
    await writeFile(join(assets, "logo.svg"), "<svg/>\n", "utf8");
    await writeFile(join(assets, "font.woff2"), "font\n", "utf8");
    await verifyUiBuild("apps/ui", root);

    await writeFile(join(assets, "index.js"), 'fetch("https://example.invalid/data");\n', "utf8");
    await assert.rejects(verifyUiBuild("apps/ui", root), /external runtime target/);
    await writeFile(join(assets, "index.js"), safeJavaScript, "utf8");

    await writeFile(join(assets, "index.css"), 'body { background: url("https://example.invalid/a.png"); }\n', "utf8");
    await assert.rejects(verifyUiBuild("apps/ui", root), /external asset URL/);
    await writeFile(join(assets, "index.css"), safeCss, "utf8");

    for (const markup of [
      '<script src="https://example.invalid/app.js"></script>',
      '<link rel="stylesheet" href="https://example.invalid/app.css">',
      '<img src="https://example.invalid/image.png">',
    ]) {
      await writeFile(join(ui, "index.html"), `${safeHtml}${markup}\n`, "utf8");
      await assert.rejects(verifyUiBuild("apps/ui", root), /external asset URL/);
    }
  });
});
