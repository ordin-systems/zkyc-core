import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTarGz } from "./archive-utils.mjs";
import { collectManifestTargets, readManifest } from "./package-utils.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
export const packageSpecifications = [
  {
    directory: ".",
    workspace: undefined,
    sourceDirectory: "src",
    outputDirectory: "dist/src",
    staticDirectories: ["fixtures"],
    declaredFiles: ["dist/src", "fixtures"],
  },
  {
    directory: "apps/core-api",
    workspace: "@ordin/zkyc-core-api-reference",
    sourceDirectory: "src",
    outputDirectory: "dist/src",
    staticDirectories: [],
    declaredFiles: ["dist/src"],
  },
  {
    directory: "packages/sdk",
    workspace: "@ordin/zkyc-sdk-reference",
    sourceDirectory: "src",
    outputDirectory: "dist/src",
    staticDirectories: [],
    declaredFiles: ["dist/src"],
  },
];
const uiSpecifications = ["apps/operator-ui", "apps/zkya-onboarding"];

function run(command, argumentsList, cwd) {
  const result = spawnSync(command, argumentsList, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${command} ${argumentsList.join(" ")} failed (${String(result.status)}):\n${result.stdout}${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

async function regularFiles(root, directory = root) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`symbolic link is forbidden while deriving package files: ${path}`);
    if (entry.isDirectory()) files.push(...await regularFiles(root, path));
    else if (entry.isFile()) files.push(relative(root, path).split(sep).join("/"));
    else throw new Error(`non-regular package source is forbidden: ${path}`);
  }
  return files;
}

function compiledOutputs(sourcePath, sourceDirectory, outputDirectory) {
  const extension = extname(sourcePath);
  const relativeSource = sourcePath.slice(sourceDirectory.length + 1);
  const stem = relativeSource.slice(0, -extension.length);
  if (extension === ".ts" || extension === ".tsx") return [`${outputDirectory}/${stem}.js`, `${outputDirectory}/${stem}.d.ts`];
  if (extension === ".mts") return [`${outputDirectory}/${stem}.mjs`, `${outputDirectory}/${stem}.d.mts`];
  if (extension === ".cts") return [`${outputDirectory}/${stem}.cjs`, `${outputDirectory}/${stem}.d.cts`];
  throw new Error(`unsupported compiled source extension: ${sourcePath}`);
}

export async function expectedPackageMembers(specification, packageRoot) {
  const expected = new Set(["package/package.json"]);
  const sourceRoot = join(packageRoot, specification.sourceDirectory);
  for (const sourcePath of await regularFiles(packageRoot, sourceRoot)) {
    for (const output of compiledOutputs(sourcePath, specification.sourceDirectory, specification.outputDirectory)) {
      expected.add(`package/${output}`);
    }
  }
  for (const staticDirectory of specification.staticDirectories) {
    for (const path of await regularFiles(packageRoot, join(packageRoot, staticDirectory))) expected.add(`package/${path}`);
  }
  for (const entry of await readdir(packageRoot, { withFileTypes: true })) {
    if (entry.isFile() && /^(?:readme|license|licence|copying)(?:\.|$)/i.test(entry.name)) {
      expected.add(`package/${entry.name}`);
    }
  }
  return expected;
}

function compareSets(actual, expected, label) {
  const missing = [...expected].filter((entry) => !actual.has(entry)).sort();
  const unexpected = [...actual].filter((entry) => !expected.has(entry)).sort();
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} archive member mismatch; missing=[${missing.join(", ")}], unexpected=[${unexpected.join(", ")}]`,
    );
  }
}

export async function inspectPackageArchive(archivePath, specification, repositoryRoot = repository) {
  const packageRoot = resolve(repositoryRoot, specification.directory);
  const manifest = await readManifest(join(packageRoot, "package.json"));
  if (!Array.isArray(manifest.files) || manifest.files.some((entry) => typeof entry !== "string")) {
    throw new Error(`${manifest.name} must declare a string-only files allowlist`);
  }
  compareSets(new Set(manifest.files), new Set(specification.declaredFiles), `${manifest.name} manifest files`);

  const entries = parseTarGz(await readFile(archivePath), archivePath);
  if (entries.some((entry) => entry.type !== "file")) throw new Error(`${manifest.name} archive contains non-file members`);
  for (const entry of entries) {
    if ((entry.mode & 0o022) !== 0) throw new Error(`${manifest.name} archive has a writable member: ${entry.name}`);
  }
  const members = new Set(entries.map((entry) => entry.name));
  compareSets(members, await expectedPackageMembers(specification, packageRoot), manifest.name);

  const packedManifestEntry = entries.find((entry) => entry.name === "package/package.json");
  if (packedManifestEntry === undefined) throw new Error(`${manifest.name} archive has no package manifest`);
  let packedManifest;
  try {
    packedManifest = JSON.parse(packedManifestEntry.content.toString("utf8"));
  } catch (error) {
    throw new Error(`${manifest.name} archive manifest cannot be parsed: ${error.message}`);
  }
  if (packedManifest.name !== manifest.name || packedManifest.version !== manifest.version) {
    throw new Error(`${manifest.name} archive manifest identity does not match its source manifest`);
  }
  for (const [label, checkedManifest] of [["source", manifest], ["packed", packedManifest]]) {
    for (const target of collectManifestTargets(checkedManifest)) {
      if (!members.has(`package/${target}`)) {
        throw new Error(`${manifest.name} is missing ${label} manifest target: ${target}`);
      }
    }
  }
  return manifest;
}

function localAssetPath(reference) {
  if (/^(?:[A-Za-z][A-Za-z+.-]*:|\/\/)/.test(reference)) throw new Error(`external asset URL is forbidden: ${reference}`);
  const withoutSuffix = reference.split(/[?#]/, 1)[0];
  const decoded = decodeURIComponent(withoutSuffix).replace(/^\//, "");
  if (decoded === "" || decoded === ".." || decoded.startsWith("../") || decoded.includes("\\")) {
    throw new Error(`unsafe local asset path: ${reference}`);
  }
  return decoded;
}

async function verifyLocalUiResource(outputRoot, reference, label, allowData = false, baseRoot = outputRoot) {
  if (allowData && /^data:/i.test(reference)) return undefined;
  if (reference.startsWith("#")) return undefined;
  const asset = localAssetPath(reference);
  const assetPath = resolve(reference.startsWith("/") ? outputRoot : baseRoot, asset);
  const display = relative(outputRoot, assetPath);
  if (display === ".." || display.startsWith(`..${sep}`)) throw new Error(`${label} escapes dist: ${reference}`);
  let status;
  try {
    status = await stat(assetPath);
  } catch (error) {
    throw new Error(`${label} references a missing asset: ${asset} (${error.code ?? error.message})`);
  }
  if (!status.isFile()) throw new Error(`${label} does not reference a regular file: ${asset}`);
  return asset;
}

async function inspectCssResources(content, outputRoot, label, baseRoot = outputRoot) {
  const references = [];
  for (const match of content.matchAll(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi)) references.push(match[2].trim());
  for (const match of content.matchAll(/@import\s+(?:url\(\s*)?["']([^"']+)["']/gi)) references.push(match[1].trim());
  for (const reference of references) await verifyLocalUiResource(outputRoot, reference, label, true, baseRoot);
}

function inspectJavaScriptRuntimeTargets(content, label) {
  const patterns = [
    /\b(?:fetch|importScripts|import)\s*\(\s*["'`]((?:https?:)?\/\/[^"'`]+)["'`]/gi,
    /\bnew\s+(?:WebSocket|EventSource|Worker|SharedWorker)\s*\(\s*["'`]((?:https?:)?\/\/[^"'`]+)["'`]/gi,
    /\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]((?:https?:)?\/\/[^"'`]+)["'`]/gi,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (match !== null) throw new Error(`${label} contains an external runtime target: ${match[1]}`);
  }
}

export async function verifyUiBuild(directory, repositoryRoot = repository) {
  const outputRoot = join(repositoryRoot, directory, "dist");
  const indexPath = join(outputRoot, "index.html");
  const html = await readFile(indexPath, "utf8");
  const assets = [];
  for (const match of html.matchAll(/<(script|link|img|source)\b([^>]*)>/gi)) {
    const [, tag, attributes] = match;
    for (const attribute of attributes.matchAll(/\b(src|href)=["']([^"']+)["']/gi)) {
      const asset = await verifyLocalUiResource(outputRoot, attribute[2], `${directory} <${tag}>`);
      if (asset !== undefined && (tag.toLowerCase() === "script" || tag.toLowerCase() === "link")) assets.push(asset);
    }
    for (const attribute of attributes.matchAll(/\bsrcset=["']([^"']+)["']/gi)) {
      for (const candidate of attribute[1].split(",")) {
        const reference = candidate.trim().split(/\s+/, 1)[0];
        await verifyLocalUiResource(outputRoot, reference, `${directory} <${tag}> srcset`);
      }
    }
  }
  if (!assets.some((asset) => asset.endsWith(".js"))) throw new Error(`${directory} has no local production JavaScript asset`);
  if (!assets.some((asset) => asset.endsWith(".css"))) throw new Error(`${directory} has no local production CSS asset`);

  for (const path of await regularFiles(outputRoot)) {
    if (!new Set([".css", ".html", ".js"]).has(extname(path))) continue;
    const content = await readFile(join(outputRoot, path), "utf8");
    const label = `${directory}/dist/${path}`;
    if (extname(path) === ".css" || extname(path) === ".html") {
      await inspectCssResources(content, outputRoot, label, join(outputRoot, dirname(path)));
    }
    if (extname(path) === ".js" || extname(path) === ".html") inspectJavaScriptRuntimeTargets(content, label);
  }
}

async function freePort() {
  return await new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.unref();
    server.once("error", rejectPort);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        rejectPort(new Error("failed to reserve loopback port"));
        return;
      }
      server.close((error) => error === undefined ? resolvePort(address.port) : rejectPort(error));
    });
  });
}

async function probeInstalledServer(consumer) {
  const port = await freePort();
  const serverPath = join(consumer, "node_modules", "@ordin", "zkyc-core-api-reference", "dist", "src", "server.js");
  const child = spawn(process.execPath, [serverPath], {
    cwd: consumer,
    env: {
      ...process.env,
      PORT: String(port),
      ZKYC_RECEIPT_HMAC_KEY: "reference-package-check-key-32-bytes-minimum",
      ZKYC_ISSUER_ID: "issuer:package-check",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const closed = new Promise((resolveClose) => child.once("close", resolveClose));
  try {
    const deadline = Date.now() + 10_000;
    let lastError;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error(`installed API server exited before readiness:\n${output}`);
      try {
        const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1_000) });
        const body = await response.text();
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const parsed = JSON.parse(body);
        if (parsed.ok !== true) throw new Error("health response did not report ok");
        return;
      } catch (error) {
        lastError = error;
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 100));
    }
    throw new Error(`installed API server did not become ready: ${String(lastError)}\n${output}`);
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
    if (await Promise.race([closed.then(() => true), new Promise((resolveWait) => setTimeout(() => resolveWait(false), 2_000))]) === false) {
      child.kill("SIGKILL");
      await Promise.race([closed, new Promise((resolveWait) => setTimeout(resolveWait, 2_000))]);
    }
  }
}

export async function runPackageCheck(repositoryRoot = repository) {
  run(npmCommand, ["run", "build:all", "--silent"], repositoryRoot);
  for (const directory of uiSpecifications) await verifyUiBuild(directory, repositoryRoot);

  const temporary = await mkdtemp(join(tmpdir(), "zkyc-package-check-"));
  try {
    const archives = [];
    for (const specification of packageSpecifications) {
      const argumentsList = ["pack", "--silent", "--pack-destination", temporary];
      if (specification.workspace !== undefined) argumentsList.push("--workspace", specification.workspace);
      const archiveName = run(npmCommand, argumentsList, repositoryRoot).split("\n").at(-1);
      if (archiveName === undefined || archiveName.length === 0) throw new Error("npm pack did not return an archive name");
      const archivePath = join(temporary, archiveName);
      await inspectPackageArchive(archivePath, specification, repositoryRoot);
      archives.push(archivePath);
    }

    const consumer = join(temporary, "consumer");
    await mkdir(consumer);
    await writeFile(
      join(consumer, "package.json"),
      `${JSON.stringify({ name: "zkyc-package-consumer", version: "1.0.0", private: true, type: "module" })}\n`,
      "utf8",
    );
    run(
      npmCommand,
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", ...archives],
      consumer,
    );
    run(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        [
          "const core = await import('@ordin/zkyc-core-reference');",
          "const api = await import('@ordin/zkyc-core-api-reference');",
          "const sdk = await import('@ordin/zkyc-sdk-reference');",
          "if (typeof core.canonicalJson !== 'function') process.exit(1);",
          "if (typeof api.createReferenceApp !== 'function') process.exit(1);",
          "if (typeof sdk.ZkycReferenceClient !== 'function') process.exit(1);",
        ].join(" "),
      ],
      consumer,
    );
    await probeInstalledServer(consumer);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runPackageCheck();
  console.log("package:check passed");
}
