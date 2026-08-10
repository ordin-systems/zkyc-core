import { constants } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { basename, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTarGz } from "./archive-utils.mjs";

const defaultRoot = fileURLToPath(new URL("..", import.meta.url));
const thisFile = fileURLToPath(import.meta.url);
const ignoredDirectories = new Set(["node_modules", "dist", "coverage"]);
const generatedDirectories = new Set(["__pycache__", ".cache", ".mypy_cache", ".pytest_cache", ".ruff_cache"]);
const generatedExtensions = new Set([".pyc", ".pyo"]);
const forbiddenNames = new Set([
  ".env",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".yarnrc",
  "credentials",
  "credentials.json",
  "id_ed25519",
  "id_rsa",
  "service-account.json",
]);
const forbiddenExtensions = new Set([".key", ".p12", ".pem", ".pfx"]);
const textExtensions = new Set([
  ".css", ".html", ".js", ".json", ".jsx", ".md", ".mjs", ".mts", ".ts", ".tsx", ".txt", ".yaml", ".yml",
]);
const codeExtensions = new Set([".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]);
const codeRoots = ["src", "apps", "packages"];
const defaultArchiveLimits = Object.freeze({
  maximumArchiveDepth: 3,
  maximumCumulativeDecompressedBytes: 256 * 1024 * 1024,
  maximumCumulativeMemberBytes: 256 * 1024 * 1024,
});
const forbiddenPatterns = [
  { label: "absolute macOS private path", pattern: /\/Users\/[A-Za-z0-9._-]+\// },
  { label: "absolute Windows private path", pattern: /[A-Za-z]:\\Users\\[^\\]+\\/ },
  { label: "private key material", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { label: "GitHub classic token", pattern: /gh[pousr]_[A-Za-z0-9]{20,}/ },
  { label: "GitHub fine-grained token", pattern: /github_pat_[A-Za-z0-9_]{20,}/ },
  { label: "AWS access key", pattern: /AKIA[0-9A-Z]{16}/ },
  { label: "OpenAI-style secret", pattern: /sk-[A-Za-z0-9_-]{20,}/ },
  { label: "live connection string", pattern: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s:@]+:[^\s@]+@/i },
  { label: "x402/payment execution surface", pattern: /(?:wrapFetchWithPayment|privateKeyToAccount|executeRefund|sendRefundViaX402)/, codeOnly: true },
  { label: "external model authority surface", pattern: /(?:api\.groq\.com|chat\.completions\.create|new OpenAI\s*\()/, codeOnly: true },
];

function isForbiddenFilename(filename) {
  const lower = filename.toLowerCase();
  return lower === ".env" || lower.startsWith(".env.") || forbiddenNames.has(lower) ||
    forbiddenExtensions.has(extname(lower));
}

function isTextCandidate(path, content) {
  const extension = extname(path).toLowerCase();
  if (textExtensions.has(extension) || extension === "") return true;
  return !content.subarray(0, 8_192).includes(0);
}

function scanContent(content, display, failures, archiveMember = false) {
  if (!isTextCandidate(display, content)) return;
  const text = content.toString("utf8");
  const normalizedDisplay = display.split("/").join(sep);
  const isWorkspaceCode = !archiveMember && codeExtensions.has(extname(display).toLowerCase()) &&
    codeRoots.some((codeRoot) => normalizedDisplay.startsWith(`${codeRoot}${sep}`));
  for (const { label, pattern, codeOnly = false } of forbiddenPatterns) {
    if (codeOnly && !isWorkspaceCode) continue;
    if (pattern.test(text)) failures.push(`${display}: ${label}`);
  }
}

async function readRegularFile(path) {
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const status = await handle.stat();
    if (!status.isFile()) throw new Error("not a regular file");
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

function archiveLimits(options) {
  const limits = { ...defaultArchiveLimits };
  for (const [name, minimum] of [
    ["maximumArchiveDepth", 0],
    ["maximumCumulativeDecompressedBytes", 1],
    ["maximumCumulativeMemberBytes", 1],
  ]) {
    const value = options[name] ?? limits[name];
    if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`invalid archive scanner limit: ${name}`);
    limits[name] = value;
  }
  return limits;
}

function scanArchive(content, display, failures, limits, budget, depth) {
  const remainingDecompressedBytes = limits.maximumCumulativeDecompressedBytes - budget.decompressedBytes;
  if (remainingDecompressedBytes <= 0) {
    failures.push(`${display}: cumulative archive decompressed-byte budget exceeded`);
    return;
  }
  let entries;
  try {
    entries = parseTarGz(content, display, {
      maximumOutputLength: remainingDecompressedBytes,
      onDecompressedSize(size) {
        budget.decompressedBytes += size;
      },
    });
  } catch (error) {
    failures.push(error.message.includes("exceeds its bounded decompressed archive size")
      ? `${display}: cumulative archive decompressed-byte budget exceeded`
      : `${display}: ${error.message}`);
    return;
  }

  const memberBytes = entries.reduce((total, entry) => total + entry.content.length, 0);
  if (memberBytes > limits.maximumCumulativeMemberBytes - budget.memberBytes) {
    failures.push(`${display}: cumulative archive member-byte budget exceeded`);
    return;
  }
  budget.memberBytes += memberBytes;

  for (const entry of entries) {
    const memberDisplay = `${display}!/${entry.name}`;
    const memberFilename = basename(entry.name);
    if (entry.name.split("/").includes(".git")) {
      failures.push(`${memberDisplay}: nested git metadata is forbidden`);
      continue;
    }
    if (entry.type === "file" && isForbiddenFilename(memberFilename)) {
      failures.push(`${memberDisplay}: forbidden sensitive filename`);
      continue;
    }
    if (entry.type === "file" && generatedExtensions.has(extname(memberFilename).toLowerCase())) {
      failures.push(`${memberDisplay}: generated bytecode is forbidden`);
      continue;
    }
    if (entry.name.split("/").some((component) => generatedDirectories.has(component))) {
      failures.push(`${memberDisplay}: generated cache is forbidden`);
      continue;
    }
    if (entry.type === "file" && memberFilename.toLowerCase().endsWith(".tgz")) {
      if (depth >= limits.maximumArchiveDepth) {
        failures.push(`${memberDisplay}: archive nesting depth exceeds maximum ${limits.maximumArchiveDepth}`);
      } else {
        scanArchive(entry.content, memberDisplay, failures, limits, budget, depth + 1);
      }
      continue;
    }
    if (entry.type === "file") scanContent(entry.content, memberDisplay, failures, true);
  }
}

async function isValidRootGitPointer(root, content) {
  const match = /^gitdir: ([^\0\r\n]+)\r?\n?$/.exec(content.toString("utf8"));
  if (match === null) return false;
  try {
    return (await stat(resolve(root, match[1]))).isDirectory();
  } catch {
    return false;
  }
}

export async function scanPublication(requestedRoot, options = {}) {
  const root = resolve(requestedRoot);
  const failures = [];
  const limits = archiveLimits(options);

  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const display = relative(root, path) || entry.name;
      if (entry.isSymbolicLink()) {
        failures.push(`${display}: symbolic links are forbidden`);
        continue;
      }
      const isRootGitEntry = directory === root && entry.name === ".git";
      if (isRootGitEntry && entry.isDirectory()) continue;
      if (entry.name === ".git" && !isRootGitEntry) {
        failures.push(`${display}: nested git metadata is forbidden`);
        continue;
      }
      if (entry.isDirectory() && generatedDirectories.has(entry.name)) {
        failures.push(`${display}: generated cache directory is forbidden`);
        continue;
      }
      if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      if (!entry.isFile()) {
        failures.push(`${display}: non-regular filesystem entry is forbidden`);
        continue;
      }
      if (path === thisFile) continue;

      const filename = basename(path);
      if (isForbiddenFilename(filename)) {
        failures.push(`${display}: forbidden sensitive filename`);
        continue;
      }
      if (generatedExtensions.has(extname(filename).toLowerCase())) {
        failures.push(`${display}: generated bytecode is forbidden`);
        continue;
      }

      let content;
      try {
        content = await readRegularFile(path);
      } catch (error) {
        failures.push(`${display}: unreadable or unsafe regular file (${error.code ?? error.message})`);
        continue;
      }
      if (isRootGitEntry) {
        if (!await isValidRootGitPointer(root, content)) failures.push(`${display}: malformed gitdir administrative pointer`);
        continue;
      }
      if (filename.toLowerCase().endsWith(".tgz")) {
        scanArchive(content, display, failures, limits, { decompressedBytes: 0, memberBytes: 0 }, 0);
      }
      else scanContent(content, display, failures);
    }
  }

  try {
    await walk(root);
  } catch (error) {
    failures.push(`scanner traversal failed: ${error.code ?? error.message}`);
  }
  return failures.sort();
}

if (process.argv[1] === thisFile) {
  const failures = await scanPublication(process.argv[2] ?? defaultRoot);
  if (failures.length > 0) {
    console.error(failures.join("\n"));
    process.exitCode = 1;
  } else {
    console.log("security:check passed");
  }
}
