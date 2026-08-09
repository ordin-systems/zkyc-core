import { readdir, readFile } from "node:fs/promises";
import { basename, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.argv[2] ?? new URL("..", import.meta.url).pathname;
const thisFile = fileURLToPath(import.meta.url);
const ignoredDirectories = new Set([".git", "node_modules", "dist", "coverage"]);
const forbiddenNames = new Set([".env", "id_rsa", "id_ed25519"]);
const forbiddenExtensions = new Set([".pem", ".p12", ".pfx", ".key"]);
const textExtensions = new Set([".ts", ".mjs", ".js", ".json", ".md", ".yml", ".yaml", ".txt"]);
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

const failures = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    const display = relative(root, path);
    if (entry.isDirectory()) {
      await walk(path);
      continue;
    }
    if (path === thisFile) continue;
    if (forbiddenNames.has(basename(path)) || forbiddenExtensions.has(extname(path))) {
      failures.push(`${display}: forbidden sensitive filename`);
      continue;
    }
    if (!textExtensions.has(extname(path)) && basename(path) !== ".gitignore") continue;
    const content = await readFile(path, "utf8");
    for (const { label, pattern, codeOnly = false } of forbiddenPatterns) {
      if (codeOnly && !display.startsWith(`src${process.platform === "win32" ? "\\" : "/"}`)) continue;
      if (pattern.test(content)) failures.push(`${display}: ${label}`);
    }
  }
}

await walk(root);

if (failures.length > 0) {
  console.error(failures.sort().join("\n"));
  process.exitCode = 1;
} else {
  console.log("security:check passed");
}
