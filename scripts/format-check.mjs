import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const includedRoots = ["src", "test", "fixtures", "scripts", "apps", "packages"];
const rootFiles = ["package.json", "tsconfig.json", ".gitignore"];
const textExtensions = new Set([".ts", ".tsx", ".mjs", ".js", ".json", ".css", ".html"]);
const ignoredDirectories = new Set([".git", "node_modules", "dist", "coverage"]);
const failures = [];

async function checkFile(path) {
  const content = await readFile(path, "utf8");
  const display = relative(root, path);
  if (content.includes("\r")) failures.push(`${display}: contains CR characters`);
  if (!content.endsWith("\n")) failures.push(`${display}: missing final newline`);
  content.split("\n").forEach((line, index) => {
    if (/[ \t]+$/.test(line)) failures.push(`${display}:${index + 1}: trailing whitespace`);
    if (line.includes("\t")) failures.push(`${display}:${index + 1}: tab character`);
  });
}

async function walk(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const child = join(path, entry.name);
    if (entry.isDirectory()) await walk(child);
    else if (textExtensions.has(extname(entry.name))) await checkFile(child);
  }
}

for (const directory of includedRoots) {
  try {
    await walk(join(root, directory));
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}
for (const file of rootFiles) await checkFile(join(root, file));

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("format:check passed");
}
