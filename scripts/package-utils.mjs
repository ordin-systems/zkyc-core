import { readFile } from "node:fs/promises";
import { posix } from "node:path";

function collectTargetValue(value, location, targets) {
  if (value === null) return;
  if (typeof value === "string") {
    targets.add(normalizePackageTarget(value, location));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectTargetValue(entry, `${location}[${index}]`, targets));
    return;
  }
  if (typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) collectTargetValue(entry, `${location}.${key}`, targets);
    return;
  }
  throw new Error(`${location} contains an unsupported package target`);
}

export function normalizePackageTarget(target, location = "package target") {
  if (target.includes("\\") || target.startsWith("/") || /^[A-Za-z]:/.test(target)) {
    throw new Error(`${location} has an unsafe path`);
  }
  const withoutPrefix = target.replace(/^\.\//, "");
  const normalized = posix.normalize(withoutPrefix);
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized !== withoutPrefix) {
    throw new Error(`${location} has an unsafe path`);
  }
  return normalized;
}

export function collectManifestTargets(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("package manifest must be an object");
  }
  const targets = new Set();
  for (const field of ["main", "types"]) {
    if (manifest[field] !== undefined) collectTargetValue(manifest[field], field, targets);
  }
  if (manifest.exports !== undefined) collectTargetValue(manifest.exports, "exports", targets);
  if (manifest.bin !== undefined) collectTargetValue(manifest.bin, "bin", targets);
  return targets;
}

export async function readManifest(path) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new Error(`cannot read package manifest ${path}: ${error.code ?? error.message}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    throw new Error(`cannot parse package manifest ${path}: ${error.message}`);
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error(`package manifest ${path} must contain an object`);
  }
  return manifest;
}
