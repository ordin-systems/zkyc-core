import { gunzipSync } from "node:zlib";
import { posix } from "node:path";

const blockSize = 512;
const maximumArchiveSize = 256 * 1024 * 1024;
const maximumMemberSize = 64 * 1024 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

function decodeField(block, start, length, label) {
  const bytes = block.subarray(start, start + length);
  const nul = bytes.indexOf(0);
  try {
    return decoder.decode(nul === -1 ? bytes : bytes.subarray(0, nul));
  } catch (error) {
    throw new Error(`malformed tar ${label}: ${error.message}`);
  }
}

function parseOctal(block, start, length, label) {
  const raw = decodeField(block, start, length, label).trim();
  if (!/^[0-7]+$/.test(raw)) throw new Error(`malformed tar ${label}`);
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value)) throw new Error(`tar ${label} exceeds safe integer range`);
  return value;
}

function normalizedMemberName(rawName) {
  if (rawName.length === 0) throw new Error("tar member has an empty name");
  if (rawName.includes("\\") || rawName.startsWith("/") || /^[A-Za-z]:/.test(rawName)) {
    throw new Error(`tar member has an unsafe path: ${rawName}`);
  }
  const name = rawName.endsWith("/") ? rawName.slice(0, -1) : rawName;
  const components = name.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    throw new Error(`tar member has an unsafe path: ${rawName}`);
  }
  const normalized = posix.normalize(name);
  if (normalized !== name || normalized === "." || normalized.startsWith("../")) {
    throw new Error(`tar member has an unsafe path: ${rawName}`);
  }
  return normalized;
}

function checksum(block) {
  let total = 0;
  for (let index = 0; index < blockSize; index += 1) {
    total += index >= 148 && index < 156 ? 0x20 : block[index];
  }
  return total;
}

function isZeroBlock(block) {
  return block.every((value) => value === 0);
}

export function parseTarGz(compressed, label = "archive") {
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: maximumArchiveSize });
  } catch (error) {
    throw new Error(`${label} is not a valid bounded gzip archive: ${error.message}`);
  }
  if (tar.length < blockSize * 2 || tar.length % blockSize !== 0) {
    throw new Error(`${label} has a malformed tar length`);
  }

  const entries = [];
  const names = new Set();
  let offset = 0;
  let foundTerminator = false;
  while (offset < tar.length) {
    const header = tar.subarray(offset, offset + blockSize);
    if (isZeroBlock(header)) {
      const second = tar.subarray(offset + blockSize, offset + (2 * blockSize));
      if (second.length !== blockSize || !isZeroBlock(second)) {
        throw new Error(`${label} has an incomplete tar terminator`);
      }
      for (let index = offset + (2 * blockSize); index < tar.length; index += 1) {
        if (tar[index] !== 0) throw new Error(`${label} has data after its tar terminator`);
      }
      foundTerminator = true;
      break;
    }

    const expectedChecksum = parseOctal(header, 148, 8, "checksum");
    if (checksum(header) !== expectedChecksum) throw new Error(`${label} has an invalid tar checksum`);
    const shortName = decodeField(header, 0, 100, "member name");
    const prefix = decodeField(header, 345, 155, "member prefix");
    const name = normalizedMemberName(prefix.length > 0 ? `${prefix}/${shortName}` : shortName);
    if (names.has(name)) throw new Error(`${label} has a duplicate tar member: ${name}`);
    names.add(name);

    const size = parseOctal(header, 124, 12, "member size");
    if (size > maximumMemberSize) throw new Error(`${label} member is too large: ${name}`);
    const typeFlag = String.fromCharCode(header[156]);
    const type = typeFlag === "\0" || typeFlag === "0" ? "file" : typeFlag === "5" ? "directory" : undefined;
    if (type === undefined) throw new Error(`${label} has an unsafe tar member type for ${name}`);
    if (type === "directory" && size !== 0) throw new Error(`${label} directory member has content: ${name}`);

    const mode = parseOctal(header, 100, 8, "member mode");
    const contentStart = offset + blockSize;
    const contentEnd = contentStart + size;
    if (contentEnd > tar.length) throw new Error(`${label} member is truncated: ${name}`);
    entries.push({ name, type, mode, content: Buffer.from(tar.subarray(contentStart, contentEnd)) });
    offset = contentStart + (Math.ceil(size / blockSize) * blockSize);
  }
  if (!foundTerminator) throw new Error(`${label} has no tar terminator`);
  if (entries.length === 0) throw new Error(`${label} contains no members`);
  return entries;
}
