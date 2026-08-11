import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
    version: "1.2.3",
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

function receiptProjectionPairs(markdown) {
  const marker = "Legal reachable pairs are:";
  const markerMatches = [...markdown.matchAll(/^Legal reachable pairs are:$/gm)];
  if (markerMatches.length !== 1) {
    throw new Error("document must contain exactly one receipt projection table marker");
  }
  const sectionMatches = [...markdown.matchAll(/^## Retained onboarding projection$/gm)];
  const headerMatches = [...markdown.matchAll(/^\| Durable status \| Latest attempt \|$/gm)];
  if (sectionMatches.length !== 1 || headerMatches.length !== 1) {
    throw new Error("receipt projection section structure must be unique");
  }

  const sectionIndex = sectionMatches[0].index;
  const markerIndex = markerMatches[0].index;
  const headerIndex = headerMatches[0].index;
  const nextSectionIndex = markdown.indexOf("\n## ", sectionIndex + 3);
  const sectionEnd = nextSectionIndex === -1 ? markdown.length : nextSectionIndex;
  if (!(sectionIndex < markerIndex && markerIndex < headerIndex && headerIndex < sectionEnd)) {
    throw new Error("receipt projection section structure is out of order");
  }
  const lines = markdown.slice(markerIndex + marker.length).trimStart().split(/\r?\n/);
  assert.equal(lines.shift(), "| Durable status | Latest attempt |", "receipt projection table header changed");
  assert.equal(lines.shift(), "|---|---|", "receipt projection table separator changed");

  const rows = [];
  while (lines[0] !== undefined && lines[0].trim() !== "") {
    const row = lines.shift();
    const match = /^\| ([^|]+) \| ([^|]+) \|$/.exec(row);
    if (match === null) throw new Error("receipt projection table requires a canonical two-column receipt row");
    rows.push([match[1], match[2]].map((cell) => cell.trim().replaceAll("`", "")));
  }
  assert.ok(rows.length > 0, "receipt projection table has no rows");
  return rows.sort(([leftStatus, leftAttempt], [rightStatus, rightAttempt]) =>
    leftStatus.localeCompare(rightStatus) || leftAttempt.localeCompare(rightAttempt));
}

function currentCandidateChangelog(markdown) {
  const anchorMatches = [...markdown.matchAll(/^## 0\.3\.0 — 2026-08-10$/gm)];
  if (anchorMatches.length !== 1) {
    throw new Error("changelog must contain exactly one historical changelog anchor");
  }
  const expectedHeadings = [
    "## 0.3.1 corrective candidate — unreleased",
    "## 0.3.0 — 2026-08-10",
    "## 0.2.1-full-stack-reference — 2026-08-09",
    "## 0.2.0-full-stack-reference — 2026-08-09",
    "## 0.1.0-reference — 2026-08-08",
  ];
  const headings = [...markdown.matchAll(/^## .+$/gm)].map((match) => match[0]);
  const anchorIndex = anchorMatches[0].index;
  const publishedHeading = "## 0.3.0 — 2026-08-10\n\n### Published reference release";
  if (JSON.stringify(headings) !== JSON.stringify(expectedHeadings) ||
      !markdown.slice(anchorIndex).startsWith(publishedHeading)) {
    throw new Error("changelog section structure does not match the candidate release lineage");
  }
  return markdown.slice(0, anchorIndex);
}

function candidateOpenStages(markdown) {
  const stageLines = markdown.match(/^\*\*Stage:\*\*[^\n]*$/gm) ?? [];
  if (stageLines.length !== 1) throw new Error("candidate stage must have exactly one Stage line");
  const match = /^\*\*Stage:\*\* integrated local corrective candidate; not yet ([a-z]+(?:, [a-z]+)*(?:,? or [a-z]+))\.$/i.exec(stageLines[0]);
  if (match === null) throw new Error("candidate stage must negate one constrained lifecycle list");

  const stages = match[1]
    .replace(/,?\s+or\s+/i, ", ")
    .split(/,\s*/)
    .map((stage) => stage.toLowerCase())
    .sort();
  const expected = ["merged", "published", "released", "tagged"];
  if (JSON.stringify(stages) !== JSON.stringify(expected)) {
    throw new Error("candidate stage must negate exactly merged, tagged, released, and published");
  }
  return stages;
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
      version: "1.2.3",
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

test("v0.3.1 candidate version and current publication documentation stay aligned", async () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const manifestPaths = [
    "package.json",
    "apps/core-api/package.json",
    "packages/sdk/package.json",
    "apps/operator-ui/package.json",
    "apps/zkya-onboarding/package.json",
  ];
  for (const relativePath of manifestPaths) {
    const packageManifest = JSON.parse(await readFile(join(root, relativePath), "utf8"));
    assert.equal(packageManifest.version, "0.3.1", `${relativePath} version is stale`);
  }
  const apiManifest = JSON.parse(await readFile(join(root, "apps/core-api/package.json"), "utf8"));
  assert.equal(apiManifest.peerDependencies["@ordin/zkyc-core-reference"], "0.3.1");
  const lock = JSON.parse(await readFile(join(root, "package-lock.json"), "utf8"));
  for (const packagePath of ["", "apps/core-api", "packages/sdk", "apps/operator-ui", "apps/zkya-onboarding"]) {
    assert.equal(lock.packages[packagePath].version, "0.3.1", `package-lock ${packagePath || "root"} version is stale`);
  }

  const healthSource = await readFile(join(root, "apps/core-api/src/app.ts"), "utf8");
  assert.match(healthSource, /service: "zkyc-core-api-reference",\s+version: "0\.3\.1"/);
  const healthValidation = await readFile(join(root, "packages/sdk/src/validation.ts"), "utf8");
  assert.match(healthValidation, /item\.version !== "0\.3\.1"/);
  assert.match(healthValidation, /service: "zkyc-core-api-reference",\s+version: "0\.3\.1"/);
  const serverTest = await readFile(join(root, "apps/core-api/test/server.test.ts"), "utf8");
  assert.match(serverTest, /service: "zkyc-core-api-reference",\s+version: "0\.3\.1"/);
  const onboardingSource = await readFile(join(root, "apps/zkya-onboarding/src/App.tsx"), "utf8");
  assert.match(onboardingSource, />REFERENCE \/ v0\.3\.1</);
  assert.doesNotMatch(onboardingSource, />REFERENCE \/ v0\.3\.0</);

  const currentDocuments = [
    "README.md",
    "CHANGELOG.md",
    "CLAIMS_AND_LIMITATIONS.md",
    "PROVENANCE.md",
    "REPRODUCIBILITY.md",
    "SECURITY.md",
    "docs/api-contract.md",
    "docs/architecture.md",
    "docs/decision-lifecycle.md",
    "docs/evidence-map.md",
    "docs/full-stack-reference.md",
    "docs/reviewer-walkthrough.md",
    "docs/threat-model.md",
    "docs/zkya-onboarding-reference.md",
  ];
  const currentText = (await Promise.all(currentDocuments.map(async (relativePath) => {
    const text = await readFile(join(root, relativePath), "utf8");
    const currentScope = relativePath === "CHANGELOG.md" ? currentCandidateChangelog(text) : text;
    return `${relativePath}\n${currentScope}`;
  }))).join("\n");
  for (const stale of [
    /integrated local `v0\.3\.0` reference candidate/,
    /0\.3\.0 candidate — unreleased/,
    /`v0\.3\.0` exists only as an integrated local candidate/,
    /v0\.3 executable baseline is `20fa75cf847e064e84f07f6426908412a5811be6`/,
    /SDK(?:\/server)?: 12|SDK tests?: 12|SDK 12/,
    /release-tooling(?: regression)?(?: tests?)?: 7|release-tooling 7/,
    /no (?:public\/)?immutable v0\.3 release/i,
  ]) {
    assert.doesNotMatch(currentText, stale);
  }
  assert.match(currentText, /v0\.3\.1/);
  assert.match(currentText, /automated[^\n]*(?:review|assistant)/i);
  assert.match(currentText, /Mike “Mizzy” Barrera and Monique Abrams[^\n]*joint authors and co-architects/);

  const protocolPaths = [
    "docs/api-contract.md",
    "docs/architecture.md",
    "docs/decision-lifecycle.md",
    "docs/evidence-map.md",
    "docs/full-stack-reference.md",
    "docs/reviewer-walkthrough.md",
  ];
  const protocolDocuments = new Map(await Promise.all(protocolPaths.map(async (relativePath) =>
    [relativePath, await readFile(join(root, relativePath), "utf8")])));
  for (const [relativePath, text] of protocolDocuments) {
    for (const marker of [
      /\bunbound direct\b/i,
      /\bbound direct\b/i,
      /\bunbound delegated\b/i,
      /\bacting-only delegated\b/i,
      /\bfully bound delegated\b/i,
      /request-observable/i,
      /server-authoritative/i,
    ]) {
      assert.match(text, marker, `${relativePath} is missing an exact protocol boundary`);
    }
    assert.doesNotMatch(text, /receipt\.status|receipt state: `NOT_ISSUED`.*`REJECTED`/);
  }

  const apiContract = protocolDocuments.get("docs/api-contract.md");
  assert.ok(apiContract);
  assert.match(
    apiContract,
    /^\| `POST \/delegations` issuance \| HTTP `400` \|(?=[^\n]*DELEGATION_IDENTITIES_NOT_DISTINCT)(?=[^\n]*domain-error envelope)[^\n]*$/m,
  );
  assert.match(
    apiContract,
    /^\| `POST \/evaluations` delegated evaluation \| HTTP `200` \|(?=[^\n]*acting-only delegated)(?=[^\n]*DENY \/ DELEGATION_IDENTITIES_NOT_DISTINCT)(?=[^\n]*no[^\n]*receipt)[^\n]*$/m,
  );
  assert.match(
    apiContract,
    /^\| Unbound delegated denial \|(?=[^\n]*DELEGATION_GRANTOR_CREDENTIAL_INVALID)(?=[^\n]*server-authoritative)(?=[^\n]*no independent proof of private state)[^\n]*$/mi,
  );
  const expectedReceiptPairs = [
    ["CONSUMED", "ACCEPTED / RECEIPT_VALID or associated REJECTED"],
    ["NOT_ISSUED", "NONE"],
    ["UNCONSUMED", "NONE or associated REJECTED"],
  ];
  assert.deepEqual(receiptProjectionPairs(apiContract), expectedReceiptPairs);
  for (const illegalRow of [
    "| `NOT_ISSUED` | `REJECTED / RECEIPT_REPLAYED` |",
    "| `NOT_ISSUED` | `ACCEPTED / RECEIPT_VALID` |",
    "| `UNCONSUMED` | `ACCEPTED / RECEIPT_VALID` |",
    "| `CONSUMED` | `NONE` |",
  ]) {
    const mutated = apiContract.replace(
      "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |",
      `| \`CONSUMED\` | \`ACCEPTED / RECEIPT_VALID\` or associated \`REJECTED\` |\n${illegalRow}`,
    );
    assert.notDeepEqual(receiptProjectionPairs(mutated), expectedReceiptPairs);
  }
  const malformedThirdCell = apiContract.replace(
    "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |",
    "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` | EXTRA",
  );
  assert.throws(() => receiptProjectionPairs(malformedThirdCell), /canonical two-column receipt row/);
  const indentedIllegalRow = apiContract.replace(
    "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |",
    "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |\n | `NOT_ISSUED` | `REJECTED / RECEIPT_REPLAYED` |",
  );
  assert.throws(() => receiptProjectionPairs(indentedIllegalRow), /canonical two-column receipt row/);
  const duplicateReceiptMarker = `${apiContract}\n\nLegal reachable pairs are:\n\n| Durable status | Latest attempt |\n|---|---|\n| \`CONSUMED\` | \`NONE\` |\n`;
  assert.throws(() => receiptProjectionPairs(duplicateReceiptMarker), /exactly one receipt projection table marker/);
  const substitutedReceiptTable = apiContract
    .replace("Legal reachable pairs are:", "Documented reachable pairs are:")
    .replace("| Durable status | Latest attempt |", "| Documented durable status | Documented latest attempt |")
    .replace(
      "| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |",
      "| `CONSUMED` | `NONE` |",
    )
    .replace(
      "## Retained onboarding projection",
      "Legal reachable pairs are:\n\n| Durable status | Latest attempt |\n|---|---|\n| `NOT_ISSUED` | `NONE` |\n| `UNCONSUMED` | `NONE` or associated `REJECTED` |\n| `CONSUMED` | `ACCEPTED / RECEIPT_VALID` or associated `REJECTED` |\n\n## Retained onboarding projection",
    );
  assert.throws(() => receiptProjectionPairs(substitutedReceiptTable), /receipt projection section structure is out of order/);
  assert.match(apiContract, /Replay projects `CONSUMED \+ REJECTED \/ RECEIPT_REPLAYED`/);
  assert.match(
    apiContract,
    /Malformed input[^\n]*leave both axes unchanged; `RECEIPT_MALFORMED`[^\n]*not a retained associated rejection reason/,
  );

  const decisionLifecycle = protocolDocuments.get("docs/decision-lifecycle.md");
  assert.ok(decisionLifecycle);
  assert.match(
    decisionLifecycle,
    /^3\. \*\*Unbound delegated denial\*\*(?=[^\n]*DELEGATION_GRANTOR_CREDENTIAL_INVALID)(?=[^\n]*server-authoritative)(?=[^\n]*no independent proof of private state)[^\n]*$/mi,
  );
  assert.match(
    decisionLifecycle,
    /DELEGATION_IDENTITIES_NOT_DISTINCT[^\n]*issuance HTTP `400`[^\n]*evaluation HTTP `200`[^\n]*acting-only delegated denial/,
  );
  assert.match(decisionLifecycle, /Replay remains `CONSUMED`[^\n]*`REJECTED \/ RECEIPT_REPLAYED`/);
  assert.match(decisionLifecycle, /malformed or unassociated input leaves both axes unchanged/i);

  const security = await readFile(join(root, "SECURITY.md"), "utf8");
  assert.match(security, /v0\.3\.0[^\n]*published/i);
  assert.match(security, /v0\.3\.1[^\n]*not[^\n]*supported release/i);

  const template = await readFile(join(root, "VERIFICATION_RECEIPT_TEMPLATE.md"), "utf8");
  assert.match(template, /after the exact tag named below exists/i);
  assert.doesNotMatch(template, /\| (?:Core|API\/server|SDK|Operator UI|zkYA component|Scanner regression|Release-tooling regression|Chromium E2E) \| \d+ \|/);

  const v030Notes = await readFile(join(root, "release-notes-v0.3.0.md"), "utf8");
  assert.match(v030Notes, /published immutable reference release/i);
  assert.doesNotMatch(v030Notes, /Candidate Release Notes|unreleased/);
  const datedCvLayer = await readFile(
    join(root, "docs/google-deepmind-cv-evidence-addendum-2026-08-09.md"),
    "utf8",
  );
  assert.match(datedCvLayer, /dated 2026-08-09 v0\.3 candidate evidence/i);
  assert.match(datedCvLayer, /20fa75cf847e064e84f07f6426908412a5811be6/);
  assert.match(datedCvLayer, /historical description of the 2026-08-09 evidence layer/i);
  const v031Notes = await readFile(join(root, "release-notes-v0.3.1.md"), "utf8");
  assert.match(v031Notes, /candidate/i);
  const expectedOpenStages = ["merged", "published", "released", "tagged"];
  assert.deepEqual(candidateOpenStages(v031Notes), expectedOpenStages);
  assert.deepEqual(
    candidateOpenStages("**Stage:** integrated local corrective candidate; not yet published, released, tagged, or merged."),
    expectedOpenStages,
  );
  for (const invalidStage of [
    "**Stage:** integrated local corrective candidate; not yet merged, tagged, or released.",
    "**Stage:** integrated local corrective candidate; not yet tagged, released, or published.",
    "**Stage:** integrated local corrective candidate; not yet merged, released, or published.",
    "**Stage:** integrated local corrective candidate; not yet merged, tagged, or published.",
    "**Stage:** integrated local corrective candidate; not yet merged, merged, tagged, released, or published.",
    "**Stage:** integrated local corrective candidate; not yet merged; now tagged, released, and published.",
    "**Stage:** integrated local corrective candidate; merged, tagged, released, and published.",
  ]) {
    assert.throws(() => candidateOpenStages(invalidStage), /candidate stage/);
  }

  const changelog = await readFile(join(root, "CHANGELOG.md"), "utf8");
  assert.throws(
    () => currentCandidateChangelog(changelog.replace("## 0.3.0 — 2026-08-10", "## 0.3.0 historical release")),
    /exactly one historical changelog anchor/,
  );
  assert.throws(
    () => currentCandidateChangelog(changelog.replace(
      "## 0.3.0 — 2026-08-10",
      "## 0.3.0 — 2026-08-10\n\nSDK tests: 12\nrelease-tooling regression tests: 7\n\n## 0.3.0 — 2026-08-10",
    )),
    /exactly one historical changelog anchor/,
  );
  const substitutedChangelogAnchor = changelog
    .replace("## 0.3.0 — 2026-08-10", "## 0.3.0 historical release")
    .replace(
      "## 0.3.1 corrective candidate — unreleased",
      "## 0.3.1 corrective candidate — unreleased\n\n## 0.3.0 — 2026-08-10\n\nSDK tests: 12\nrelease-tooling regression tests: 7",
    );
  assert.throws(() => currentCandidateChangelog(substitutedChangelogAnchor), /changelog section structure/);
});
