import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const root = resolve(new URL("..", import.meta.url).pathname);
const children = new Set();
const logs = new Map();
const outputDirectory = await mkdtemp(join(tmpdir(), "zkya-browser-proof-"));

function run(command, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: root,
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; process.stdout.write(chunk); });
    child.stderr.on("data", (chunk) => { output += chunk; process.stderr.write(chunk); });
    child.on("error", rejectRun);
    child.on("exit", (code, signal) => {
      if (code === 0) resolveRun(output);
      else rejectRun(new Error(`${command} ${args.join(" ")} exited ${String(code)} (${String(signal)})\n${output}`));
    });
  });
}

function start(name, command, args, env = {}) {
  const child = spawn(command, args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  logs.set(child, { name, output: "" });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      const state = logs.get(child);
      if (state !== undefined) state.output += chunk.toString();
    });
  }
  return child;
}

async function freePort() {
  return new Promise((resolvePort, rejectPort) => {
    const server = createServer();
    server.unref();
    server.on("error", rejectPort);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        rejectPort(new Error("failed to reserve loopback port"));
        return;
      }
      const port = address.port;
      server.close((error) => error === undefined ? resolvePort(port) : rejectPort(error));
    });
  });
}

async function waitFor(url, child, label) {
  const deadline = Date.now() + 20_000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      const state = logs.get(child);
      throw new Error(`${label} exited before readiness\n${state?.output ?? ""}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
      lastError = new Error(`${label} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`${label} did not become ready: ${String(lastError)}`);
}

async function stopChildren() {
  for (const child of children) {
    if (child.exitCode === null) child.kill("SIGTERM");
  }
  await new Promise((resolveWait) => setTimeout(resolveWait, 250));
  for (const child of children) {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
}

try {
  await run("npm", ["run", "build", "--silent"]);
  await run("npm", ["run", "build", "-w", "@ordin/zkyc-core-api-reference", "--silent"]);
  await run("npm", ["run", "build", "-w", "@ordin/zkyc-sdk-reference", "--silent"]);
  await run("npm", ["run", "build", "-w", "@ordin/zkya-onboarding-reference", "--silent"]);

  const apiPort = await freePort();
  const uiPort = await freePort();
  const api = start("API", process.execPath, ["apps/core-api/dist/src/server.js"], {
    PORT: String(apiPort),
    ZKYC_RECEIPT_HMAC_KEY: "reference-browser-smoke-key-32-bytes-minimum",
    ZKYC_ISSUER_ID: "issuer:zkya-browser-smoke",
  });
  await waitFor(`http://127.0.0.1:${apiPort}/health`, api, "API");

  const ui = start("UI", process.execPath, [
    "node_modules/vite/bin/vite.js",
    "preview",
    "--config",
    "apps/zkya-onboarding/vite.config.ts",
    "--host",
    "127.0.0.1",
    "--port",
    String(uiPort),
    "--strictPort",
  ], { VITE_ZKYC_API_TARGET: `http://127.0.0.1:${apiPort}` });
  const baseURL = `http://127.0.0.1:${uiPort}`;
  await waitFor(baseURL, ui, "UI");

  await run(process.execPath, [
    "node_modules/@playwright/test/cli.js",
    "test",
    "e2e/zkya-onboarding.spec.ts",
    "--config",
    "playwright.config.ts",
    "--project",
    "chromium",
  ], {
    env: {
      ZKYA_BASE_URL: baseURL,
      ZKYA_E2E_OUTPUT_DIR: outputDirectory,
    },
  });
  console.log(`zkYA Chromium full-stack smoke passed: ${baseURL}`);
} catch (error) {
  for (const { name, output } of logs.values()) {
    if (output.length > 0) console.error(`\n--- ${name} log ---\n${output}`);
  }
  throw error;
} finally {
  await stopChildren();
  await rm(outputDirectory, { recursive: true, force: true });
}
