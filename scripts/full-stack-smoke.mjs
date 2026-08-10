import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const records = new Map();
const outputDirectory = await mkdtemp(join(tmpdir(), "zkya-browser-proof-"));
let teardownPromise;

function spawnTracked(name, command, args, env = {}) {
  const child = spawn(command, args, {
    cwd: root,
    detached: process.platform !== "win32",
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const record = { name, child, output: "", close: undefined };
  record.close = new Promise((resolveClose) => {
    child.once("error", (error) => {
      record.output += `${error.stack ?? error.message}\n`;
    });
    child.once("close", (code, signal) => resolveClose({ code, signal }));
  });
  records.set(child, record);
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      record.output += chunk.toString();
    });
  }
  return record;
}

async function run(command, args, options = {}) {
  const record = spawnTracked(`${command} ${args.join(" ")}`, command, args, options.env);
  for (const stream of [record.child.stdout, record.child.stderr]) {
    const destination = stream === record.child.stdout ? process.stdout : process.stderr;
    stream.on("data", (chunk) => destination.write(chunk));
  }
  const { code, signal } = await record.close;
  if (code !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited ${String(code)} (${String(signal)})\n${record.output}`);
  }
  return record.output;
}

function start(name, command, args, env = {}) {
  return spawnTracked(name, command, args, env).child;
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

async function waitFor(url, child, label) {
  const deadline = Date.now() + 20_000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      const record = records.get(child);
      throw new Error(`${label} exited before readiness\n${record?.output ?? ""}`);
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.min(2_000, Math.max(1, deadline - Date.now())));
    try {
      const response = await fetch(url, { signal: controller.signal });
      await response.arrayBuffer();
      if (response.ok) return;
      lastError = new Error(`${label} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`${label} did not become ready: ${String(lastError)}`);
}

function signalChild(child, signal) {
  if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

async function waitForRecords(active, timeoutMilliseconds) {
  if (active.length === 0) return true;
  return await Promise.race([
    Promise.all(active.map((record) => record.close)).then(() => true),
    new Promise((resolveWait) => setTimeout(() => resolveWait(false), timeoutMilliseconds)),
  ]);
}

async function stopChildren() {
  if (teardownPromise !== undefined) return await teardownPromise;
  teardownPromise = (async () => {
    let active = [...records.values()].filter(({ child }) => child.exitCode === null && child.signalCode === null);
    for (const { child } of active) signalChild(child, "SIGTERM");
    if (!await waitForRecords(active, 2_000)) {
      active = active.filter(({ child }) => child.exitCode === null && child.signalCode === null);
      for (const { child } of active) signalChild(child, "SIGKILL");
      if (!await waitForRecords(active, 2_000)) {
        const survivors = active.filter(({ child }) => child.exitCode === null && child.signalCode === null);
        if (survivors.length > 0) throw new Error(`failed to stop child processes: ${survivors.map(({ name }) => name).join(", ")}`);
      }
    }
  })();
  return await teardownPromise;
}

let cleanupPromise;
async function cleanup() {
  if (cleanupPromise === undefined) {
    cleanupPromise = (async () => {
      await stopChildren();
      await rm(outputDirectory, { recursive: true, force: true, maxRetries: 3 });
    })();
  }
  return await cleanupPromise;
}

const signalHandlers = new Map();
for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  const handler = () => {
    void cleanup().then(
      () => process.exit(exitCode),
      (error) => {
        console.error(`teardown after ${signal} failed: ${error.stack ?? error.message}`);
        process.exit(1);
      },
    );
  };
  signalHandlers.set(signal, handler);
  process.once(signal, handler);
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
  for (const { name, output } of records.values()) {
    if (output.length > 0) console.error(`\n--- ${name} log ---\n${output}`);
  }
  throw error;
} finally {
  for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
  await cleanup();
}
