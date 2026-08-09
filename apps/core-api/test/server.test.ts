import assert from "node:assert/strict";
import test from "node:test";
import { Hono } from "hono";
import { startLoopbackReferenceServer } from "../src/server-runtime.js";

test("reference listener binds only to IPv4 loopback", async () => {
  const app = new Hono();
  app.get("/health", (context) => context.json({ ok: true }));

  let server: ReturnType<typeof startLoopbackReferenceServer> | undefined;
  const info = await new Promise<{ readonly port: number }>((resolve) => {
    server = startLoopbackReferenceServer(app.fetch, 0, resolve);
  });

  assert.ok(server);
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    assert.equal(address.address, "127.0.0.1");
    const response = await fetch(`http://127.0.0.1:${info.port}/health`);
    assert.equal(response.status, 200);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => error === undefined ? resolve() : reject(error));
    });
  }
});
