import { serve, type ServerType } from "@hono/node-server";
import type { Hono } from "hono";

export interface LoopbackServerInfo {
  readonly port: number;
}

export function startLoopbackReferenceServer(
  fetch: Hono["fetch"],
  port: number,
  onReady?: (info: LoopbackServerInfo) => void,
): ServerType {
  return serve(
    {
      fetch,
      hostname: "127.0.0.1",
      port,
    },
    onReady,
  );
}
