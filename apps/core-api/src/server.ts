import { randomUUID } from "node:crypto";
import { createReferenceApp, type ReferenceIdKind } from "./app.js";
import { localReferencePolicyCatalog } from "./reference-policy-catalog.js";
import { startLoopbackReferenceServer } from "./server-runtime.js";

const secret = process.env.ZKYC_RECEIPT_HMAC_KEY;
if (secret === undefined || new TextEncoder().encode(secret).byteLength < 32) {
  throw new Error("ZKYC_RECEIPT_HMAC_KEY must contain at least 32 bytes");
}

const portValue = Number(process.env.PORT ?? "8787");
if (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535");
}

const app = createReferenceApp({
  clock: () => new Date().toISOString(),
  idFactory: (kind: ReferenceIdKind) => `${kind}:${randomUUID()}`,
  receiptHmacKey: new TextEncoder().encode(secret),
  trustedPolicies: localReferencePolicyCatalog,
  issuerId: process.env.ZKYC_ISSUER_ID ?? "issuer:reference-local",
});

startLoopbackReferenceServer(app.fetch, portValue, (info) => {
  console.log(`zKYC reference API listening on http://127.0.0.1:${info.port}`);
});
