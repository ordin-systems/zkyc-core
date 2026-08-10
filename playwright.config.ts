import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.ZKYA_BASE_URL;
if (baseURL === undefined) {
  throw new Error("ZKYA_BASE_URL is required; run npm run test:browser");
}

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "line",
  outputDir: process.env.ZKYA_E2E_OUTPUT_DIR,
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [{
    name: "chromium",
    use: { ...devices["Desktop Chrome"] },
  }],
});
