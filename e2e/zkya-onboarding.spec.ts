import { expect, test } from "@playwright/test";

async function runSelectedScenario(page: import("@playwright/test").Page): Promise<import("@playwright/test").Locator> {
  await page.getByRole("button", { name: "Run reference scenario" }).click();
  const view = page.getByTestId("onboarding-view");
  await expect(view).toBeVisible();
  return view;
}

test("real SDK and HTTP stack executes zkYA authority lifecycle lanes", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "zkYA / Know-Your-Agent Onboarding Reference",
  );
  await expect(page.getByLabel("Persistent reference boundary")).toContainText("LOCAL REFERENCE ONLY");

  let view = await runSelectedScenario(page);
  await expect(view.getByText("agent:reference-direct-reader", { exact: true })).toBeVisible();
  await expect(view.getByText("UNCONSUMED", { exact: true })).toBeVisible();
  await expect(view.getByText("HMAC-SHA256", { exact: true })).toBeVisible();
  await view.getByRole("button", { name: "Verify & consume full v2 binding" }).click();
  await expect(view.getByText("RECEIPT_VALID", { exact: true })).toBeVisible();
  await expect(view.getByText("CONSUMED", { exact: true })).toBeVisible();
  await view.getByRole("button", { name: "Verify & consume full v2 binding" }).click();
  await expect(view.getByText("RECEIPT_REPLAYED", { exact: true })).toBeVisible();
  await expect(view.getByText("Attempt 2", { exact: true })).toBeVisible();

  await page.getByRole("radio", { name: /Delegated organization scope/ }).check();
  view = await runSelectedScenario(page);
  await expect(view.getByText("DELEGATED", { exact: true })).toBeVisible();
  await expect(view.getByText("ORGANIZATION", { exact: true })).toBeVisible();
  const authority = view.getByRole("article", { name: "Authority" });
  await expect(authority.getByText("Delegation ID", { exact: true })).toBeVisible();
  await expect(authority.getByText(/^delegation:/)).toBeVisible();
  const capabilities = authority.getByRole("heading", { name: "Capabilities" }).locator("..");
  const exactActions = authority.getByRole("heading", { name: "Exact actions" }).locator("..");
  const exactResources = authority.getByRole("heading", { name: "Exact resources" }).locator("..");
  await expect(capabilities.getByText("records:read", { exact: true })).toBeVisible();
  await expect(exactActions.getByText("records:read", { exact: true })).toBeVisible();
  await expect(exactResources.getByText("dataset:reference-alpha", { exact: true })).toBeVisible();

  await page.getByRole("radio", { name: /Human step-up boundary/ }).check();
  view = await runSelectedScenario(page);
  await expect(view.getByText("PENDING", { exact: true })).toBeVisible();
  await view.getByRole("button", { name: "Approve as HUMAN" }).click();
  await expect(view.getByText("APPROVED", { exact: true })).toBeVisible();
  await expect(view.getByText("STEP_UP_APPROVED", { exact: true })).toHaveCount(2);

  view = await runSelectedScenario(page);
  await expect(view.getByText("PENDING", { exact: true })).toBeVisible();
  await view.getByRole("button", { name: "Reject as HUMAN" }).click();
  await expect(view.getByText("REJECTED", { exact: true })).toBeVisible();
  await expect(view.getByText("STEP_UP_REJECTED", { exact: true })).toHaveCount(2);

  await page.getByRole("radio", { name: /Action scope mismatch/ }).check();
  view = await runSelectedScenario(page);
  await expect(view.getByText("INELIGIBLE", { exact: true })).toBeVisible();
  await expect(view.getByText("ACTION_OUTSIDE_CREDENTIAL_SCOPE", { exact: true })).toBeVisible();

  await page.getByRole("radio", { name: /Resource scope mismatch/ }).check();
  view = await runSelectedScenario(page);
  await expect(view.getByText("RESOURCE_OUTSIDE_CREDENTIAL_SCOPE", { exact: true })).toBeVisible();

  await page.getByRole("radio", { name: /Revoked delegation/ }).check();
  view = await runSelectedScenario(page);
  const revokedAuthority = view.getByRole("article", { name: "Authority" });
  await expect(revokedAuthority.getByText("Delegation status", { exact: true })).toBeVisible();
  await expect(revokedAuthority.getByText("REVOKED", { exact: true })).toBeVisible();
  await expect(view.getByText("DELEGATION_REVOKED", { exact: true })).toBeVisible();
});
