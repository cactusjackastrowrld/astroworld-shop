#!/usr/bin/env node
// Rotates ADMIN_JWT_SECRET (96 hex chars) and SHOP_WEBHOOK_SECRET (64 hex chars) on project iqdzokybhggiilzscnxv,
// redeploys shop-admin and shop-bot, and re-registers the Telegram webhook with the new SHOP_WEBHOOK_SECRET.
// Never prints any secret values.

import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";

const PROJECT_REF = "iqdzokybhggiilzscnxv";

const newAdminJwtSecret = randomBytes(48).toString("hex"); // 96 chars (>= 64)
const newWebhookSecret = randomBytes(32).toString("hex");  // 64 chars

console.log(`Setting rotated ADMIN_JWT_SECRET (${newAdminJwtSecret.length} chars) and SHOP_WEBHOOK_SECRET (${newWebhookSecret.length} chars) on ${PROJECT_REF}...`);

execFileSync(
  "npx",
  [
    "supabase",
    "secrets",
    "set",
    "--project-ref",
    PROJECT_REF,
    "--yes",
    `ADMIN_JWT_SECRET=${newAdminJwtSecret}`,
    `SHOP_WEBHOOK_SECRET=${newWebhookSecret}`,
  ],
  { stdio: ["ignore", "pipe", "inherit"] }
);

console.log("Deploying shop-admin and shop-bot so the new secrets take effect...");
execFileSync(
  "npx",
  ["supabase", "functions", "deploy", "shop-admin", "--project-ref", PROJECT_REF, "--no-verify-jwt", "--yes"],
  { stdio: "inherit" }
);
execFileSync(
  "npx",
  ["supabase", "functions", "deploy", "shop-bot", "--project-ref", PROJECT_REF, "--no-verify-jwt", "--yes"],
  { stdio: "inherit" }
);

console.log("Re-registering Telegram webhook with rotated SHOP_WEBHOOK_SECRET...");
const syncRes = await fetch(`https://${PROJECT_REF}.supabase.co/functions/v1/shop-admin/bot/sync-webhook`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-admin-token": newAdminJwtSecret,
  },
}).then((r) => r.json());

console.log("Telegram webhook sync result:", JSON.stringify(syncRes));
if (!syncRes?.ok) {
  process.exit(1);
}
console.log("✅ Secrets rotated, all prior admin tokens invalidated, and Telegram webhook updated.");
