#!/usr/bin/env node
// Owner-controlled local CLI tool to safely set or reset an admin password on project iqdzokybhggiilzscnxv.
// Usage: node scripts/set-admin-password.mjs <username> [--force-change]
// Reads the new password from an interactive hidden prompt (never passed on the command line or stored in git).

import { webcrypto, randomBytes, pbkdf2Sync, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import readline from "node:readline";

const PROJECT_REF = "iqdzokybhggiilzscnxv";
const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSWORD_LEN = 12;
const LEGACY_SALT = "astro-world-salt-2026";
const LEAKED_SEED_HASH = "db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393";

const username = (process.argv[2] || "").trim().toLowerCase();
const forceChange = process.argv.includes("--force-change");

if (!username) {
  console.error("Usage: node scripts/set-admin-password.mjs <username> [--force-change]");
  process.exit(1);
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write(query);
    rl._writeToOutput = () => {};
    rl.question("", (answer) => {
      process.stdout.write("\n");
      rl.close();
      resolve(answer);
    });
  });
}

const pwd1 = await promptHidden(`Enter new password for '${username}' (min ${MIN_PASSWORD_LEN} chars): `);
const pwd2 = await promptHidden(`Confirm new password for '${username}': `);

if (pwd1 !== pwd2) {
  console.error("Error: Passwords do not match.");
  process.exit(1);
}
if (pwd1.length < MIN_PASSWORD_LEN) {
  console.error(`Error: Password must be at least ${MIN_PASSWORD_LEN} characters.`);
  process.exit(1);
}
const legacyCheck = createHash("sha256").update(LEGACY_SALT + pwd1).digest("hex");
if (legacyCheck === LEAKED_SEED_HASH) {
  console.error("Error: Cannot use the leaked default password.");
  process.exit(1);
}

const salt = randomBytes(16);
const derived = pbkdf2Sync(pwd1, salt, PBKDF2_ITERATIONS, 32, "sha256");
const formattedHash = `pbkdf2$${PBKDF2_ITERATIONS}$${salt.toString("hex")}$${derived.toString("hex")}`;

const out = execFileSync(
  "npx",
  ["supabase", "projects", "api-keys", "--project-ref", PROJECT_REF, "-o", "json"],
  { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
);
const keys = JSON.parse(out);
const srk = keys.find((k) => k.name === "service_role")?.api_key;
if (!srk) {
  console.error("Error: Could not retrieve service_role key from Supabase CLI.");
  process.exit(1);
}

const nowIso = new Date().toISOString();
const res = await fetch(
  `https://${PROJECT_REF}.supabase.co/rest/v1/admins?username=eq.${encodeURIComponent(username)}`,
  {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      apikey: srk,
      Authorization: `Bearer ${srk}`,
      Prefer: "return=representation",
    },
    body: JSON.stringify({
      password_hash: formattedHash,
      must_change_password: forceChange,
      session_invalidated_at: nowIso,
    }),
  }
);

const updated = await res.json();
if (!res.ok || !Array.isArray(updated) || updated.length === 0) {
  console.error("Error: Could not update admin account (check that username exists).");
  process.exit(1);
}

console.log(
  `✅ Password updated for @${updated[0].username} (${updated[0].role}) with PBKDF2-SHA256 (${PBKDF2_ITERATIONS} iterations) and all prior sessions invalidated.`
);
