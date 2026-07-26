import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";

const output = new URL("../.dev.vars", import.meta.url);
const force = process.argv.includes("--force");
const secret = () => randomBytes(32).toString("hex");

const contents = [
  "# Generated for local development. Never commit this file.",
  `ADMIN_BOOTSTRAP_TOKEN="${secret()}"`,
  'BOT_PROTECTION_MODE="adaptive"',
  `BOT_PROTECTION_SECRET="${secret()}"`,
  `PLATFORM_IDENTITY_SECRET="${secret()}"`,
  'PASSKEY_RP_ID="localhost"',
  'PASSKEY_ORIGIN="http://localhost:3000"',
  'WEB3_CHAIN_ID="11155111"',
  'WEB3_RPC_URL=""',
  'WEB3_RPC_HOST_ALLOWLIST=""',
  'WEB3_ESCROW_ADDRESS=""',
  'WEB3_PAYMENT_TOKEN_ADDRESS=""',
  'WEB3_CONFIRMATIONS="3"',
  "",
].join("\n");

try {
  await writeFile(output, contents, {
    encoding: "utf8",
    mode: 0o600,
    flag: force ? "w" : "wx",
  });
} catch (error) {
  if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") {
    console.error(".dev.vars already exists. Keep it, or rerun with: npm run setup:local -- --force");
    process.exitCode = 1;
  } else {
    throw error;
  }
}

if (!process.exitCode) {
  console.log("Created .dev.vars with independent local-only secrets.");
}
