import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const lockfile = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
assert.equal(lockfile.lockfileVersion, 3, "package-lock.json must use lockfile version 3");

for (const [path, entry] of Object.entries(lockfile.packages ?? {})) {
  if (!path || entry.link || entry.inBundle) continue;
  assert.match(entry.resolved ?? "", /^https:\/\/registry\.npmjs\.org\//u, `${path} must resolve from the HTTPS npm registry`);
  assert.match(entry.integrity ?? "", /^sha512-[A-Za-z0-9+/=]+$/u, `${path} must have SHA-512 integrity metadata`);
}

console.log("Dependency lockfile integrity checks passed.");
