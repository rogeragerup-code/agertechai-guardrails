#!/usr/bin/env node
/**
 * Self-test: run guardrails against the deliberately-broken fixture and assert
 * that every rule fires exactly once. Run: node test/run.mjs
 */
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture = join(__dirname, "fixtures");
const script = join(__dirname, "..", "guardrails.mjs");

const EXPECTED = [
  "select-star",
  "service-role-client",
  "weak-redirect",
  "dangerous-html",
  "cors-wildcard",
  "missing-rls",
  "missing-csp",
  "secret-in-log",
];

let output = "";
let exitCode = 0;
try {
  execFileSync("node", [script, fixture], { encoding: "utf8" });
} catch (e) {
  exitCode = e.status;
  output = (e.stdout || "") + (e.stderr || "");
}

const failures = [];
if (exitCode !== 1) failures.push(`expected exit 1, got ${exitCode}`);
for (const rule of EXPECTED) {
  const count = (output.match(new RegExp(`\\[${rule}\\]`, "g")) || []).length;
  if (count !== 1) failures.push(`rule "${rule}" fired ${count} time(s), expected 1`);
}
// safe_table must never be flagged.
if (/leaky_table/.test(output) === false) failures.push(`missing-rls did not name leaky_table`);
if (/safe_table/.test(output)) failures.push(`safe_table was wrongly flagged`);

if (failures.length) {
  console.error("✗ self-test FAILED:");
  for (const f of failures) console.error(`  - ${f}`);
  console.error("\n--- guardrails output ---\n" + output);
  process.exit(1);
}
console.log(`✓ self-test passed — all ${EXPECTED.length} rules fire on the fixture, safe_table not flagged.`);
