#!/usr/bin/env node
/**
 * Self-test: run guardrails against deliberately-broken fixtures and assert
 * every rule fires the expected number of times. Run: node test/run.mjs
 */
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const script = join(__dirname, "..", "guardrails.mjs");

function run(fixtureDir) {
  try {
    const stdout = execFileSync("node", [script, join(__dirname, fixtureDir)], { encoding: "utf8" });
    return { exitCode: 0, output: stdout };
  } catch (e) {
    return { exitCode: e.status, output: (e.stdout || "") + (e.stderr || "") };
  }
}

const failures = [];
function assert(cond, msg) {
  if (!cond) failures.push(msg);
}
function count(output, rule) {
  return (output.match(new RegExp(`\\[${rule}\\]`, "g")) || []).length;
}

// ── Main fixture: every rule fires; hardened regexes catch the variants ─────
const main = run("fixtures");
assert(main.exitCode === 1, `fixtures: expected exit 1, got ${main.exitCode}`);
const EXPECTED = {
  "select-star": 3, //         bad.tsx + embedded-resource form + no-spill line
  "dangerous-html": 1,
  "cors-wildcard": 4, //       bad.tsx + lowercase + backtick + next.config key/value
  "service-role-client": 1,
  "weak-redirect": 1,
  "secret-in-log": 2, //       bad.tsx + supabase/functions edge fn
  "missing-rls": 1,
  "missing-csp": 1,
};
for (const [rule, expected] of Object.entries(EXPECTED)) {
  const got = count(main.output, rule);
  if (got !== expected) failures.push(`fixtures: rule "${rule}" fired ${got} time(s), expected ${expected}`);
}
assert(/leaky_table/.test(main.output), "fixtures: missing-rls did not name leaky_table");
for (const t of ["safe_table", "pgdump_table", "allowed_table", "ghost_table"]) {
  assert(!main.output.includes(t), `fixtures: ${t} was wrongly flagged`);
}
assert(
  /vercel\.json sets Access-Control-Allow-Origin/.test(main.output),
  "fixtures: vercel.json wildcard warning missing",
);

// ── Report-Only CSP must NOT satisfy missing-csp ─────────────────────────────
const reportOnly = run("fixtures-csp-report-only");
assert(reportOnly.exitCode === 1, `csp-report-only: expected exit 1, got ${reportOnly.exitCode}`);
assert(count(reportOnly.output, "missing-csp") === 1, "csp-report-only: missing-csp did not fire");

// ── missing-csp suppression path (marker anywhere in the middleware file) ───
const suppressedCsp = run("fixtures-csp-suppressed");
assert(suppressedCsp.exitCode === 0, `csp-suppressed: expected exit 0, got ${suppressedCsp.exitCode}`);

if (failures.length) {
  console.error("✗ self-test FAILED:");
  for (const f of failures) console.error(`  - ${f}`);
  console.error("\n--- fixtures output ---\n" + main.output);
  console.error("\n--- csp-report-only output ---\n" + reportOnly.output);
  process.exit(1);
}
console.log(
  `✓ self-test passed — all ${Object.keys(EXPECTED).length} rules fire at expected counts; ` +
    `safe/pg_dump/suppressed/commented tables not flagged; Report-Only rejected; missing-csp suppression honored.`,
);
