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

// ── Next 16 renamed middleware → proxy. The checker must SEE the new name ───
// Before this, a migrated repo dropped silently out of rule 7: no file found,
// so missing-csp could not fire, and CI looked green because it had stopped
// looking. Each case below is one rung of the severity ladder.

// proxy.* WITH an enforcing CSP — the target shape, must be clean.
const proxyCsp = run("fixtures-proxy-csp");
assert(proxyCsp.exitCode === 0, `proxy-csp: expected exit 0, got ${proxyCsp.exitCode}`);
assert(
  !/No proxy\.\* or middleware/.test(proxyCsp.output),
  "proxy-csp: checker did not recognise src/proxy.ts as the edge entrypoint",
);

// proxy.* with NO CSP anywhere — must be a hard fail, not a warning.
const proxyNoCsp = run("fixtures-proxy-no-csp");
assert(proxyNoCsp.exitCode === 1, `proxy-no-csp: expected exit 1, got ${proxyNoCsp.exitCode}`);
assert(count(proxyNoCsp.output, "missing-csp") === 1, "proxy-no-csp: missing-csp did not fire on a proxy.ts");

// proxy.* where the CSP header exists ONLY in comments — must fail. Until
// 2026-09-05 the rule searched the raw file, so commenting out every header
// line still read as "enforcing CSP present" (mutation-proved on HR-Kompis).
// This is the "can the word sit in a comment while the code changed?" test the
// Sentry and suite rules already have; rule 7 lacked it.
const proxyCommentedCsp = run("fixtures-proxy-csp-commented");
assert(proxyCommentedCsp.exitCode === 1, `proxy-csp-commented: expected exit 1, got ${proxyCommentedCsp.exitCode}`);
assert(
  count(proxyCommentedCsp.output, "missing-csp") === 1,
  "proxy-csp-commented: a CSP header present ONLY in comments was accepted — comment stripping in rule 7 is broken, which is the exact false-green this fixture exists to prevent",
);

// proxy.* without CSP but next.config has one — documented static-surface
// exception (reference §1.4). Must WARN and must NOT gate: failing here would
// red agertechai-web and agerup.it for a decision that was deliberate.
const proxyConfigCsp = run("fixtures-proxy-config-csp");
assert(
  proxyConfigCsp.exitCode === 0,
  `proxy-config-csp: expected exit 0 (warning, not a gate), got ${proxyConfigCsp.exitCode}`,
);
assert(
  /next\.config does/.test(proxyConfigCsp.output),
  "proxy-config-csp: the next.config-CSP warning did not fire",
);
assert(
  count(proxyConfigCsp.output, "missing-csp") === 0,
  "proxy-config-csp: missing-csp fired even though next.config sets a CSP",
);

// BOTH spellings present — Next resolves one and ignores the other in silence.
// This duplicate shipped HR-Kompis to prod 404ing every unprefixed route.
const duplicateEdge = run("fixtures-duplicate-edge");
assert(duplicateEdge.exitCode === 1, `duplicate-edge: expected exit 1, got ${duplicateEdge.exitCode}`);
assert(
  count(duplicateEdge.output, "duplicate-edge-entry") === 1,
  "duplicate-edge: duplicate-edge-entry did not fire when both middleware.ts and src/proxy.ts exist",
);

// ── Sentry without app/global-error.* — WARNS but must NOT gate ─────────────
const sentryNoBoundary = run("fixtures-sentry-no-boundary");
assert(
  sentryNoBoundary.exitCode === 0,
  `sentry-no-boundary: expected exit 0 (warning, not a gate), got ${sentryNoBoundary.exitCode}`,
);
assert(
  /no app\/global-error\.tsx/.test(sentryNoBoundary.output),
  "sentry-no-boundary: global-error warning did not fire",
);
// And the inverse: no Sentry dependency means no warning, so repos without it stay quiet.
assert(
  !/global-error/.test(suppressedCsp.output),
  "csp-suppressed: global-error warning fired on a fixture with no @sentry/nextjs (false positive)",
);

// ---------------------------------------------------------------------------
// Rule 10 — sentry-scrub-disconnected.
//
// Three assertions, because the interesting one is the middle: a rule that only
// checked "does beforeSend appear in this file" would pass the comment-only
// fixture, and that false-green is the exact failure this rule exists to avoid.
// The third asserts the inverse — a correctly wired init must stay silent, or
// the rule is just noise that teaches people to suppress it.
// ---------------------------------------------------------------------------
const sentryNoScrub = run("fixtures-sentry-no-scrub");
// Use the existing count() helper, which anchors on the [rule-id] HEADER.
// A bare substring count reads 2 findings as 4: each finding prints the rule id
// twice — once in the header, once inside the guardrails-allow hint.
const noScrubHits = count(sentryNoScrub.output, "sentry-scrub-disconnected");
assert(
  noScrubHits === 2,
  `sentry-no-scrub: expected exactly 2 findings (missing + comment-only), got ${noScrubHits}`,
);
assert(
  /sentry\.server\.config\.ts/.test(sentryNoScrub.output),
  "sentry-no-scrub: did not flag the init with no beforeSend at all",
);
assert(
  /sentry\.edge\.config\.ts/.test(sentryNoScrub.output),
  "sentry-no-scrub: beforeSend present ONLY in a comment was accepted — comment stripping is broken, which is the false-green this rule exists to prevent",
);
assert(
  !/sentry\.client\.config\.ts/.test(sentryNoScrub.output),
  "sentry-no-scrub: a correctly wired init was flagged (false positive)",
);

const sentrySuppressed = run("fixtures-sentry-scrub-suppressed");
assert(
  !/sentry-scrub-disconnected/.test(sentrySuppressed.output),
  "sentry-scrub-suppressed: guardrails-allow marker was not honored",
);

// ── test-suite-unregistered — a glob cannot notice a DELETED suite ──────────
// Three fixtures, because two would not discriminate: firing on the broken one
// proves nothing unless the correct one is proven to PASS, and neither proves
// that a filename appearing only in PROSE is rejected.
const suiteUnreg = run("fixtures-suite-unregistered");
assert(suiteUnreg.exitCode === 1, `suite-unregistered: expected exit 1, got ${suiteUnreg.exitCode}`);
assert(
  count(suiteUnreg.output, "test-suite-unregistered") === 1,
  "suite-unregistered: rule did not fire on a runner that globs without a manifest",
);
for (const s of ["01_alpha_test.sql", "02_beta_test.sql"]) {
  assert(suiteUnreg.output.includes(s), `suite-unregistered: did not name ${s}`);
}

const suiteReg = run("fixtures-suite-registered");
assert(
  !/test-suite-unregistered/.test(suiteReg.output),
  "suite-registered: a runner that DOES name every suite was flagged — without this the rule could fire unconditionally and still look correct",
);

const suiteComment = run("fixtures-suite-comment-only");
assert(
  count(suiteComment.output, "test-suite-unregistered") === 1,
  "suite-comment-only: suite names present ONLY in comments were accepted as a manifest — comment stripping is broken, and that is the exact false-green this rule exists to prevent",
);

// The shape the fleet actually uses: a separate supabase/tests/MANIFEST file
// (one filename per line, `#` comments) read by the runner. The first draft of
// this rule demanded the names live in run.mjs and would have turned CRM and
// Aktsom red the moment the pin moved — caught by a pre-flight against all 13
// repos before anything was pushed, not by CI afterwards.
const suiteManifest = run("fixtures-suite-manifest-file");
assert(
  !/test-suite-unregistered/.test(suiteManifest.output),
  "suite-manifest-file: a MANIFEST-file manifest was rejected — this is the shape CRM and Aktsom use",
);

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
