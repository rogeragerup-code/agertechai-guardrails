#!/usr/bin/env node
/**
 * AgerTechAI guardrails — the mechanical enforcement layer for the
 * "Security Floor for Next.js + Supabase + Vercel Builds" (global CLAUDE.md §8,
 * canonical source: agertechai_no/docs/engineering/compliance-stack-engineering-reference.md).
 *
 * No dependencies. Runs against the CWD of the calling repo. Exits 1 on any
 * finding so CI fails the build. Each rule maps 1:1 to a real 2025-2026 breach
 * class of AI-built SaaS.
 *
 * Run locally:  node guardrails.mjs            (scans current repo)
 *               node guardrails.mjs <path>      (scans another repo)
 *
 * Suppress a single justified line with an inline marker on that line OR the
 * line directly above it:   // guardrails-allow: <rule-id>
 * Use sparingly and only when the input is provably safe — every suppression
 * is a place a human took responsibility.
 */

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";

const ROOT = process.argv[2] ? process.argv[2] : process.cwd();

const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const SKIP_DIRS = new Set([
  "node_modules", ".next", ".git", "dist", "build", "out",
  "coverage", ".vercel", ".turbo",
]);

/** Recursively collect files under `dir` whose extension is in `exts`. */
function walk(dir, exts, acc = []) {
  if (!existsSync(dir)) return acc;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") && entry.isDirectory() && entry.name !== ".github") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, exts, acc);
    } else if (exts.has(extname(entry.name))) {
      acc.push(full);
    }
  }
  return acc;
}

const findings = [];
const warnings = [];
function flag(ruleId, file, line, message) {
  findings.push({ ruleId, file: relative(ROOT, file), line, message });
}

/** True if `lines[idx]` (or the line above) carries an allow-marker for ruleId. */
function suppressed(lines, idx, ruleId) {
  const marker = new RegExp(`guardrails-allow:\\s*${ruleId}\\b`);
  if (marker.test(lines[idx])) return true;
  if (idx > 0 && marker.test(lines[idx - 1])) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Code rules — scan src/ and app/ (cover both Next.js conventions).
// ---------------------------------------------------------------------------
const codeDirs = ["src", "app"].map((d) => join(ROOT, d)).filter(existsSync);
const codeFiles = codeDirs.flatMap((d) => walk(d, CODE_EXT));

const SELECT_STAR = /\.select\(\s*['"`]\s*\*\s*['"`]/;
const CORS_WILDCARD = /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/;
const WEAK_REDIRECT = /\.startsWith\(\s*['"]\/\/['"]\s*\)/;
const STRONG_REDIRECT = /\/\^\\\/\(\?!\\\/\)\[\^\\\\\]\*\$\//; // /^\/(?!\/)[^\\]*$/
// Rule 8 — secret in logs: a console.* call whose args reference an env secret
// or a known secret identifier. High-signal patterns only (env vars ending
// KEY/SECRET/TOKEN/PASSWORD, or compound secret var names) so prose like
// console.log("token refreshed") does NOT trip it.
const CONSOLE_CALL = /console\.(?:log|error|warn|info|debug|trace)\s*\(/;
const SECRET_IDENT =
  /process\.env\.[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CRED)[A-Z0-9_]*|\b(?:service[_-]?role[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)\b/i;

for (const file of codeFiles) {
  const text = readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  const isClient = /^\s*['"]use client['"]/m.test(text);
  const hasStrongRedirect = STRONG_REDIRECT.test(text);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const n = i + 1;

    // Rule 1 — bloated API contracts: never select('*').
    if (SELECT_STAR.test(line) && !suppressed(lines, i, "select-star")) {
      flag("select-star", file, n, "select('*') leaks internal columns and over-fetches — enumerate columns explicitly.");
    }

    // Rule 2 — stored XSS: dangerouslySetInnerHTML on untrusted (esp. AI) output.
    if (line.includes("dangerouslySetInnerHTML") && !suppressed(lines, i, "dangerous-html")) {
      flag("dangerous-html", file, n, "dangerouslySetInnerHTML renders raw HTML — allowlist with `// guardrails-allow: dangerous-html` only when input is provably safe.");
    }

    // Rule 3 — open CORS: never wildcard Allow-Origin on app routes.
    if (CORS_WILDCARD.test(line) && !suppressed(lines, i, "cors-wildcard")) {
      flag("cors-wildcard", file, n, "Access-Control-Allow-Origin: * exposes authenticated routes — scope CORS to a named allowlist.");
    }

    // Rule 4 — service-role key leak: must never reach a client bundle.
    if (isClient && /SERVICE_ROLE_KEY/.test(line) && !suppressed(lines, i, "service-role-client")) {
      flag("service-role-client", file, n, "SUPABASE_SERVICE_ROLE_KEY referenced in a \"use client\" file — service-role key is server-only.");
    }

    // Rule 5 — open redirect: weak //-guard without the canonical regex in the file.
    if (WEAK_REDIRECT.test(line) && !hasStrongRedirect && !suppressed(lines, i, "weak-redirect")) {
      flag("weak-redirect", file, n, "startsWith('//') misses /\\evil.com — use /^\\/(?!\\/)[^\\\\]*$/ to validate redirect params.");
    }

    // Rule 8 — secret in logs: never log API keys, tokens, or service-role keys.
    if (CONSOLE_CALL.test(line) && SECRET_IDENT.test(line) && !suppressed(lines, i, "secret-in-log")) {
      flag("secret-in-log", file, n, "console.* logging a secret (env key/token/service-role) — logs leak into transcripts and aggregators; redact or remove.");
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 6 — RLS on every table: aggregate create-table vs enable-RLS across ALL
// migrations (a table may be created in one file and RLS-enabled in another).
// ---------------------------------------------------------------------------
const migDir = join(ROOT, "supabase", "migrations");
if (existsSync(migDir)) {
  const created = new Map(); // bareName -> { file, line }
  const rlsEnabled = new Set(); // bareName
  const CREATE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?\w+"?\.)?"?(\w+)"?/i;
  const RLS_RE = /alter\s+table\s+(?:"?\w+"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/i;

  for (const file of walk(migDir, new Set([".sql"]))) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const c = CREATE_RE.exec(lines[i]);
      if (c && !created.has(c[1])) created.set(c[1], { file, line: i + 1 });
      const r = RLS_RE.exec(lines[i]);
      if (r) rlsEnabled.add(r[1]);
    }
  }

  for (const [name, loc] of created) {
    if (!rlsEnabled.has(name)) {
      flag("missing-rls", loc.file, loc.line, `Table "${name}" is created but never gets "enable row level security" — the Lovable CVE-2025-48757 class.`);
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 7 — CSP in middleware. Existing middleware without CSP is a hard fail;
// no middleware at all is a warning (greenfield repos may not have one yet).
// ---------------------------------------------------------------------------
const middlewareCandidates = [
  "middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
].map((p) => join(ROOT, p));
const middleware = middlewareCandidates.find(existsSync);
if (middleware) {
  if (!/Content-Security-Policy/.test(readFileSync(middleware, "utf8"))) {
    flag("missing-csp", middleware, 1, "middleware exists but sets no Content-Security-Policy header — add a nonce-based CSP.");
  }
} else {
  warnings.push("No middleware file found — a nonce-based CSP in middleware is part of the security floor.");
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------
const repoName = relative(join(ROOT, ".."), ROOT) || ROOT;
if (findings.length === 0) {
  console.log(`✓ guardrails: ${repoName} passed (${codeFiles.length} code files scanned).`);
  for (const w of warnings) console.log(`  ⚠ ${w}`);
  process.exit(0);
}

console.error(`✗ guardrails: ${findings.length} finding(s) in ${repoName}:\n`);
for (const f of findings) {
  console.error(`  [${f.ruleId}] ${f.file}:${f.line}`);
  console.error(`      ${f.message}\n`);
}
for (const w of warnings) console.error(`  ⚠ ${w}`);
console.error(`\nFix the above or suppress a provably-safe line with: // guardrails-allow: <rule-id>`);
process.exit(1);
