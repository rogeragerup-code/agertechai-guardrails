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
  // The line above only counts when it is a standalone comment (incl. the JSX
  // form `{/* ... */}`) — an inline marker on a flagged code line must not
  // spill onto the next line.
  if (idx > 0 && marker.test(lines[idx - 1]) && /^\s*(?:\{\s*\/\*|\/\/|\/\*|\*|--|#)/.test(lines[idx - 1])) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Code rules — scan every directory that can reach production: both Next.js
// conventions (src/, app/, pages/), shared code (lib/, components/, server/),
// and Supabase edge functions (a prime service-role-key location). Plus
// next.config.* at the root — that's where Next.js CORS headers usually live.
// ---------------------------------------------------------------------------
const codeDirs = ["src", "app", "pages", "lib", "components", "server", join("supabase", "functions")]
  .map((d) => join(ROOT, d))
  .filter(existsSync);
const rootConfigs = ["next.config.js", "next.config.mjs", "next.config.ts"]
  .map((p) => join(ROOT, p))
  .filter(existsSync);
const codeFiles = [...codeDirs.flatMap((d) => walk(d, CODE_EXT)), ...rootConfigs];

// Leading wildcard, bare (`'*'`) or embedded-resource form (`'*, relation(*)'`).
const SELECT_STAR = /\.select\(\s*(['"`])\s*\*\s*(?:,|\1)/;
const CORS_WILDCARD = /Access-Control-Allow-Origin['"`]?\s*[:,]\s*['"`]\*['"`]/i;
// The Next.js headers() form — `{ key: 'Access-Control-Allow-Origin', value: '*' }`
// — where key and value may sit on the same or nearby lines.
const CORS_KEY = /key\s*:\s*['"`]Access-Control-Allow-Origin['"`]/i;
const CORS_VALUE_STAR = /value\s*:\s*['"`]\*['"`]/;
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
    } else if (
      CORS_KEY.test(line) &&
      [line, lines[i + 1] ?? "", lines[i + 2] ?? ""].some((l) => CORS_VALUE_STAR.test(l)) &&
      !suppressed(lines, i, "cors-wildcard")
    ) {
      flag("cors-wildcard", file, n, "Access-Control-Allow-Origin: * (headers() key/value form) exposes authenticated routes — scope CORS to a named allowlist.");
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
  // ALTER TABLE [IF EXISTS] [ONLY] — pg_dump emits the ONLY form.
  const RLS_RE = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?\w+"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/i;

  for (const file of walk(migDir, new Set([".sql"]))) {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      // Strip SQL comments so commented-out DDL is never counted; suppression
      // markers live in comments, so suppressed() below reads the raw line.
      const code = lines[i].replace(/--.*$/, "");
      const c = CREATE_RE.exec(code);
      if (c && !created.has(c[1]) && !suppressed(lines, i, "missing-rls")) {
        created.set(c[1], { file, line: i + 1 });
      }
      const r = RLS_RE.exec(code);
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
// Rule 7 — CSP in the edge entrypoint (proxy on Next 16, middleware before it).
//
// ⚠ Next 16 RENAMED this convention from `middleware` to `proxy`. Checking only
// for `middleware` meant every migrated repo silently dropped OUT of this rule:
// the file was never found, so `missing-csp` could not fire, and the only
// signal was a warning that read like a greenfield notice. HR-Kompis ran a day
// with no CI-verified CSP floor that way (2026-08-21) — the rule looked green
// because it had stopped looking.
//
// Severity ladder, deliberately not all-or-nothing:
//   enforcing CSP in the file          → clean
//   no CSP anywhere                    → FAIL
//   CSP only in next.config            → WARN, not fail. Reference §1.4: a
//     static, no-auth marketing surface may keep a static CSP there on purpose,
//     because a nonce forces per-request dynamic rendering and kills ISR/PPR.
//     The checker cannot tell a marketing site from an authenticated product,
//     so it says so instead of guessing — failing here would red two green
//     repos (agertechai-web, agerup.it) for a decision that was correct.
//   no file at all                     → WARN (greenfield repos may lack one)
// ---------------------------------------------------------------------------
const MIDDLEWARE_NAMES = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];
const PROXY_NAMES = ["proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"];

const middlewareFiles = MIDDLEWARE_NAMES.map((p) => join(ROOT, p)).filter(existsSync);
const proxyFiles = PROXY_NAMES.map((p) => join(ROOT, p)).filter(existsSync);
// Prefer the proxy spelling when both exist — it is the one Next 16 wires up.
const edgeEntry = proxyFiles[0] ?? middlewareFiles[0] ?? null;

// Both spellings present: Next resolves ONE and ignores the other in silence.
// This exact duplicate shipped HR-Kompis to production 404ing every unprefixed
// route in 2026-06, and no build output mentioned it. Mechanically checkable,
// so it belongs here rather than in a human checklist.
if (middlewareFiles.length && proxyFiles.length) {
  flag(
    "duplicate-edge-entry",
    edgeEntry,
    1,
    `both a middleware.* (${relative(ROOT, middlewareFiles[0])}) and a proxy.* (${relative(ROOT, proxyFiles[0])}) entrypoint exist — Next resolves one and silently ignores the other, which can drop your CSP and locale routing in production. Keep exactly one (proxy.* on Next 16).`,
  );
}

if (edgeEntry) {
  const mwText = readFileSync(edgeEntry, "utf8");
  // Report-Only does not count — the floor requires an ENFORCING CSP in prod.
  const hasEnforcingCsp = /Content-Security-Policy(?!-Report-Only)/.test(mwText);
  const allowed = /guardrails-allow:\s*missing-csp\b/.test(mwText);
  if (!hasEnforcingCsp && !allowed) {
    const configCsp = ["next.config.ts", "next.config.js", "next.config.mjs"]
      .map((p) => join(ROOT, p))
      .filter(existsSync)
      .some((f) => /Content-Security-Policy(?!-Report-Only)/.test(readFileSync(f, "utf8")));
    if (configCsp) {
      warnings.push(
        `${relative(ROOT, edgeEntry)} sets no CSP, but next.config does. That is the documented exception for a STATIC, no-auth surface — an authenticated product needs the nonce-CSP in the proxy itself.`,
      );
    } else {
      flag("missing-csp", edgeEntry, 1, "proxy/middleware exists but sets no enforcing Content-Security-Policy header, and neither does next.config (Report-Only doesn't count) — add a nonce-based CSP, or add `// guardrails-allow: missing-csp` if this is provably deliberate.");
    }
  }
} else {
  warnings.push("No proxy.* or middleware.* file found — a nonce-based CSP there is part of the security floor.");
}

// ---------------------------------------------------------------------------
// Rule 9 — Sentry installed but no root error boundary. WARNING only, for the
// same reason as the middleware case: several repos already ship Sentry without
// this file, and gating on it would red their CI in one go the moment @v1 moves.
//
// Why it is worth surfacing at all: a React RENDER error that escapes the root
// layout never fires window.onerror — the error boundary catches it first — so a
// pre-init buffer listening on window error/unhandledrejection is structurally
// blind to it. Without app/global-error.tsx those crashes are reported NOWHERE,
// and the app looks healthy because every server-side check still returns 200.
// Found on agertechai-web 2026-08-14; Sentry's own build warning had been
// scrolling past unread for weeks.
// ---------------------------------------------------------------------------
const pkgPath = join(ROOT, "package.json");
if (existsSync(pkgPath)) {
  let pkg = null;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    // An unparseable package.json is a different problem, and not this rule's to police.
  }
  const deps = pkg ? { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) } : {};
  if (deps["@sentry/nextjs"]) {
    const appDir = ["app", "src/app"].map((d) => join(ROOT, d)).find(existsSync);
    if (appDir) {
      const hasBoundary = ["tsx", "jsx", "ts", "js"].some((ext) =>
        existsSync(join(appDir, `global-error.${ext}`)),
      );
      if (!hasBoundary) {
        warnings.push(
          "@sentry/nextjs is installed but there is no app/global-error.tsx — a React render error escaping the root layout never fires window.onerror, so it is reported nowhere. Add the boundary, and force SDK init inside it if your Sentry init is deferred.",
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 10 — Sentry.init() that does not pass a beforeSend scrubber.
//
// WHY THIS IS A GATE AND NOT A CHECKLIST ITEM. A repo can have a correct,
// well-tested credential scrubber and still send unscrubbed events, because
// nothing links "the scrubber works" to "the scrubber is wired in". Measured in
// crm-agertechai 2026-08-27: deleting `beforeSend` plus its import from
// sentry.server.config.ts left the scrubber's own 12-gate test suite at 12/12,
// tsc at 0, eslint at 0 and guardrails at 0. Every gate green over a scrubber
// connected to nothing.
//
// Sentry events are logs (floor rule 16: structured, secret-free). A URL with a
// `?code=` or `?token=` in a breadcrumb is exactly what the scrubber exists to
// redact, and an unwired scrubber redacts nothing.
//
// BLOCKING, not a warning — measured across all 12 wired repos before shipping:
// 18 Sentry.init calls in 6 repos, every one already passing beforeSend. The
// other 6 repos have no Sentry at all, so the rule self-scopes and stays silent
// there. Zero repos break on adoption.
//
// TWO IMPLEMENTATION DETAILS THAT ARE NOT OPTIONAL, both learned the hard way:
//   1. Comments are stripped first. A raw substring search is satisfied by a
//      comment that merely mentions beforeSend — that exact false-green was
//      mutation-proved three times in one day in the calling repo.
//   2. The match is scoped to the init call by paren depth, not to the file.
//      "beforeSend appears somewhere in this file" is a different claim from
//      "this init call passes it", and only the second one is the property.
// ---------------------------------------------------------------------------
const sentryConfigs = ["server", "edge", "client"]
  .flatMap((k) => [`sentry.${k}.config.ts`, `sentry.${k}.config.js`, `sentry.${k}.config.mjs`])
  .map((p) => join(ROOT, p))
  .filter(existsSync);

// codeFiles covers src/app/lib/etc, but Sentry's generated configs live at the
// repo ROOT and are not in it — miss them and the rule reads clean on the very
// files most likely to hold an init call.
for (const file of [...new Set([...codeFiles, ...sentryConfigs])]) {
  const raw = readFileSync(file, "utf8");
  if (!raw.includes("Sentry.init(")) continue;
  if (/guardrails-allow:\s*sentry-scrub-disconnected\b/.test(raw)) continue;

  const lines = [];
  let inBlockComment = false;
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (inBlockComment) {
      if (t.includes("*/")) inBlockComment = false;
      continue;
    }
    if (t.startsWith("/*")) {
      if (!t.includes("*/")) inBlockComment = true;
      continue;
    }
    if (t.startsWith("//") || t.startsWith("*")) continue;
    lines.push(line);
  }

  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes("Sentry.init(")) continue;
    let depth = 0;
    const call = [];
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === "(") depth++;
        else if (ch === ")") depth--;
      }
      call.push(lines[j]);
      if (depth === 0 && call.length > 1) break;
    }
    if (!call.some((l) => l.includes("beforeSend"))) {
      flag(
        "sentry-scrub-disconnected",
        file,
        i + 1,
        "Sentry.init() does not pass `beforeSend` — events reach Sentry unscrubbed, and a credential scrubber elsewhere in the repo cannot help if nothing calls it. Wire it (`beforeSend: scrubSentryEvent`), or add `// guardrails-allow: sentry-scrub-disconnected` if this init provably handles no user data.",
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 3 (config side) — wildcard CORS in vercel.json headers. WARNING only:
// `*` on public static assets (fonts, images) is legitimate, and JSON has no
// comment syntax for a suppression marker — so surface it, don't gate on it.
// ---------------------------------------------------------------------------
const vercelJson = join(ROOT, "vercel.json");
if (existsSync(vercelJson)) {
  const raw = readFileSync(vercelJson, "utf8");
  try {
    const hasWildcard = (function find(node) {
      if (Array.isArray(node)) return node.some(find);
      if (node && typeof node === "object") {
        if (
          typeof node.key === "string" &&
          node.key.toLowerCase() === "access-control-allow-origin" &&
          node.value === "*"
        ) return true;
        return Object.values(node).some(find);
      }
      return false;
    })(JSON.parse(raw));
    if (hasWildcard) {
      warnings.push("vercel.json sets Access-Control-Allow-Origin: * — fine for public static assets, never for authenticated/API routes. Verify the matched paths.");
    }
  } catch {
    /* unparseable vercel.json — Vercel itself will reject it */
  }
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
