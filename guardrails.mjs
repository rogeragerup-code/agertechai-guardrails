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
// Rule 6b — missing-grant: a NEW public table/view/function with no explicit
// GRANT to service_role.
//
// From 2026-10-30 Supabase stops auto-granting new objects in `public` to anon,
// authenticated AND service_role (tables, views, functions, sequences). Existing
// objects keep their grants, so nothing breaks on the day — the break is the
// FIRST migration after it that forgets a grant: the Data API answers 42501,
// including for server code on the service key.
//
// ⚠ WHY service_role SPECIFICALLY, not "any grant". Measured 2026-09-29: HR, CRM,
// Aktsom and AgerTechAI already altered their default privileges so new tables
// go to service_role ONLY. Their migrations therefore grant `authenticated`
// explicitly but have never needed to grant service_role — it arrived by
// default. That is exactly the default that disappears. "Any grant" would pass
// a migration that grants authenticated and silently breaks every server path.
// Granting service_role adds no surface: it bypasses RLS anyway.
//
// ⚠ ONLY MIGRATIONS DATED >= GRANT_CUTOFF ARE CHECKED. Every older object got
// the default grants when it was created; flagging them would red all 8 repos
// with migrations (4–27 historic hits each, mostly `create or replace function`
// whose grant sits in an earlier file). Undated files can't be placed in time,
// so they are skipped with a warning rather than guessed at.
//
// A grant only counts in the SAME or a LATER file: a grant in an earlier file
// belonged to a previous incarnation of the object (or to nothing yet).
// Trigger functions are exempt (called by triggers, never over the API).
//
// ⚠ `alter default privileges … grant … to service_role` ONLY COUNTS IF DATED ON
// OR AFTER THE ENFORCEMENT DAY. On 2026-10-30 Supabase itself runs the revoke on
// the default privileges, which undoes every earlier default grant. And every
// pg_dump baseline carries those earlier grants verbatim (`ALTER DEFAULT
// PRIVILEGES FOR ROLE "postgres" … GRANT ALL ON TABLES TO "service_role"`) — the
// first draft counted them, which made this rule INERT in every repo with a
// baseline. The fleet preflight read "0 findings, identical" and measured
// nothing; a probe migration in HR-Kompis, which should have been flagged,
// passed. Only a deliberate re-grant written after the change survives it.
// ---------------------------------------------------------------------------
const GRANT_CUTOFF = "20260930";
const GRANT_ENFORCEMENT = "20261030";
if (existsSync(migDir)) {
  /** Mask comments and dollar-quoted bodies with spaces, keeping newlines, so
   *  offsets still map to line numbers and nothing inside a body is matched. */
  const mask = (sql) =>
    sql
      .replace(/\$(\w*)\$[\s\S]*?\$\1\$/g, (m) => m.replace(/[^\n]/g, " "))
      .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
      .replace(/--[^\n]*/g, (m) => " ".repeat(m.length));
  const lineOf = (text, idx) => text.slice(0, idx).split("\n").length;
  /** `"public"."x"` / `public.x` / `x` → { schema, name } (lowercased). */
  const parseName = (raw) => {
    const parts = raw.replace(/"/g, "").split(".");
    return parts.length > 1
      ? { schema: parts[0].toLowerCase(), name: parts[1].toLowerCase() }
      : { schema: "public", name: parts[0].toLowerCase() };
  };
  const statementAt = (text, idx) => {
    const end = text.indexOf(";", idx);
    return text.slice(idx, end === -1 ? text.length : end);
  };
  const NAME = String.raw`((?:"?\w+"?\.)?"?\w+"?)`;
  const CREATE_TABLE = new RegExp(String.raw`\bcreate\s+(?:(?:global\s+|local\s+)?(temp|temporary)\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?` + NAME, "gi");
  const CREATE_VIEW = new RegExp(String.raw`\bcreate\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?` + NAME, "gi");
  const CREATE_FUNC = new RegExp(String.raw`\bcreate\s+(?:or\s+replace\s+)?function\s+` + NAME + String.raw`\s*\(`, "gi");
  const GRANT_STMT = /\bgrant\s+([^;]*?)\s+on\s+([^;]*?)\s+to\s+([^;]*)/gi;
  const DEFAULT_GRANT = /\balter\s+default\s+privileges\b[^;]*?\bgrant\s+([^;]*?)\s+on\s+(tables|functions|routines|sequences)\s+to\s+([^;]*)/gi;
  const DROP = new RegExp(String.raw`\bdrop\s+(function|view|materialized\s+view|table)\s+(?:if\s+exists\s+)?` + NAME, "gi");
  // A TABLE grant only counts if service_role can WRITE: after 2026-10-30 a
  // `grant select … to authenticated, service_role` still 42501s every server
  // insert/update. Column-level grants (`select (a), update (b)`) don't count.
  const canWrite = (privs) => !/\(/.test(privs) && /\b(all|insert|update|delete)\b/i.test(privs);

  const files = walk(migDir, new Set([".sql"])).sort((a, b) => a.localeCompare(b));
  const undated = [];
  const creates = []; // { kind, name, idx, file, line, needsSeq }
  const grants = []; // { kind: "table"|"function"|"sequence"|"all-*", name, idx, write }
  const defaults = []; // { kind, idx, write }
  const seen = []; // every create in every dated file: { kind, name, idx }
  const drops = []; // { kind, name, idx }

  files.forEach((file, idx) => {
    const base = file.split(/[\\/]/).pop();
    const date = (base.match(/^(\d{8})/) || [])[1];
    if (!date) {
      undated.push(relative(ROOT, file));
      return;
    }
    const raw = readFileSync(file, "utf8");
    const text = mask(raw);
    const rawLines = raw.split(/\r?\n/);

    let m;
    GRANT_STMT.lastIndex = 0;
    while ((m = GRANT_STMT.exec(text))) {
      if (!/\bservice_role\b/i.test(m[3])) continue;
      const write = canWrite(m[1]);
      const target = m[2].trim();
      const all = target.match(/^all\s+(tables|functions|routines|sequences)\s+in\s+schema\s+"?public"?/i);
      if (all) {
        grants.push({ kind: `all-${all[1].toLowerCase().replace("routines", "functions")}`, name: "*", idx, write });
        continue;
      }
      const kindWord = (target.match(/^(table|function|sequence|procedure)\s+/i) || [])[1]?.toLowerCase() ?? "table";
      const objects = target.replace(/^(table|function|sequence|procedure)\s+/i, "").replace(/\([^)]*\)/g, "").split(",");
      for (const o of objects) {
        const n = parseName(o.trim());
        if (n.schema === "public") grants.push({ kind: kindWord === "procedure" ? "function" : kindWord, name: n.name, idx, write });
      }
    }
    DEFAULT_GRANT.lastIndex = 0;
    while ((m = DEFAULT_GRANT.exec(text))) {
      if (date >= GRANT_ENFORCEMENT && /\bservice_role\b/i.test(m[3])) {
        defaults.push({ kind: m[2].toLowerCase().replace("routines", "functions"), idx, write: canWrite(m[1]) });
      }
    }
    DROP.lastIndex = 0;
    while ((m = DROP.exec(text))) {
      const n = parseName(m[2]);
      const k = m[1].toLowerCase().startsWith("function") ? "function" : m[1].toLowerCase() === "table" ? "table" : "view";
      // Ordered by (file, offset), not file alone: a migration that drops and
      // re-creates in ONE file (HR 000062 does exactly that) must read as
      // drop-then-create, or a later `or replace` is wrongly flagged.
      if (n.schema === "public") drops.push({ kind: k, name: n.name, key: idx * 1e9 + m.index });
    }

    const fileCreates = []; // added to `seen` AFTER this file, so a create never sees itself
    const push = (kind, match, extra = {}) => {
      const n = parseName(match[match.length - 1]);
      if (n.schema !== "public") return;
      const key = idx * 1e9 + match.index;
      fileCreates.push({ kind, name: n.name, key });
      if (date < GRANT_CUTOFF) return;
      const line = lineOf(text, match.index);
      if (suppressed(rawLines, line - 1, "missing-grant")) return;
      // `create or replace` of an object an EARLIER migration created keeps its
      // ACL in Postgres — unless it was dropped since (a drop loses the ACL).
      // Without this, every body-only fix to an existing function went red.
      if (/\bor\s+replace\b/i.test(match[0])) {
        const prev = seen.filter((s) => s.kind === kind && s.name === n.name).map((s) => s.key);
        if (prev.length > 0) {
          const last = Math.max(...prev);
          if (!drops.some((d) => d.kind === kind && d.name === n.name && d.key > last && d.key < key)) return;
        }
      }
      creates.push({ kind, name: n.name, idx, file, line, ...extra });
    };
    CREATE_TABLE.lastIndex = 0;
    while ((m = CREATE_TABLE.exec(text))) {
      if (m[1]) continue; // temp table — never exposed
      const stmt = statementAt(text, m.index);
      push("table", { 0: m[0], 1: m[2], length: 2, index: m.index }, { needsSeq: /\b(?:small|big)?serial\b|\bnextval\s*\(/i.test(stmt) });
    }
    CREATE_VIEW.lastIndex = 0;
    while ((m = CREATE_VIEW.exec(text))) push("view", m);
    CREATE_FUNC.lastIndex = 0;
    while ((m = CREATE_FUNC.exec(text))) {
      if (/\breturns\s+(?:event_)?trigger\b/i.test(statementAt(text, m.index))) continue;
      push("function", m);
    }
    seen.push(...fileCreates);
  });

  /** "ok" | "none" | "read-only" (a table grant exists but service_role can't write). */
  const coverage = (kind, name, idx) => {
    const grantKind = kind === "view" ? "table" : kind;
    const allKind = grantKind === "table" ? "all-tables" : "all-functions";
    const defaultKind = grantKind === "table" ? "tables" : "functions";
    const needsWrite = kind === "table";
    const matching = [
      ...grants.filter((g) => g.idx >= idx && ((g.kind === grantKind && g.name === name) || g.kind === allKind)),
      ...defaults.filter((d) => d.idx <= idx && d.kind === defaultKind),
    ];
    if (matching.length === 0) return "none";
    return !needsWrite || matching.some((g) => g.write) ? "ok" : "read-only";
  };
  const label = { table: "Table", view: "View", function: "Function" };
  for (const c of creates) {
    const cov = coverage(c.kind, c.name, c.idx);
    if (cov === "none") {
      flag(
        "missing-grant",
        c.file,
        c.line,
        `${label[c.kind]} "${c.name}" has no GRANT … TO service_role in this or a later migration. From 2026-10-30 Supabase no longer auto-grants new public objects (not even to service_role), so the Data API — server code on the service key included — answers 42501. Grant service_role (plus authenticated/anon only where intended), or mark "-- guardrails-allow: missing-grant" if the object must stay off the API.`,
      );
    } else if (cov === "read-only") {
      flag(
        "missing-grant",
        c.file,
        c.line,
        `Table "${c.name}" is only granted READ (or column-level) access for service_role — every server insert/update/delete over the Data API answers 42501 after 2026-10-30. Grant insert/update/delete (or all) to service_role, or suppress if the table is provably read-only for the server.`,
      );
    }
    const seqGranted =
      grants.some((g) => g.idx >= c.idx && (g.kind === "sequence" || g.kind === "all-sequences")) ||
      defaults.some((d) => d.idx <= c.idx && d.kind === "sequences");
    if (c.needsSeq && !seqGranted) {
      flag(
        "missing-grant",
        c.file,
        c.line,
        `Table "${c.name}" uses serial/nextval() but no sequence is granted to service_role — inserts over the Data API fail with 42501 after 2026-10-30. Grant usage on the sequence, or use an identity column (no sequence grant needed).`,
      );
    }
  }
  if (undated.length > 0) {
    warnings.push(
      `missing-grant: ${undated.length} migration file(s) without a YYYYMMDD prefix were NOT checked (can't tell whether they predate the 2026-10-30 grant change): ${undated.slice(0, 3).join(", ")}${undated.length > 3 ? ", …" : ""}`,
    );
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

// Drop whole-line comments (`//`, `/* … */`, JSDoc `*` lines) before a
// substring search. ⚠ Until 2026-09-05 rule 7 searched the RAW file, so a
// proxy.ts with every CSP line commented out still read as "sets an enforcing
// CSP" — mutation-proved in HR-Kompis: all three header lines commented, the
// checker said passed. Same false-green the Sentry rule below documents, in
// the rule that guards the floor's most silent failure. Trailing comments on
// a code line are NOT stripped (a `//` can sit inside a string, e.g. an URL),
// so a header string mentioned only in a trailing comment still counts —
// that shape does not occur in practice, and stripping it would risk
// mangling real code.
function withoutCommentLines(raw) {
  const out = [];
  let inBlock = false;
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (inBlock) {
      if (t.includes("*/")) inBlock = false;
      continue;
    }
    if (t.startsWith("/*")) {
      if (!t.includes("*/")) inBlock = true;
      continue;
    }
    if (t.startsWith("//") || t.startsWith("*")) continue;
    out.push(line);
  }
  return out.join("\n");
}

if (edgeEntry) {
  const mwRaw = readFileSync(edgeEntry, "utf8");
  const mwText = withoutCommentLines(mwRaw);
  // Report-Only does not count — the floor requires an ENFORCING CSP in prod.
  const hasEnforcingCsp = /Content-Security-Policy(?!-Report-Only)/.test(mwText);
  // The suppression marker LIVES in a comment, so it is read from the raw text.
  const allowed = /guardrails-allow:\s*missing-csp\b/.test(mwRaw);
  if (!hasEnforcingCsp && !allowed) {
    const configCsp = ["next.config.ts", "next.config.js", "next.config.mjs"]
      .map((p) => join(ROOT, p))
      .filter(existsSync)
      .some((f) => /Content-Security-Policy(?!-Report-Only)/.test(withoutCommentLines(readFileSync(f, "utf8"))));
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
// Rule 10 — a pgTAP suite can vanish and nothing goes red.
//
// Every runner in this fleet selects suites with a GLOB. A glob describes what
// EXISTS; it cannot have an opinion about what is gone. `files.length === 0`
// catches total disappearance, but delete ONE suite of nine and the glob finds
// eight, all pass, exit 0 — nothing knows nine were expected.
//
// Measured across the fleet 2026-08-30: HR-Kompis, CRM and Aktsom carried the
// hole; agertechai-web carried it too. The local fix is a manifest enforced in
// BOTH directions. This rule makes the fleet-wide half mechanical, and — the
// reason it is worth a rule rather than four copies — it fires for ARP,
// Raad-Kompis and KI-Kompis the day they add their FIRST suite, when nobody is
// thinking about this.
//
// ⚠ WHAT THIS PROVES, AND WHAT IT DOES NOT. It checks one direction: every
// suite on disk is named in the runner. That is enough to catch "this repo has
// no manifest at all" and "a suite was added without registering it". It CANNOT
// see the other direction (listed-but-deleted) — that needs the runner to
// compare against its own list at runtime, which is the local guard's job.
// Passing this rule does not mean the local guard exists in both directions.
//
// ⚠ Comments are stripped first, in BOTH source shapes. A runner or manifest
// that merely MENTIONS a filename in prose would otherwise satisfy the rule
// while registering nothing — the exact false-green mutation-proved three times
// in the calling repos.
//
// ⚠ TWO SHAPES ARE ACCEPTED, because the fleet already converged on the better
// one and the rule must fit reality rather than the reverse. The first draft
// demanded the names live in `run.mjs`; the pre-flight against all 13 repos then
// flagged CRM and Aktsom, which BOTH have a correct manifest — in a separate
// `supabase/tests/MANIFEST` file (one filename per line, `#` for comments) read
// by the runner. A list as DATA beats a list as code, and CRM's own file argues
// why. So: names may live in run.mjs or in MANIFEST*.
// ---------------------------------------------------------------------------
const testsDir = join(ROOT, "supabase", "tests");
const suiteRunner = join(testsDir, "run.mjs");
if (existsSync(testsDir) && existsSync(suiteRunner)) {
  const entries = readdirSync(testsDir);
  const suites = entries.filter((f) => f.endsWith("_test.sql")).sort();
  const runnerRaw = readFileSync(suiteRunner, "utf8");

  if (suites.length > 0 && !/guardrails-allow:\s*test-suite-unregistered\b/.test(runnerRaw)) {
    let inBlockComment = false;
    const runnerCode = runnerRaw
      .split("\n")
      .filter((line) => {
        const t = line.trim();
        if (inBlockComment) {
          if (t.includes("*/")) inBlockComment = false;
          return false;
        }
        if (t.startsWith("/*")) {
          if (!t.includes("*/")) inBlockComment = true;
          return false;
        }
        return !t.startsWith("//") && !t.startsWith("*");
      })
      .join("\n");

    // MANIFEST files: `#` is the comment marker, one filename per line.
    const manifestCode = entries
      .filter((f) => f.startsWith("MANIFEST"))
      .map((f) => readFileSync(join(testsDir, f), "utf8"))
      .map((raw) =>
        raw
          .split("\n")
          .filter((l) => !l.trim().startsWith("#"))
          .join("\n"),
      )
      .join("\n");

    const registered = runnerCode + "\n" + manifestCode;
    const unregistered = suites.filter((f) => !registered.includes(f));
    if (unregistered.length > 0) {
      flag(
        "test-suite-unregistered",
        suiteRunner,
        1,
        `${unregistered.length} pgTAP suite(s) exist on disk but are named neither in run.mjs nor in a supabase/tests/MANIFEST file: ${unregistered.join(", ")}. ` +
          "The runner globs, and a glob cannot notice a suite that was DELETED — it finds N-1 files, passes them all, and exits 0. " +
          "Add a manifest (a const array of expected filenames) and enforce it in BOTH directions: listed-but-missing is red, and on-disk-but-unlisted is red. " +
          "The second direction is what makes the list free to live with — a new suite goes red until registered instead of being silently skipped. " +
          "Suppress with `// guardrails-allow: test-suite-unregistered` only if this repo provably has no suite-level inventory to protect.",
      );
    }
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
