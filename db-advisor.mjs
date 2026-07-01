#!/usr/bin/env node
// Supabase Advisor gate for CI (Layer 2, database side).
//
// The code checker (guardrails.mjs) can't see the live database. This runs the
// Supabase Management API advisors in two lanes:
//   • SECURITY     — fails CI on unambiguous findings (ERROR + high-signal WARN).
//   • PERFORMANCE  — ADVISORY only (never blocks): surfaces unindexed foreign
//                    keys, RLS-initplan perf (auth.<fn>() re-evaluated per row),
//                    unused/duplicate indexes — the index/RLS hygiene the static
//                    code checker structurally can't see. A missing index is a
//                    perf smell, not a vulnerability, so it is reported, not gated.
//
// SAFE BY DEFAULT:
//   - No SUPABASE_ACCESS_TOKEN / SUPABASE_PROJECT_REF set  → skip (exit 0).
//   - Advisor API unreachable / non-200                    → skip that lane
//                                                            (never blocks a deploy
//                                                            on an API hiccup).
//
// Env:
//   SUPABASE_ACCESS_TOKEN  (secret) — Supabase personal/management access token
//   SUPABASE_PROJECT_REF   — project ref to audit
//
// Suppress a verified-safe finding: add its `cache_key` to .guardrails-db-allow
// (one per line; `#` comments allowed) in the calling repo root.

import { readFileSync, statSync } from "node:fs";

const token = process.env.SUPABASE_ACCESS_TOKEN;
const ref = process.env.SUPABASE_PROJECT_REF;
const root = process.argv[2] || ".";

// Detect whether the calling repo actually uses Supabase, so an unconfigured
// advisor gate becomes a REMINDER (not a silent skip) exactly where it's needed
// — including brand-new repos that added Supabase but never wired the gate.
function usesSupabase(dir) {
  try {
    const pkg = JSON.parse(readFileSync(`${dir}/package.json`, "utf8"));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    if (Object.keys(deps).some((d) => d.startsWith("@supabase/"))) return true;
  } catch {
    /* no/unreadable package.json */
  }
  try {
    if (statSync(`${dir}/supabase`).isDirectory()) return true;
  } catch {
    /* no supabase/ dir */
  }
  return false;
}

if (!token || !ref) {
  if (usesSupabase(root)) {
    const missing = [];
    if (!ref) missing.push("the `supabase_project_ref` input in guardrails.yml");
    if (!token) missing.push("the `SUPABASE_ACCESS_TOKEN` repo secret");
    const msg =
      `This repo uses Supabase but the DB Security Advisor gate isn't fully wired — missing ${missing.join(" + ")}. ` +
      `Wire it so schema regressions are caught in CI (engineering reference §1.6 / CLAUDE.md rule 22). Reminder only — not blocking.`;
    // GitHub Actions annotation → surfaces in the Checks/PR UI, not just the log.
    console.log(`::warning title=Supabase DB advisor gate not wired::${msg}`);
    console.log(`[db-advisor] ⚠ ${msg}`);
  } else {
    console.log(
      "[db-advisor] skipped — no Supabase usage detected (no @supabase/* dependency or supabase/ directory).",
    );
  }
  process.exit(0);
}

// High-signal SECURITY WARN lints treated as build failures — these are almost
// never intentional (see engineering reference §1.6).
const BLOCK_WARN = new Set([
  "anon_security_definer_function_executable", // anon can call a SECURITY DEFINER fn via /rpc
  "rls_policy_always_true", // INSERT/UPDATE/DELETE policy with USING/WITH CHECK (true)
]);

let allow = new Set();
try {
  allow = new Set(
    readFileSync(`${root}/.guardrails-db-allow`, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#")),
  );
} catch {
  /* no allow file — fine */
}

// Fetch one advisor lane. Returns null on any error / non-200 so the caller can
// skip that lane — an API hiccup must never block a deploy.
async function fetchLints(lane) {
  const url = `https://api.supabase.com/v1/projects/${ref}/advisors/${lane}`;
  try {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) {
      console.log(`[db-advisor] ${lane} advisor returned HTTP ${res.status} — skipping that lane.`);
      return null;
    }
    const body = await res.json();
    return body.lints ?? body.result?.lints ?? (Array.isArray(body) ? body : []);
  } catch (e) {
    console.log(`[db-advisor] ${lane} advisor fetch failed (${e.message}) — skipping that lane.`);
    return null;
  }
}

function notAllowed(l) {
  return !(l.cache_key && allow.has(l.cache_key));
}

// ── SECURITY lane (can fail the build) ──────────────────────────────────────
const secLints = await fetchLints("security");
if (secLints === null) process.exit(0); // API hiccup on the blocking lane — don't block

const fails = [];
const secAdvisories = [];
for (const l of secLints.filter(notAllowed)) {
  const level = String(l.level || "").toUpperCase();
  if (level === "ERROR" || BLOCK_WARN.has(l.name)) fails.push(l);
  else secAdvisories.push(l);
}

if (secAdvisories.length) {
  console.log(`\n[db-advisor] security: ${secAdvisories.length} advisory finding(s) (not blocking — review per §1.6):`);
  for (const l of secAdvisories) {
    console.log(`  · ${l.level} ${l.name}: ${l.detail ?? l.title ?? ""}`);
  }
}

// ── PERFORMANCE lane (advisory only — never blocks) ─────────────────────────
// Index/RLS hygiene the static code checker can't see. Surfaced, not gated.
const perfLints = await fetchLints("performance");
if (perfLints) {
  const shown = perfLints.filter(notAllowed);
  if (shown.length) {
    console.log(`\n[db-advisor] performance: ${shown.length} advisory finding(s) (not blocking — index/RLS hygiene):`);
    for (const l of shown) {
      console.log(`  · ${l.level} ${l.name}: ${l.detail ?? l.title ?? ""}`);
    }
  }
}

// ── Verdict (only the security lane can fail the build) ─────────────────────
if (fails.length) {
  console.error(`\n[db-advisor] ${fails.length} BLOCKING security finding(s):`);
  for (const l of fails) {
    console.error(`  ✗ ${l.level} ${l.name}: ${l.detail ?? l.title ?? ""}`);
    if (l.remediation) console.error(`      ${l.remediation}`);
  }
  console.error(
    "\nFix these, or — if verified safe — add the finding's cache_key to .guardrails-db-allow.",
  );
  process.exit(1);
}

console.log("\n[db-advisor] OK — no blocking security advisor findings.");
