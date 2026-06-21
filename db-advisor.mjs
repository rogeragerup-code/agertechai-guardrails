#!/usr/bin/env node
// Supabase Security Advisor gate for CI (Layer 2, database side).
//
// The code checker (guardrails.mjs) can't see the live database. This runs the
// Supabase Management API security advisors and fails CI on the unambiguous
// findings, reports the nuanced ones, and is SAFE BY DEFAULT:
//   - No SUPABASE_ACCESS_TOKEN / SUPABASE_PROJECT_REF set  → skip (exit 0).
//   - Advisor API unreachable / non-200                    → skip (exit 0, never
//                                                            blocks a deploy on
//                                                            an API hiccup).
//
// Env:
//   SUPABASE_ACCESS_TOKEN  (secret) — Supabase personal/management access token
//   SUPABASE_PROJECT_REF   — project ref to audit
//
// Suppress a verified-safe finding: add its `cache_key` to .guardrails-db-allow
// (one per line; `#` comments allowed) in the calling repo root.

import { readFileSync } from "node:fs";

const token = process.env.SUPABASE_ACCESS_TOKEN;
const ref = process.env.SUPABASE_PROJECT_REF;
const root = process.argv[2] || ".";

if (!token || !ref) {
  console.log(
    "[db-advisor] skipped — set SUPABASE_ACCESS_TOKEN (secret) + SUPABASE_PROJECT_REF to enable the database security check.",
  );
  process.exit(0);
}

// High-signal WARN lints treated as build failures — these are almost never
// intentional (see engineering reference §1.6).
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

const url = `https://api.supabase.com/v1/projects/${ref}/advisors/security`;
let lints;
try {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    console.log(
      `[db-advisor] advisor API returned HTTP ${res.status} — skipping (not blocking the build).`,
    );
    process.exit(0);
  }
  const body = await res.json();
  lints = body.lints ?? body.result?.lints ?? (Array.isArray(body) ? body : []);
} catch (e) {
  console.log(
    `[db-advisor] advisor fetch failed (${e.message}) — skipping (not blocking the build).`,
  );
  process.exit(0);
}

const fails = [];
const advisories = [];
for (const l of lints) {
  if (l.cache_key && allow.has(l.cache_key)) continue;
  const level = String(l.level || "").toUpperCase();
  if (level === "ERROR" || BLOCK_WARN.has(l.name)) fails.push(l);
  else advisories.push(l);
}

if (advisories.length) {
  console.log(`\n[db-advisor] ${advisories.length} advisory finding(s) (not blocking — review per §1.6):`);
  for (const l of advisories) {
    console.log(`  · ${l.level} ${l.name}: ${l.detail ?? l.title ?? ""}`);
  }
}

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

console.log(
  `\n[db-advisor] OK — no blocking security advisor findings (${lints.length} lint(s) checked, ${advisories.length} advisory).`,
);
