# agertechai-guardrails

Mechanical enforcement of the **AgerTechAI security floor** for Next.js + Supabase + Vercel builds. One referenced workflow file makes every repo — existing or greenfield — fail CI on the breach classes that actually hit AI-built SaaS in 2025–2026.

This is **Layer 2** (enforcement). Layer 1 is the instruction layer in the global `CLAUDE.md` §8 and the canonical, sourced reference at `agertechai_no/docs/engineering/compliance-stack-engineering-reference.md`. When the reference and a rule here disagree, the reference wins — update the rule.

## Adoption — one file per repo

Add `.github/workflows/guardrails.yml` to any repo:

```yaml
name: guardrails
on: [push, pull_request]
jobs:
  guardrails:
    uses: rogeragerup-code/agertechai-guardrails/.github/workflows/check.yml@v1
```

That's it. The reusable workflow checks out your repo, fetches the pinned guardrails script, and runs it. (`examples/caller-workflow.yml` is the same file ready to copy.)

## Run it locally

```bash
node guardrails.mjs            # scan the current repo
node guardrails.mjs ../some-other-repo
```

Exits `0` on pass, `1` on any finding.

## What it checks

Each rule maps 1:1 to a real breach class (see the engineering reference for sources).

| Rule id | Catches | Maps to |
|---|---|---|
| `select-star` | `.select('*')` | Bloated API contracts / column leakage |
| `dangerous-html` | `dangerouslySetInnerHTML` (not allowlisted) | Stored XSS — AI output rendered as raw HTML |
| `cors-wildcard` | `Access-Control-Allow-Origin: *` | Open CORS on authenticated routes |
| `service-role-client` | `SUPABASE_SERVICE_ROLE_KEY` in a `"use client"` file | Service-role key in client bundle |
| `weak-redirect` | `startsWith("//")` guard without the canonical regex | Open redirect (`/\evil.com` bypass) |
| `missing-rls` | a `create table` with no matching `enable row level security` | Lovable CVE-2025-48757 RLS-bypass class |
| `missing-csp` | `middleware.ts` present but no `Content-Security-Policy` | No nonce-based CSP |
| `secret-in-log` | `console.*` logging an env secret or a known secret identifier | Secrets leaking into logs / aggregators |

Scope: code rules scan `src/` and `app/`; the RLS rule aggregates across all of `supabase/migrations/` (a table may be created in one migration and RLS-enabled in another); the CSP rule reads `middleware.ts`/`src/middleware.ts`. A repo with **no** middleware gets a warning, not a failure — greenfield repos may not have one yet.

## Database side — Supabase Security Advisor (opt-in)

The eight rules above check **code**. They can't see the live database, where the
2026-06 cross-product sweep found the real issues (leftover `anon` execute on
`SECURITY DEFINER` functions, unpinned `search_path`, anon `INSERT WITH CHECK(true)`
lead tables). To run the Supabase **Security Advisor** automatically in CI, give the
caller a project ref + token:

```yaml
name: guardrails
on: [push, pull_request]
jobs:
  guardrails:
    uses: rogeragerup-code/agertechai-guardrails/.github/workflows/check.yml@v1
    with:
      supabase_project_ref: your-project-ref      # not a secret
    secrets:
      SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}   # repo secret
```

Add `SUPABASE_ACCESS_TOKEN` (a Supabase personal/management token) as a repo secret.
**Safe by default:** with neither set, the DB step skips — existing callers are
unaffected. It **fails** CI on `ERROR`-level advisor lints plus the two high-signal
WARN classes (`anon_security_definer_function_executable`, `rls_policy_always_true`),
**reports** the nuanced ones (search_path, intended definer fns, `extension_in_public`),
and never blocks a build on an Advisor API hiccup. Suppress a verified-safe finding
by adding its `cache_key` to `.guardrails-db-allow`.

Full DB-side floor + the human-review items the Advisor can't check (rate-limit
coverage, JWT-theft posture, DoS resilience): engineering reference §1.6 +
`agertechai-next-starter/supabase/SECURITY-CHECKLIST.md`.

## Suppressing a justified line

When input is provably safe, add an inline marker on the offending line or the line directly above it:

```ts
// guardrails-allow: dangerous-html
<div dangerouslySetInnerHTML={{ __html: sanitizedTrustedHtml }} />
```

Use sparingly. Every suppression is a place a human took responsibility for the exception.

## Bumping a rule

Tags are how repos pin a version. When a rule tightens:

1. Land the change on `main`, keep `node test/run.mjs` green.
2. Move the tag: `git tag -f v1 && git push -f origin v1` for a backward-compatible tightening, **or** cut `v2` for a breaking change and bump callers deliberately.

The self-test (`test/run.mjs`) runs a deliberately-insecure fixture and asserts every rule fires exactly once and that a correctly-secured table is **not** flagged. It runs in CI on every push.

## Why these eight

They are the rules a linter passes straight through — authorization, policy, and data-exposure correctness, not style. Spend human review here; let CI hold the floor.
