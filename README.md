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
| `select-star` | `.select('*')` and the embedded-resource form `.select('*, relation(*)')` | Bloated API contracts / column leakage |
| `dangerous-html` | `dangerouslySetInnerHTML` (not allowlisted) | Stored XSS — AI output rendered as raw HTML |
| `cors-wildcard` | `Access-Control-Allow-Origin: *` (any case/quote style, incl. the `headers()` key/value form; `vercel.json` gets a warning) | Open CORS on authenticated routes |
| `service-role-client` | `SUPABASE_SERVICE_ROLE_KEY` in a `"use client"` file | Service-role key in client bundle |
| `weak-redirect` | the specific `startsWith("//")` anti-pattern in a file without the canonical regex — it does **not** detect redirects with no validation at all | Open redirect (`/\evil.com` bypass) |
| `missing-rls` | a `create table` with no matching `enable row level security` (incl. pg_dump's `ALTER TABLE ONLY` form; commented-out DDL ignored) | Lovable CVE-2025-48757 RLS-bypass class |
| `missing-csp` | `proxy.*`/`middleware.*` present but no **enforcing** `Content-Security-Policy` there **or** in `next.config` (Report-Only doesn't count) | No nonce-based CSP |
| `duplicate-edge-entry` | Both a `middleware.*` **and** a `proxy.*` entrypoint exist | Next resolves one and silently ignores the other — this shipped a prod 404 on every unprefixed route |
| `secret-in-log` | `console.*` logging an env secret or a known secret identifier | Secrets leaking into logs / aggregators |
| *(warning)* | `@sentry/nextjs` installed, app router present, but no `app/global-error.*` | Root render crashes reported nowhere |

Scope: code rules scan `src/`, `app/`, `pages/`, `lib/`, `components/`, `server/`, `supabase/functions/` (edge functions are a prime service-role-key location), and `next.config.*` at the root; the RLS rule aggregates across all of `supabase/migrations/` (a table may be created in one migration and RLS-enabled in another); the CSP rule reads the edge entrypoint under either spelling — `proxy.ts`/`src/proxy.ts` (the Next 16 convention) **and** `middleware.ts`/`src/middleware.ts`. Checking only the old name is how a migrated repo drops silently out of this rule: the file is never found, `missing-csp` cannot fire, and CI reads green because it has stopped looking. A repo with **no** entrypoint at all gets a warning, not a failure — greenfield repos may not have one yet. A repo whose entrypoint sets no CSP but whose `next.config` does gets a **warning**, not a failure: per engineering reference §1.4, a static, no-auth marketing surface may deliberately keep a static CSP there, because a nonce forces per-request dynamic rendering and kills ISR/PPR. The checker cannot tell a marketing site from an authenticated product, so it names the situation instead of guessing. A wildcard-CORS header in `vercel.json` is a warning, not a failure — `*` on public static assets (fonts, images) is legitimate and JSON has no room for a suppression marker. A repo with `@sentry/nextjs` but no `app/global-error.*` also gets a warning: a React **render** error escaping the root layout never fires `window.onerror` (the error boundary catches it first), so without that file those crashes are reported nowhere — but several repos already ship in that state, so gating on it would red their CI the moment `v1` moves.

## Database side — Supabase Advisors (opt-in)

The eight rules above check **code**. They can't see the live database, where the
2026-06 cross-product sweep found the real issues (leftover `anon` execute on
`SECURITY DEFINER` functions, unpinned `search_path`, anon `INSERT WITH CHECK(true)`
lead tables). To run the Supabase **Advisors** automatically in CI, give the
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
unaffected. Two lanes run:

- **Security** (can fail the build): **fails** CI on `ERROR`-level advisor lints plus
  the two high-signal WARN classes (`anon_security_definer_function_executable`,
  `rls_policy_always_true`), and **reports** the nuanced ones (search_path, intended
  definer fns, `extension_in_public`).
- **Performance** (advisory only — never blocks): surfaces the index/RLS hygiene the
  static code checker structurally can't see — unindexed foreign keys, RLS-initplan
  perf (`auth.<fn>()` re-evaluated per row), unused/duplicate indexes. A missing index
  is a perf smell, not a vulnerability, so it is reported, not gated.

Neither lane blocks a build on an Advisor API hiccup. An **invalid/revoked token**
(HTTP 401/403) is treated differently from a hiccup: it still doesn't block (a token
expiry must not freeze every deploy), but it emits a `::warning` annotation in the
Checks UI — a dead token silently disables the gate forever, so it must be visible.
Rotate the secret promptly when you see it. Suppress a verified-safe finding
(either lane) by adding its `cache_key` to `.guardrails-db-allow`.

Full DB-side floor + the human-review items the Advisor can't check (rate-limit
coverage, JWT-theft posture, DoS resilience): engineering reference §1.6 +
`agertechai-next-starter/supabase/SECURITY-CHECKLIST.md`.

## Suppressing a justified line

When input is provably safe, add an inline marker on the offending line, or a standalone comment (`//`, `/* */`, JSX `{/* */}`, SQL `--`) on the line directly above it:

```ts
// guardrails-allow: dangerous-html
<div dangerouslySetInnerHTML={{ __html: sanitizedTrustedHtml }} />
```

```sql
-- guardrails-allow: missing-rls
create table public.reviewed_exception (...);
```

A marker covers exactly **one** line: an inline marker covers its own line only (it does not spill onto the next), and an above-line marker only counts when that line is a pure comment. `missing-csp` is file-level — put `// guardrails-allow: missing-csp` anywhere in the proxy/middleware file (e.g. when the CSP deliberately lives in `next.config` headers on a static site).

Use sparingly. Every suppression is a place a human took responsibility for the exception.

## Bumping a rule

Tags are how repos pin a version. When a rule tightens:

1. Land the change on `main`, keep `node test/run.mjs` green.
2. Move the tag: `git tag -f v1 && git push -f origin v1` for a backward-compatible tightening, **or** cut `v2` for a breaking change and bump callers deliberately.

The self-test (`test/run.mjs`) runs a deliberately-insecure fixture and asserts every rule fires exactly once and that a correctly-secured table is **not** flagged. It runs in CI on every push.

## Why these eight

They are the rules a linter passes straight through — authorization, policy, and data-exposure correctness, not style. Spend human review here; let CI hold the floor.

## Known limits / threat model

This is a **reflex layer** — line-based regexes that catch the naive form of each breach class. It is not a parser, a taint tracker, or a substitute for `/code-review`, `/security-review`, and the Supabase Advisors. Known blind spots, kept here honestly so nobody mistakes a green check for a clean bill:

- **Line-based matching.** Any construct split across lines (`.select(` + `'*'` on the next line, a `console.log(` with the secret argument on its own line, a CORS header name and value far apart) is invisible. The one mitigation: the `headers()` key/value CORS form is checked with a 2-line lookahead window.
- **`weak-redirect` detects one named anti-pattern** (`startsWith("//")` without the canonical regex `/^\/(?!\/)[^\\]*$/` in the file). A redirect with *no* validation at all passes clean — that's a review-cadence catch, not a regex catch.
- **`service-role-client` only sees the literal name in the same file.** The realistic leak — a `"use client"` file importing a server module that holds the key, pulled in transitively by the bundler — needs a build-level check. New-style `sb_secret_...` key env names that don't contain `SERVICE_ROLE_KEY` are also not matched.
- **`secret-in-log` needs the call and the secret on one line**, and `console.log(JSON.stringify(process.env))` — the worst case — carries no secret identifier to match.
- **Supply chain: the `v1` tag is mutable by design** (see *Bumping a rule*), and it is the one unpinned link in an otherwise SHA-pinned chain. Callers fetch the checker at `@v1`, and the reusable workflow hands `SUPABASE_ACCESS_TOKEN` to the fetched `db-advisor.mjs`. Anyone who can force-push this repo's tags executes code in every consumer's CI with that secret in the environment. Single-owner repo, branch-protected — accepted; if the ownership model ever widens, switch callers to SHA pins.
