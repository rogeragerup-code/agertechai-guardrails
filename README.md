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
| `missing-grant` | a `create table`/`create view`/non-trigger `create function` in `public`, in a migration dated **≥ 2026-09-30**, with no `GRANT … TO service_role` on it in the same or a later migration (for a table: one that lets service_role WRITE) — plus a `serial`/`nextval()` table with no sequence grant. `create or replace` of an object an earlier migration created is skipped (the ACL survives). Older migrations are not checked; undated ones are skipped with a warning | Supabase's 2026-10-30 default change: new public objects are no longer granted to anon, authenticated **or service_role**, so the Data API — server code on the service key included — answers `42501`. Four repos already defaulted new tables to service_role only, so their migrations grant `authenticated` and have never needed to grant service_role; that default is exactly what disappears |
| `missing-csp` | `proxy.*`/`middleware.*` present but no **enforcing** `Content-Security-Policy` there **or** in `next.config` (Report-Only doesn't count) | No nonce-based CSP |
| `duplicate-edge-entry` | Both a `middleware.*` **and** a `proxy.*` entrypoint exist | Next resolves one and silently ignores the other — this shipped a prod 404 on every unprefixed route |
| `secret-in-log` | `console.*` logging an env secret or a known secret identifier | Secrets leaking into logs / aggregators |
| `sentry-scrub-disconnected` | `Sentry.init()` that passes no `beforeSend` | A credential scrubber can be correct, well-tested and **wired to nothing** — measured: deleting `beforeSend` left its own 12-gate suite at 12/12, plus tsc, eslint and guardrails all clean. Sentry events are logs, and an unwired scrubber redacts nothing |
| `test-suite-unregistered` | A `supabase/tests/*_test.sql` suite that is named neither in `run.mjs` nor in a `supabase/tests/MANIFEST` file | A runner that GLOBS cannot notice a suite that was **deleted** — it finds N−1 files, passes them all, and exits 0. `files.length === 0` catches total disappearance; nothing catches gradual. Measured 2026-08-30: four repos with suites, four carrying the hole |
| *(warning)* | `@sentry/nextjs` installed, app router present, but no `app/global-error.*` | Root render crashes reported nowhere |

Scope note for `sentry-scrub-disconnected`: it additionally reads `sentry.{server,edge,client}.config.*` at the repo ROOT, which the general code scan does not cover — miss those and the rule reads clean on the very files most likely to hold an init call. It matches by paren depth inside the `Sentry.init(...)` call, not per file ("beforeSend appears somewhere here" is a different claim from "this call passes it"), and strips comments first — a commented-out `beforeSend` line INSIDE the call is the realistic false-green, and the self-test fails if that stripping is removed. Repos without Sentry never trigger it.

Scope note for `test-suite-unregistered`: it checks ONE direction — every suite on disk is named somewhere. That is enough to catch "this repo has no manifest at all" and "a suite was added without registering it", and it fires for a greenfield repo the day it adds its FIRST suite, when nobody is thinking about this. It CANNOT see the other direction (listed-but-deleted): that needs the runner to compare against its own list at runtime, so passing this rule does not mean the local guard enforces both ways. Two manifest shapes are accepted — a filename list in `run.mjs`, or a separate `supabase/tests/MANIFEST` (one name per line, `#` comments) — because the first draft demanded the former and a pre-flight against all 13 repos flagged CRM and Aktsom, which both had a *correct* manifest in the latter shape. Comments are stripped from both, so a filename mentioned in prose does not count as registration; the self-test fails if that stripping is removed. Repos without `supabase/tests/run.mjs` never trigger it.

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

## Why these twelve

<!-- ⚠ Dette tallet var «eight» da regelen under ble lagt til 2026-08-30, og
     tabellen hadde da alt TI rader — overskriften hadde drevet i to runder uten
     at noen talte. Jeg inkrementerte den først til «nine», som gjorde den
     annerledes gal. Teller du reglene: tolv failende regler i tabellen over
     (talt 2026-09-29 da missing-grant kom til). Warnings, som ikke feller
     bygget, telles bevisst ikke her — det tallet sto feil sist. -->

They are the rules a linter passes straight through — authorization, policy, and data-exposure correctness, not style. Spend human review here; let CI hold the floor.

## Known limits / threat model

This is a **reflex layer** — line-based regexes that catch the naive form of each breach class. It is not a parser, a taint tracker, or a substitute for `/code-review`, `/security-review`, and the Supabase Advisors. Known blind spots, kept here honestly so nobody mistakes a green check for a clean bill:

- **Line-based matching.** Any construct split across lines (`.select(` + `'*'` on the next line, a `console.log(` with the secret argument on its own line, a CORS header name and value far apart) is invisible. The one mitigation: the `headers()` key/value CORS form is checked with a 2-line lookahead window.
- **`weak-redirect` detects one named anti-pattern** (`startsWith("//")` without the canonical regex `/^\/(?!\/)[^\\]*$/` in the file). A redirect with *no* validation at all passes clean — that's a review-cadence catch, not a regex catch.
- **`service-role-client` only sees the literal name in the same file.** The realistic leak — a `"use client"` file importing a server module that holds the key, pulled in transitively by the bundler — needs a build-level check. New-style `sb_secret_...` key env names that don't contain `SERVICE_ROLE_KEY` are also not matched.
- **`missing-grant` checks service_role, not every role.** It demands a grant to `service_role` because that is the default four repos silently relied on — and for a TABLE the grant must let service_role WRITE (`all`/`insert`/`update`/`delete`; select-only and column-level grants are flagged, because server writes 42501 otherwise). It cannot know whether `authenticated` or `anon` also need one — that is still a review question. `create or replace` of a function/view an EARLIER migration created is skipped (Postgres keeps the ACL) unless a `drop` sits between them, ordered by file AND offset, since HR drops and re-creates inside one file. Gaps: that match is by NAME, so a new overload (`f(text)` beside an existing `f(uuid)`) is wrongly treated as a replace; a `grant … on all tables in schema public` placed BEFORE the `create` in the same file still counts; DDL built dynamically via `execute` and SQL outside `supabase/migrations/` (e.g. a `docs/*.sql` pasted into the prod SQL editor) are not seen; and `alter default privileges … to service_role` only counts when dated **≥ 2026-10-30**, because Supabase's own revoke on that day undoes every earlier one — including the copy every pg_dump baseline carries. The first draft counted those, which made the rule inert in every repo with a baseline: the fleet preflight read "0 findings, identical" and measured nothing, and only a probe migration that should have been flagged exposed it. Positive control since then: a probe migration in each of the 7 repos with migrations is flagged. Also pre-existing and unrelated: `missing-rls` strips `--` comments but not `/* … */` blocks, so a block-commented `create table` still counts there.
- **`test-suite-unregistered` proves registration, not enforcement.** It sees that a name is listed; it cannot see whether the runner actually compares the list against the directory, or in which direction. A repo could list every suite in a dead constant and pass. The runtime half is the local runner's job — and neither half survives the whole workflow file being deleted, which no guard can prevent (a guard cannot guarantee its own invocation).
- **`secret-in-log` needs the call and the secret on one line**, and `console.log(JSON.stringify(process.env))` — the worst case — carries no secret identifier to match.
- **Supply chain: the `v1` tag is mutable by design** (see *Bumping a rule*), and it is the one unpinned link in an otherwise SHA-pinned chain. Callers fetch the checker at `@v1`, and the reusable workflow hands `SUPABASE_ACCESS_TOKEN` to the fetched `db-advisor.mjs`. Anyone who can force-push this repo's tags executes code in every consumer's CI with that secret in the environment. Single-owner repo, branch-protected — accepted; if the ownership model ever widens, switch callers to SHA pins.

### Decision record: no rule for swallowed failure signals (2026-08-21)

Considered and **declined**, recorded so it isn't re-litigated. A failure signal that goes nowhere was measured across the fleet in three mechanical shapes:

1. Destructure the result, omit `error` — `const { data } = await …listFactors()`. The return *is* used, so no floating-value rule can fire.
2. Bare `await fn(...)` as a statement, discarding a returned failure state — `compensateRacedDelivery()` returns `"none" | "compensated" | "failed"`; two call sites threw it away.
3. plpgsql `raise warning …; return;` — a normal return, so the caller's `exception when others` never fires and no failure row is written.

A rule was proposed for shape 2 (an awaited call used as a statement whose declared return type isn't `void`). It was declined for three reasons:

- **It needs type-aware ESLint, not this checker.** This repo is line-based text matching; the rule requires type information. It belongs in each repo's `eslint.config`, and none of them currently enables `projectService`.
- **It covers 2 of the 4 measured instances** — and misses the one that actually reached production (shape 1, in HR's `MfaSection`: a transient error rendered as "two-factor not set up" while disabling the only self-service recovery path).
- **Shapes 1 and 3 are semantic.** No text pattern distinguishes "correctly ignored a value" from "dropped the error".

Half-coverage on a class like this is worse than none — a green check would read as "we don't swallow failure signals" when it only means "not in the one shape we can see". Kept as a review question instead — *where else do we swallow a failure signal?* — carried in global CLAUDE.md floor rule 20 and in each product's `docs/SECURITY-TODO.md`. Revisit if a repo adopts type-aware linting for other reasons, at which point shape 2 becomes nearly free.
