-- FLAGGED: no grant at all.
create table public.ny_uten (id uuid primary key);

-- OK: granted to service_role in the same file.
create table if not exists public.ny_med (id uuid primary key);
grant select, insert on public.ny_med to authenticated, service_role;

-- FLAGGED: granted to authenticated ONLY — the trap in repos whose defaults
-- already gave service_role for free. That default is what disappears.
create table public.bare_authenticated (id uuid primary key);
grant select on public.bare_authenticated to authenticated;

-- OK: granted in a LATER migration.
create table public.senere (id uuid primary key);

-- FLAGGED: the only grant sits in an EARLIER migration.
create table public.tidligere_grant (id uuid primary key);

-- Not checked: other schema, temp table.
create table private.intern (id uuid primary key);
create temp table tmp_x (id int);

-- Not flagged: deliberate, suppressed.
-- guardrails-allow: missing-grant
create table public.bevisst_uten (id uuid primary key);

-- FLAGGED (sequence): the table is granted, its serial sequence is not.
create table public.teller (id bigserial primary key);
grant select, insert on table public.teller to service_role;

-- FLAGGED: view without a grant.
create or replace view public.v_uten as select 1 as x;

-- OK: function granted (argument list stripped before matching).
create or replace function public.rpc_med(p uuid, q text) returns void language sql as $$ select 1; $$;
grant execute on function public.rpc_med(uuid, text) to service_role;

-- FLAGGED: function without a grant. The body must not be scanned.
create function public.rpc_uten() returns void language plpgsql as $$
begin
  -- create table public.i_kroppen (x int);
  execute 'create table public.dynamisk (x int)';
  perform 1;
end;
$$;

-- Not flagged: trigger function (never called over the API).
create or replace function public.trig() returns trigger language plpgsql as $$ begin return new; end; $$;

-- Not flagged: commented-out DDL.
-- create table public.kommentert (id int);
/* create table public.blokkommentert (id int); */

-- OK: pg_dump's quoted style.
CREATE TABLE "public"."sitert" ("id" uuid);
GRANT ALL ON TABLE "public"."sitert" TO "service_role";

-- FLAGGED: quoted style WITHOUT a grant. Without this case, a checker that
-- failed to unquote "public" would skip quoted DDL silently and still pass.
CREATE TABLE "public"."sitert_uten" ("id" uuid);

-- FLAGGED (read-only): service_role may only READ — every server write 42501s.
create table public.bare_select (id uuid primary key);
grant select on public.bare_select to authenticated, service_role;

-- FLAGGED (read-only): a column-level grant is not a table grant.
create table public.kolonne (id uuid primary key, x int);
grant select (id), update (x) on public.kolonne to service_role;

-- Not flagged: `or replace` of an EXISTING function/view keeps its ACL.
create or replace function public.gammel_fn() returns void language sql as $$ select 2 $$;
create or replace view public.gammel_v as select 2 as x;

-- FLAGGED: dropped first, so the ACL is gone and the new one has none.
drop function if exists public.gammel_fn2();
create or replace function public.gammel_fn2() returns void language sql as $$ select 2 $$;

-- Not flagged: replaces an object whose LAST event before this was a create
-- (the drop sat before it, in the same earlier file).
create or replace function public.samme_fil() returns void language sql as $$ select 2 $$;

-- FLAGGED: HR's signature-change pattern (000089) — new signature first, old one
-- dropped AFTER, in the same file. The new signature is a NEW object, no ACL.
create or replace function public.sig_fn(a int, b text) returns void language sql as $$ select 2 $$;
drop function if exists public.sig_fn(int);
