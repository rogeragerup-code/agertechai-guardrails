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
