-- Before GRANT_CUTOFF: every object here got the platform's default grants.
create table public.gammel_uten (id uuid primary key);

-- A grant on a name BEFORE that name is (re)created must not count for the
-- later object: it belonged to a previous incarnation.
grant select on public.tidligere_grant to service_role;

-- pg_dump baselines carry the OLD platform defaults verbatim. Supabase revokes
-- them on 2026-10-30, so this must NOT cover anything created later.
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";

-- Existing objects that a later migration redefines.
create or replace function public.gammel_fn() returns void language sql as $$ select 1 $$;
create or replace function public.gammel_fn2() returns void language sql as $$ select 1 $$;
create or replace view public.gammel_v as select 1 as x;

-- Dropped and re-created in the SAME file (HR 000062 does this): the object
-- that exists afterwards is the re-created one.
drop function if exists public.samme_fil();
create function public.samme_fil() returns void language sql as $$ select 1 $$;
