-- Before GRANT_CUTOFF: every object here got the platform's default grants.
create table public.gammel_uten (id uuid primary key);

-- A grant on a name BEFORE that name is (re)created must not count for the
-- later object: it belonged to a previous incarnation.
grant select on public.tidligere_grant to service_role;

-- pg_dump baselines carry the OLD platform defaults verbatim. Supabase revokes
-- them on 2026-10-30, so this must NOT cover anything created later.
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";
