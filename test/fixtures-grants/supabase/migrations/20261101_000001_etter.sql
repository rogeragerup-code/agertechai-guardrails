-- A default re-grant written AFTER the enforcement day survives it, and
-- covers objects created after it.
alter default privileges for role postgres in schema public grant all on tables to service_role;
create table public.etter_default (id uuid primary key);

-- FLAGGED: its previous incarnation was dropped in 20261002 (a different file).
create or replace function public.mellom_fn() returns void language sql as $$ select 2 $$;
