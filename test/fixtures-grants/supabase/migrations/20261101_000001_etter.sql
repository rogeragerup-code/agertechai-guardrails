-- A default re-grant written AFTER the enforcement day survives it, and
-- covers objects created after it.
alter default privileges for role postgres in schema public grant all on tables to service_role;
create table public.etter_default (id uuid primary key);
