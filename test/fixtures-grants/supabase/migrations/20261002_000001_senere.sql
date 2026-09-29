grant all on public.senere to service_role;

-- Dropped in an INTERMEDIATE migration: the later `or replace` makes a new object.
drop function if exists public.mellom_fn();
