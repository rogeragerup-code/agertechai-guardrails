-- missing-rls: this table is created but RLS is never enabled anywhere.
create table if not exists public.leaky_table (
  id uuid primary key default gen_random_uuid(),
  secret text
);

-- This one is fine — created AND RLS-enabled, so it must NOT be flagged.
create table if not exists public.safe_table (
  id uuid primary key default gen_random_uuid()
);
alter table public.safe_table enable row level security;
