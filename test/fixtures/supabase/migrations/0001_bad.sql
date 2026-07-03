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

-- pg_dump emits the ONLY form — it must satisfy the RLS requirement too.
create table if not exists public.pgdump_table (
  id uuid primary key default gen_random_uuid()
);
ALTER TABLE ONLY public.pgdump_table ENABLE ROW LEVEL SECURITY;

-- Suppressed via the SQL marker — a human took responsibility; must NOT be flagged.
-- guardrails-allow: missing-rls
create table if not exists public.allowed_table (
  id uuid primary key default gen_random_uuid()
);

-- Commented-out DDL must not be counted as a real table:
-- create table public.ghost_table (id int);
