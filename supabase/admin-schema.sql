-- Astro World Admin Schema (`admin-schema.sql`)
-- Never seed accounts with a shared password or commit password hashes to git.
-- To create or reset the Owner account safely from your terminal, run:
--   node scripts/set-admin-password.mjs owner

create table if not exists public.admins (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  display_name text not null,
  role text default 'Staff',
  blocked boolean not null default false,
  must_change_password boolean not null default false,
  last_seen timestamp with time zone,
  session_invalidated_at timestamp with time zone,
  created_at timestamp with time zone default now()
);

alter table public.admins enable row level security;
