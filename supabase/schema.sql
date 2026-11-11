-- Astro World Cyber Shop — Core Database Schema (`schema.sql`)

create table if not exists public.catalog (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  subtitle text,
  category text not null default 'movies',
  sub text,
  genres text[] default array['Action'],
  description text default '',
  image_path text,
  trending integer default 0,
  active boolean default true,
  created_at timestamp with time zone default now()
);

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text not null,
  service text not null,
  date text not null,
  time text not null,
  notes text default '',
  status text default 'new', -- new | confirmed | completed | done | cancelled
  created_at timestamp with time zone default now()
);

create table if not exists public.requests (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  title text not null,
  kind text not null default 'Movie',
  status text default 'new', -- new | ready | completed | done
  created_at timestamp with time zone default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  rating integer not null default 5,
  body text not null,
  status text default 'pending', -- pending | approved | rejected
  created_at timestamp with time zone default now()
);

create table if not exists public.rate_limits (
  id uuid primary key default gen_random_uuid(),
  ip_hash text not null,
  created_at timestamp with time zone default now()
);

create table if not exists public.drafts (
  chat_id bigint primary key,
  title text,
  subtitle text,
  category text,
  sub text,
  genres text[],
  description text,
  image_path text,
  step text,
  updated_at timestamp with time zone default now()
);

alter table public.catalog enable row level security;
alter table public.bookings enable row level security;
alter table public.requests enable row level security;
alter table public.reviews enable row level security;
alter table public.rate_limits enable row level security;
alter table public.drafts enable row level security;

create index if not exists idx_rate_limits_ip_created on public.rate_limits(ip_hash, created_at);
create index if not exists idx_catalog_active_created on public.catalog(active, created_at desc);
create index if not exists idx_reviews_status_created on public.reviews(status, created_at desc);
