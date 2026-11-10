-- Astro World Admin Schema & Seed
create table if not exists public.admins (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  display_name text not null,
  role text default 'Admin',
  created_at timestamp with time zone default now()
);

alter table public.admins enable row level security;

-- Default 4 admin accounts (password: astro2026!)
insert into public.admins (username, password_hash, display_name, role)
values
  ('owner', 'db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393', 'Shop Owner', 'Owner'),
  ('manager', 'db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393', 'Store Manager', 'Manager'),
  ('staff1', 'db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393', 'Front Desk', 'Front Desk'),
  ('staff2', 'db812db08007152375fbf084d0664856b2633f7d0594fa2599a31edae8dbf393', 'Cyber Operator', 'Operator')
on conflict (username) do nothing;
