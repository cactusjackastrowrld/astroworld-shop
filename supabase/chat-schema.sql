-- Admin table updates (run after existing schema)
alter table public.admins add column if not exists blocked boolean default false;
alter table public.admins add column if not exists last_seen timestamp with time zone;
alter table public.admins add column if not exists session_invalidated_at timestamp with time zone;

-- Live Chat tables
create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  session_id text unique not null,
  customer_name text not null default 'Customer',
  status text default 'open', -- open | closed
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid references public.conversations(id) on delete cascade,
  sender text not null, -- 'customer' | 'admin'
  sender_name text not null,
  text text not null,
  created_at timestamp with time zone default now()
);

alter table public.conversations enable row level security;
alter table public.messages enable row level security;

create index if not exists idx_messages_conv_created on public.messages(conversation_id, created_at);
create index if not exists idx_conversations_updated on public.conversations(updated_at desc);
