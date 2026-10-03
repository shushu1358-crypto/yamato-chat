-- Yamato Chat V2.2 アカウント機能
-- Supabase SQL Editorで1回だけ実行してください。

create extension if not exists pgcrypto;

create table if not exists public.accounts (
    id uuid primary key default gen_random_uuid(),
    username text not null unique,
    display_name text not null,
    password_hash text not null,
    gate_password_hash text not null,
    bio text not null default '',
    avatar_url text,
    created_at timestamptz not null default now(),
    last_login_at timestamptz
);

create table if not exists public.sessions (
    id uuid primary key default gen_random_uuid(),
    account_id uuid not null references public.accounts(id) on delete cascade,
    token_hash text not null unique,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists idx_sessions_token_hash
on public.sessions(token_hash);

create index if not exists idx_sessions_account_id
on public.sessions(account_id);

create index if not exists idx_sessions_expires_at
on public.sessions(expires_at);

alter table public.accounts enable row level security;
alter table public.sessions enable row level security;

grant select, insert, update, delete on table public.accounts, public.sessions to service_role;

-- 既存のchat_usersとの互換性用:
-- V2.2以降はaccountsを正式なログインIDとして使用します。


-- Yamato Chat global settings.
-- The gate password is one shared password for all users and compatible works.
create table if not exists public.yamato_settings (
    key text primary key,
    value_hash text not null,
    updated_at timestamptz not null default now()
);

alter table public.yamato_settings enable row level security;

grant select, insert, update, delete
on table public.yamato_settings
to service_role;


-- The gate password is global, not per-account.
-- Keep the old column only for compatibility with an earlier V2.2 schema.
alter table public.accounts
  alter column gate_password_hash drop not null;


-- V2.3: profile avatars + chat attachments
alter table public.chat_users
  add column if not exists avatar_url text;

alter table public.messages
  add column if not exists attachment_url text,
  add column if not exists attachment_name text,
  add column if not exists attachment_type text,
  add column if not exists attachment_size bigint;

grant select, insert, update, delete
on table public.chat_users, public.messages
to service_role;


-- V2.3.2: chat messages use the account display name, not the login username.
alter table public.chat_users
  add column if not exists display_name text;

update public.chat_users cu
set display_name = a.display_name
from public.accounts a
where a.username = cu.username
  and (cu.display_name is null or cu.display_name = '');

alter table public.chat_users
  alter column display_name set default '';

grant select, insert, update, delete
on table public.chat_users
to service_role;
