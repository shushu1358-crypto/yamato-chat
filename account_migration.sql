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
