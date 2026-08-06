-- 遊戲留言板：每則留言一列，綁玩家帳號。
-- 在 Supabase → SQL Editor 貼上執行一次。

create table if not exists public.game_messages (
  id         bigint generated always as identity primary key,
  uid        text not null,                 -- 留言者帳號（對應 users.uid）
  name       text,                          -- 留言者名字（留存當下的顯示名）
  text       text not null,                 -- 留言內容
  created_at timestamptz not null default now()
);
create index if not exists game_messages_uid_idx on public.game_messages (uid);
alter table public.game_messages enable row level security;

-- 讓後端（service_role）能讀寫這張表（本專案新表不會自動授權）
grant select, insert, update, delete on table public.game_messages to service_role;
grant usage, select on all sequences in schema public to service_role;
