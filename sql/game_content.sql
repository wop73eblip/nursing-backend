-- 遊戲內容表：只存一列（id=1），對話/道具文字整包放 jsonb，後台編輯用。
-- 在 Supabase → SQL Editor 貼上執行一次。

create table if not exists public.game_content (
  id         int primary key default 1,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.game_content enable row level security;

-- 讓後端（service_role）能讀寫這張表（你的專案預設不會自動授權新表）
grant select, insert, update, delete on table public.game_content to service_role;

-- 順便補上「遊戲存檔表」的權限（上次若已跑過，這行重跑也不會出錯）
grant select, insert, update, delete on table public.game_saves to service_role;
