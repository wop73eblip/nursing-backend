-- 遊戲存檔資料表：一個帳號一筆，進度整包存 jsonb。
-- 在 Supabase 後台 → SQL Editor 貼上執行一次即可。

create table if not exists public.game_saves (
  uid        text primary key,               -- 對應 users.uid（登入帳號）
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- 只透過後端（service key）存取，因此開啟 RLS 但不加任何公開政策，
-- 等於：拿 anon key 的瀏覽器完全碰不到這張表，只有你的後端能讀寫。
alter table public.game_saves enable row level security;

-- （選用）刪除使用者時一併刪掉他的存檔。若 users.uid 不是主鍵/唯一鍵，
-- 這行會失敗，可略過不影響功能：
-- alter table public.game_saves
--   add constraint game_saves_uid_fkey
--   foreign key (uid) references public.users(uid) on delete cascade;
