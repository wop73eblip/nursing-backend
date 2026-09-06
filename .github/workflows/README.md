# GitHub Actions

## keepalive.yml — 每天 08:00 台灣時間 ping Supabase

### 目的
Supabase 免費 tier 若 project 超過 7 天無 DB 活動會自動 pause。此 workflow 每天打一次確保有活動記錄。

### 首次設定(**你必須做這一步**)

1. 進 GitHub repo:https://github.com/wop73eblip/nursing-backend
2. 上方 tab 選 **Settings** → 左側選單 **Secrets and variables** → **Actions**
3. 點 **New repository secret** 建 2 個 secret:

   | Name | Value |
   |---|---|
   | `SUPABASE_URL` | `https://swziremayhtrffxltcjz.supabase.co` |
   | `SUPABASE_ANON_KEY` | (backend/.env 裡的 SUPABASE_ANON_KEY 值,複製整段 JWT) |

4. 建完後,回到 repo,上方 tab **Actions** → 左側找 **Supabase Keepalive** → 右上 **Enable workflow**(第一次要手動啟用)
5. 立刻點 **Run workflow** 手動觸發一次驗證 → 綠色 ✓ 就成功

### 之後自動運作
- 每天台灣時間 08:00 自動觸發
- 若失敗會發 email 到你的 GitHub 註冊信箱
- 你可以在 Actions 頁面看歷史執行結果

### 費用
- GitHub Actions 免費額度:public repo 完全免費;private repo 每月 2000 分鐘免費
- 這個 workflow 每天跑 < 10 秒 → 月用量 < 5 分鐘 → **永遠免費**

### 手動觸發
Actions 頁面 → Supabase Keepalive → Run workflow(右上)
