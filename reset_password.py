"""臨時腳本：直接更新指定帳號的密碼（自動讀取同目錄 .env）"""
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

import bcrypt
from supabase import create_client

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SERVICE_KEY")
print(f"連線到: {url}")

supabase = create_client(url, key)

res = supabase.table("users").select("uid, name, role").execute()
print("\n現有帳號：")
for u in res.data:
    print(f"  uid={u['uid']}  name={u['name']}  role={u['role']}")

uid = input("\n輸入要重設密碼的 uid: ").strip()
new_pwd = input("輸入新密碼: ").strip()

hashed = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
supabase.table("users").update({"password_hash": hashed}).eq("uid", uid).execute()
print(f"\n✅ 已更新 {uid} 的密碼")
