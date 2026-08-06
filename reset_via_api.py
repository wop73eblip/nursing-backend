"""用本機後端 API 重設 admin 密碼"""
import urllib.request, json

# 先用現有帳號登入取得 token（請改成你目前能登入的帳號）
login_uid = input("你目前能登入的帳號 uid（如 yr）: ").strip()
login_pwd = input("該帳號的密碼: ").strip()

req = urllib.request.Request(
    "http://localhost:8000/auth/login",
    data=json.dumps({"uid": login_uid, "password": login_pwd}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as r:
    token = json.loads(r.read())["access_token"]
print("✓ 登入成功")

# 重設 admin 密碼
target_uid = input("要重設密碼的 uid（如 admin）: ").strip()
new_pwd = input("新密碼: ").strip()

req2 = urllib.request.Request(
    f"http://localhost:8000/users/{target_uid}/reset-password",
    data=json.dumps({"new_password": new_pwd}).encode(),
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    method="POST"
)
with urllib.request.urlopen(req2) as r:
    print("✓", json.loads(r.read())["message"])
