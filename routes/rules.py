"""規則設定(GET/POST /rules)+ 公開登入/首頁設定(/login-config、/home-config)。"""
from datetime import datetime
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from auth import get_current_user, require_roles
from db import supabase

router = APIRouter()


class RulesUpdate(BaseModel):
    rules: dict


@router.get("/rules")
def get_rules(current_user: dict = Depends(get_current_user)):
    res = supabase.table("rules").select("*").limit(1).execute()
    if res.data:
        return {"rules": res.data[0].get("data") or {}}
    return {"rules": {}}


@router.get("/login-config")
def get_login_config():
    """公開端點(登入頁未帶 token):回傳登入畫面自訂內容,未設定則回空值由前端用預設。"""
    res = supabase.table("rules").select("data").limit(1).execute()
    login = {}
    if res.data:
        login = (res.data[0].get("data") or {}).get("login") or {}
    return {
        "title": login.get("title") or "",
        "subtitle": login.get("subtitle") or "",
        "image": login.get("image") or "",
    }


# 登入後首頁的模組卡片預設值(大標/小標/圖片可於後台自訂;enabled 由程式控制)
DEFAULT_MODULES = [
    {"key": "schedule", "title": "排班系統", "tagline": "不來預班就沒得預班囉～", "enabled": True},
    {"key": "data",     "title": "學習系統", "tagline": "護理訓練小遊戲",           "enabled": True},
]


@router.get("/home-config")
def get_home_config(current_user: dict = Depends(get_current_user)):
    """登入後首頁的模組卡片設定:合併後台自訂與預設值。"""
    res = supabase.table("rules").select("data").limit(1).execute()
    saved: dict = {}
    if res.data:
        for m in ((res.data[0].get("data") or {}).get("modules") or []):
            if m.get("key"):
                saved[m["key"]] = m
    modules = []
    for d in DEFAULT_MODULES:
        s = saved.get(d["key"], {})
        modules.append({
            "key": d["key"],
            "title": s.get("title") or d["title"],
            "tagline": s.get("tagline") or d["tagline"],
            "image": s.get("image") or "",
            "enabled": d["enabled"],
        })
    return {"modules": modules}


@router.post("/rules")
def save_rules(
    body: RulesUpdate,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    existing = supabase.table("rules").select("id", "data").limit(1).execute()
    if existing.data:
        current_data = existing.data[0].get("data") or {}
        incoming = dict(body.rules)
        # modules 特殊處理:依 key 合併(更新有送的、保留沒送的),
        # 讓「排班後台」「學習系統後台」各自只送自己那張卡也不會蓋掉對方。
        if "modules" in incoming:
            cur = {m["key"]: m for m in (current_data.get("modules") or []) if m.get("key")}
            for m in incoming["modules"]:
                if m.get("key"):
                    cur[m["key"]] = m
            incoming["modules"] = list(cur.values())
        merged = {**current_data, **incoming}
        supabase.table("rules").update({
            "data": merged,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("id", existing.data[0]["id"]).execute()
    else:
        supabase.table("rules").insert({
            "key": "config",
            "value": "{}",
            "data": body.rules,
        }).execute()
    return {"message": "規則已儲存"}
