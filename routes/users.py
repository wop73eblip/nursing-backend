"""護理師帳號管理:GET/POST/PATCH/DELETE /users + 密碼變更/重設 + 排序。"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import (
    get_current_user, require_roles,
    verify_password, get_password_hash,
    ChangePassword, AdminResetPassword,
)
from db import supabase

router = APIRouter()


class UserCreate(BaseModel):
    uid: str
    password: str
    name: str
    role: str        # nurse, dual, admin, superadmin
    level: str       # leader, second, member
    attr: str        # 輪班屬性
    halftime: bool = False
    admin_staff: bool = False   # 行政人員:可預班但不參與一鍵生成
    is_trainee: bool = False     # 新人:照排班規則排、但不計臨床人數、跟隨導師
    mentor_uid: Optional[str] = None
    note: str = ""
    sort_order: Optional[int] = None


class UserPatch(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    level: Optional[str] = None
    attr: Optional[str] = None
    halftime: Optional[bool] = None
    admin_staff: Optional[bool] = None
    is_trainee: Optional[bool] = None
    mentor_uid: Optional[str] = None
    note: Optional[str] = None
    sort_order: Optional[int] = None


@router.get("/users")
def get_users(current_user: dict = Depends(get_current_user)):
    try:
        res = supabase.table("users").select(
            "uid, name, role, level, attr, halftime, admin_staff, is_trainee, mentor_uid, note, sort_order, created_at"
        ).order("sort_order").order("created_at").execute()
    except Exception:
        res = supabase.table("users").select(
            "uid, name, role, level, attr, halftime, admin_staff, is_trainee, mentor_uid, note, created_at"
        ).order("created_at").execute()
    return {"users": res.data}


@router.post("/users", status_code=201)
def create_user(
    user: UserCreate,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    if user.role == "superadmin" and current_user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="只有超級管理員可新增超級管理員帳號")

    # 帳號統一轉大寫儲存,登入與唯一性檢查皆大小寫不敏感
    uid_new = (user.uid or "").strip().upper()
    if not uid_new:
        raise HTTPException(status_code=400, detail="帳號 UID 不可為空")
    all_uids = supabase.table("users").select("uid").execute()
    dup = next((u for u in (all_uids.data or []) if (u.get("uid") or "").lower() == uid_new.lower()), None)
    if dup:
        raise HTTPException(status_code=400, detail=f"此帳號 UID 已存在({dup['uid']},不分大小寫)")

    if user.sort_order is None:
        cnt = supabase.table("users").select("uid", count="exact").execute()
        sort_order = (cnt.count or 0) + 1
    else:
        sort_order = user.sort_order

    supabase.table("users").insert({
        "uid": uid_new,
        "password_hash": get_password_hash(user.password),
        "name": user.name,
        "role": user.role,
        "level": user.level,
        "attr": user.attr,
        "halftime": user.halftime,
        "admin_staff": user.admin_staff,
        "is_trainee": user.is_trainee,
        "mentor_uid": user.mentor_uid or None,
        "note": user.note,
        "sort_order": sort_order,
    }).execute()
    return {"message": "帳號建立成功", "uid": uid_new}


@router.patch("/users/{uid}")
def patch_user(
    uid: str,
    body: UserPatch,
    current_user: dict = Depends(get_current_user),
):
    requester = current_user.get("sub")
    requester_role = current_user.get("role")

    if requester != uid and requester_role not in ["admin", "superadmin", "dual"]:
        raise HTTPException(status_code=403, detail="權限不足")

    update_data = body.model_dump(exclude_none=True)

    # 角色變更權限邏輯
    if "role" in update_data:
        new_role = update_data["role"]
        if requester_role == "superadmin":
            pass
        elif requester_role in ["admin", "dual"]:
            target_res = supabase.table("users").select("role").eq("uid", uid).single().execute()
            target_role = target_res.data.get("role") if target_res.data else None
            if target_role == "superadmin":
                raise HTTPException(status_code=403, detail="無法修改超級管理員帳號")
            if new_role == "superadmin":
                raise HTTPException(status_code=403, detail="只有超級管理員可設定超級管理員角色")
        else:
            raise HTTPException(status_code=403, detail="權限不足")

    if update_data:
        supabase.table("users").update(update_data).eq("uid", uid).execute()
    return {"message": "更新成功"}


@router.post("/auth/change-password")
def change_password(
    body: ChangePassword,
    current_user: dict = Depends(get_current_user),
):
    uid = current_user.get("sub")
    res = supabase.table("users").select("password_hash").eq("uid", uid).single().execute()
    if not res.data or not verify_password(body.old_password, res.data["password_hash"]):
        raise HTTPException(status_code=400, detail="目前密碼不正確")
    if len(body.new_password) < 4:
        raise HTTPException(status_code=400, detail="新密碼至少 4 個字元")
    supabase.table("users").update({
        "password_hash": get_password_hash(body.new_password)
    }).eq("uid", uid).execute()
    return {"message": "密碼已變更"}


@router.post("/users/{uid}/reset-password")
def reset_password(
    uid: str,
    body: AdminResetPassword,
    current_user: dict = Depends(require_roles("admin", "superadmin")),
):
    if len(body.new_password) < 4:
        raise HTTPException(status_code=400, detail="密碼至少 4 個字元")
    supabase.table("users").update({
        "password_hash": get_password_hash(body.new_password)
    }).eq("uid", uid).execute()
    return {"message": "密碼已重設"}


@router.delete("/users/{uid}")
def delete_user(
    uid: str,
    current_user: dict = Depends(require_roles("admin", "superadmin")),
):
    if uid == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="無法刪除自己的帳號")
    supabase.table("users").delete().eq("uid", uid).execute()
    return {"message": "帳號已刪除"}


@router.post("/users/reorder")
def reorder_users(
    order: List[str],
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    for i, uid in enumerate(order):
        supabase.table("users").update({"sort_order": i}).eq("uid", uid).execute()
    return {"message": "排序已更新"}
