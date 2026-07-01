from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import bcrypt as _bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta, date as date_type
import math, os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

app = FastAPI(title="護理排班系統 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

security = HTTPBearer()


# ── 資料模型
class LoginRequest(BaseModel):
    uid: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    name: str
    uid: str

class UserCreate(BaseModel):
    uid: str
    password: str
    name: str
    role: str        # nurse, dual, admin, superadmin
    level: str       # leader, second, member
    attr: str        # 輪班屬性
    halftime: bool = False
    note: str = ""
    sort_order: Optional[int] = None

class UserPatch(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    level: Optional[str] = None
    attr: Optional[str] = None
    halftime: Optional[bool] = None
    note: Optional[str] = None
    sort_order: Optional[int] = None

class AdminResetPassword(BaseModel):
    new_password: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

class ShiftUpdate(BaseModel):
    nurse_uid: str
    date: str
    shift: Optional[str] = None

class RulesUpdate(BaseModel):
    rules: dict


# ── 工具函數
def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

def get_password_hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        if uid is None:
            raise HTTPException(status_code=401, detail="無效的 Token")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token 已過期或無效")

def require_roles(*roles):
    def checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="權限不足")
        return current_user
    return checker


# ── 路由
@app.get("/")
def root():
    return {"message": "護理排班系統 API 運行中", "version": "2.0.0"}


@app.post("/auth/login", response_model=Token)
def login(request: LoginRequest):
    res = supabase.table("users").select("*").eq("uid", request.uid).single().execute()
    if not res.data:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    user = res.data
    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    token = create_access_token({
        "sub": user["uid"],
        "role": user["role"],
        "name": user["name"],
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "name": user["name"],
        "uid": user["uid"],
    }


@app.get("/users")
def get_users(current_user: dict = Depends(get_current_user)):
    res = supabase.table("users").select(
        "uid, name, role, level, attr, halftime, note, sort_order, created_at"
    ).order("sort_order").order("created_at").execute()
    return {"users": res.data}


@app.post("/users", status_code=201)
def create_user(
    user: UserCreate,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    if user.role == "superadmin" and current_user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="只有超級管理員可新增超級管理員帳號")

    existing = supabase.table("users").select("uid").eq("uid", user.uid).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="此帳號 UID 已存在")

    # 計算 sort_order：接在最後
    if user.sort_order is None:
        cnt = supabase.table("users").select("uid", count="exact").execute()
        sort_order = (cnt.count or 0) + 1
    else:
        sort_order = user.sort_order

    supabase.table("users").insert({
        "uid": user.uid,
        "password_hash": get_password_hash(user.password),
        "name": user.name,
        "role": user.role,
        "level": user.level,
        "attr": user.attr,
        "halftime": user.halftime,
        "note": user.note,
        "sort_order": sort_order,
    }).execute()
    return {"message": "帳號建立成功", "uid": user.uid}


@app.patch("/users/{uid}")
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
            pass  # 超管無限制
        elif requester_role in ["admin", "dual"]:
            # 管理員可操作所有非超管帳號，但不能升為超管
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


@app.post("/auth/change-password")
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


@app.post("/users/{uid}/reset-password")
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


@app.delete("/users/{uid}")
def delete_user(
    uid: str,
    current_user: dict = Depends(require_roles("admin", "superadmin")),
):
    if uid == current_user.get("sub"):
        raise HTTPException(status_code=400, detail="無法刪除自己的帳號")
    supabase.table("users").delete().eq("uid", uid).execute()
    return {"message": "帳號已刪除"}


@app.post("/users/reorder")
def reorder_users(
    order: List[str],   # list of uid in new order
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    for i, uid in enumerate(order):
        supabase.table("users").update({"sort_order": i}).eq("uid", uid).execute()
    return {"message": "排序已更新"}


@app.get("/schedule")
def get_schedule(
    year: int,
    month: int,
    current_user: dict = Depends(get_current_user),
):
    start = f"{year}-{month:02d}-01"
    end = f"{year+1}-01-01" if month == 12 else f"{year}-{month+1:02d}-01"
    res = supabase.table("shifts").select("*").gte("date", start).lt("date", end).execute()
    return {"schedule": res.data}


@app.post("/schedule/shift")
def update_shift(
    update: ShiftUpdate,
    current_user: dict = Depends(get_current_user),
):
    role = current_user.get("role")
    uid = current_user.get("sub")

    if role == "nurse" and update.nurse_uid != uid:
        raise HTTPException(status_code=403, detail="只能修改自己的預班")

    existing = supabase.table("shifts").select("id").eq("nurse_uid", update.nurse_uid).eq("date", update.date).execute()

    if existing.data:
        supabase.table("shifts").update({
            "shift": update.shift,
            "confirmed": False,
            "updated_by": uid,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("nurse_uid", update.nurse_uid).eq("date", update.date).execute()
    else:
        supabase.table("shifts").insert({
            "code": f"{update.nurse_uid}_{update.date}",   # unique per nurse+date
            "label": update.shift or "",
            "nurse_uid": update.nurse_uid,
            "date": update.date,
            "shift": update.shift,
            "confirmed": False,
            "updated_by": uid,
        }).execute()

    try:
        supabase.table("shift_logs").insert({
            "nurse_uid": update.nurse_uid,
            "date": update.date,
            "shift": update.shift,
            "changed_by": uid,            # 舊欄位 NOT NULL 相容
            "operator_uid": uid,
            "operator_role": role,
            "action": "edit",
        }).execute()
    except Exception:
        pass  # log 失敗不影響主流程

    return {"message": "班別更新成功"}


@app.post("/schedule/confirm")
def confirm_shifts(
    shifts: List[ShiftUpdate],
    current_user: dict = Depends(get_current_user),
):
    uid = current_user.get("sub")
    role = current_user.get("role")

    for s in shifts:
        # 護理師只能確認自己的班
        if role == "nurse" and s.nurse_uid != uid:
            raise HTTPException(status_code=403, detail="只能確認自己的班別")

        existing = supabase.table("shifts").select("id").eq("nurse_uid", s.nurse_uid).eq("date", s.date).execute()
        if existing.data:
            supabase.table("shifts").update({
                "shift": s.shift,
                "confirmed": True,
                "updated_by": uid,
                "updated_at": datetime.utcnow().isoformat(),
            }).eq("nurse_uid", s.nurse_uid).eq("date", s.date).execute()
        else:
            supabase.table("shifts").insert({
                "code": f"{s.nurse_uid}_{s.date}",
                "label": s.shift or "",
                "nurse_uid": s.nurse_uid,
                "date": s.date,
                "shift": s.shift,
                "confirmed": True,
                "updated_by": uid,
            }).execute()

        try:
            supabase.table("shift_logs").insert({
                "nurse_uid": s.nurse_uid,
                "date": s.date,
                "shift": s.shift,
                "changed_by": uid,
                "operator_uid": uid,
                "operator_role": role,
                "action": "confirm",
            }).execute()
        except Exception:
            pass

    return {"message": f"已確認 {len(shifts)} 筆班別"}


@app.post("/schedule/unconfirm")
def unconfirm_shifts(
    shifts: List[ShiftUpdate],
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    uid = current_user.get("sub")
    role = current_user.get("role")
    for s in shifts:
        supabase.table("shifts").update({
            "confirmed": False,
            "updated_by": uid,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("nurse_uid", s.nurse_uid).eq("date", s.date).execute()
        try:
            supabase.table("shift_logs").insert({
                "nurse_uid": s.nurse_uid,
                "date": s.date,
                "shift": s.shift,
                "changed_by": uid,
                "operator_uid": uid,
                "operator_role": role,
                "action": "unconfirm",
            }).execute()
        except Exception:
            pass
    return {"message": f"已取消確認 {len(shifts)} 筆"}


@app.get("/rules")
def get_rules(current_user: dict = Depends(get_current_user)):
    res = supabase.table("rules").select("*").limit(1).execute()
    if res.data:
        return {"rules": res.data[0].get("data") or {}}
    return {"rules": {}}


@app.post("/rules")
def save_rules(
    body: RulesUpdate,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    existing = supabase.table("rules").select("id", "data").limit(1).execute()
    if existing.data:
        current_data = existing.data[0].get("data") or {}
        merged = {**current_data, **body.rules}
        supabase.table("rules").update({
            "data": merged,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("id", existing.data[0]["id"]).execute()
    else:
        supabase.table("rules").insert({
            "key": "config",   # 舊欄位 NOT NULL 相容
            "value": "{}",
            "data": body.rules,
        }).execute()
    return {"message": "規則已儲存"}


@app.post("/schedule/generate")
def generate_schedule(
    overwrite_confirmed: bool = False,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """
    順班演算法：
    1. 依輪班屬性與比例，把同種班排成連續區塊，OFF 均勻穿插於各區塊中
    2. 第二階段：逐日檢查 D/E/N 人數，不足時從 OFF 護理師補調
    固定班（固定D/E/N）整週期幾乎只排同一種班，僅在人力缺口下才少數例外
    """
    uid = current_user.get("sub")

    # ── 讀取規則
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "請先設定排班規則")
    rules = rules_res.data[0].get("data") or {}

    cycle      = rules.get("cycle", {})
    scheduling = rules.get("scheduling", {})
    ratio      = rules.get("ratio", {})

    start_str = cycle.get("start_date")
    end_str   = cycle.get("end_date")
    if not start_str or not end_str:
        raise HTTPException(400, "請先在「排班週期」設定開始與結束日期")

    start_d = date_type.fromisoformat(start_str)
    end_d   = date_type.fromisoformat(end_str)
    cycle_dates = [
        (start_d + timedelta(days=i)).isoformat()
        for i in range((end_d - start_d).days + 1)
    ]
    n = len(cycle_dates)

    max_consec  = int(scheduling.get("max_consecutive_work", 5))
    daily_d     = int(scheduling.get("daily_d", 3))
    daily_e     = int(scheduling.get("daily_e", 3))
    daily_n     = int(scheduling.get("daily_n", 3))
    no_reverse  = bool(scheduling.get("no_reverse_shift", True))
    holiday_days = int(cycle.get("holiday_days", 0))
    full_off    = min(8 + holiday_days, 13)
    part_off    = min(16 + holiday_days, 21)

    # ── 讀取護理師
    nurses_res = supabase.table("users").select(
        "uid, attr, halftime, level"
    ).in_("role", ["nurse", "dual"]).execute()
    nurses = nurses_res.data or []
    if not nurses:
        raise HTTPException(400, "尚無護理師帳號")

    # ── 計算各屬性的班別分配數量
    def shift_counts(attr: str, work_days: int) -> tuple[int, int, int]:
        """回傳 (d, e, n) 各班天數"""
        if attr == "固定D": return (work_days, 0, 0)
        if attr == "固定E": return (0, work_days, 0)
        if attr == "固定N": return (0, 0, work_days)

        def r(key): return max(1, int(ratio.get(key, 1)))

        if attr == "輪班DE":
            rd, re = r("de_d"), r("de_e"); tot = rd + re
            d = round(work_days * rd / tot); return (d, work_days - d, 0)
        if attr == "輪班EN":
            re, rn = r("en_e"), r("en_n"); tot = re + rn
            e = round(work_days * re / tot); return (0, e, work_days - e)
        if attr == "輪班DN":
            rd, rn = r("dn_d"), r("dn_n"); tot = rd + rn
            d = round(work_days * rd / tot); return (d, 0, work_days - d)
        # 輪班DEN（預設）
        rd, re, rn = r("den_d"), r("den_e"), r("den_n"); tot = rd + re + rn
        d = round(work_days * rd / tot); e = round(work_days * re / tot)
        return (d, e, work_days - d - e)

    # ── 建立單一區塊（shift × work_cnt，穿插 off_cnt 天 OFF）
    def build_block(shift: str, work_cnt: int, off_cnt: int) -> list[str]:
        """
        填法：連續排到 max_consec 上限就插 OFF，
        其餘 OFF 均勻分佈（避免 OFF 全堆到最後）
        """
        block: list[str] = []
        rem_w, rem_o = work_cnt, off_cnt
        consec = 0
        while rem_w > 0 or rem_o > 0:
            if consec >= max_consec and rem_o > 0:
                block.append("OFF"); rem_o -= 1; consec = 0
            elif rem_w > 0:
                block.append(shift); rem_w -= 1; consec += 1
            else:
                block.append("OFF"); rem_o -= 1; consec = 0
        return block

    # ── 產生單人順班排程（區塊式）
    def smooth_sched(off_days: int, d: int, e: int, nv: int) -> list[str]:
        work_days = d + e + nv
        blocks = [(s, c) for s, c in [("D", d), ("E", e), ("N", nv)] if c > 0]
        if not blocks:
            return ["OFF"] * (work_days + off_days)

        sched: list[str] = []
        rem_off = off_days
        for bi, (sh, wc) in enumerate(blocks):
            # 依比例分配 OFF 給每個區塊，最後一塊拿剩下的
            block_off = rem_off if bi == len(blocks) - 1 \
                        else math.floor(off_days * wc / work_days)
            rem_off -= block_off
            sched.extend(build_block(sh, wc, block_off))
        return sched

    # ── Phase 1：每人個別產生順班排程
    schedules: dict[str, list[str]] = {}
    nurse_attr: dict[str, str] = {}
    for nurse in nurses:
        attr       = nurse.get("attr") or "輪班DEN"
        nurse_attr[nurse["uid"]] = attr
        off_days   = part_off if nurse.get("halftime") else full_off
        off_days   = min(off_days, n - 1)
        work_days  = n - off_days
        d, e, nv   = shift_counts(attr, work_days)
        sched      = smooth_sched(off_days, d, e, nv)
        # 補齊或截斷至 n 天
        sched = (sched + ["OFF"] * n)[:n]
        schedules[nurse["uid"]] = sched

    # ── Phase 2：逐日調整，補足 D/E/N 人數缺口
    SHIFT_ALLOWED: dict[str, set[str]] = {
        "固定D":  {"D"},
        "固定E":  {"E"},
        "固定N":  {"N"},
        "輪班DE": {"D", "E"},
        "輪班EN": {"E", "N"},
        "輪班DN": {"D", "N"},
        "輪班DEN":{"D", "E", "N"},
    }
    REVERSE_FORBIDDEN: dict[str, set[str]] = {
        "N": {"D", "E"},  # 大夜後不可排白班或小夜
        "E": {"D"},       # 小夜後不可排白班
    }

    for day_i in range(n):
        for target, req in [("D", daily_d), ("E", daily_e), ("N", daily_n)]:
            cur = sum(1 for uid in schedules if schedules[uid][day_i] == target)
            if cur >= req:
                continue
            # 從 OFF 護理師中挑選可補班的
            for nurse in nurses:
                uid = nurse["uid"]
                if schedules[uid][day_i] != "OFF":
                    continue
                allowed = SHIFT_ALLOWED.get(nurse_attr[uid], {"D","E","N"})
                if target not in allowed:
                    continue
                # 反向班檢查
                if no_reverse and day_i > 0:
                    prev = schedules[uid][day_i - 1]
                    if target in REVERSE_FORBIDDEN.get(prev, set()):
                        continue
                schedules[uid][day_i] = target
                cur += 1
                if cur >= req:
                    break

    # ── Phase 3：寫入資料庫
    existing_res = supabase.table("shifts").select("nurse_uid, date, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    existing_map: dict[str, bool] = {
        f"{r['nurse_uid']}_{r['date']}": r.get("confirmed", False)
        for r in (existing_res.data or [])
    }

    to_insert, to_update = [], []
    for nurse_uid, sched in schedules.items():
        for i, shift in enumerate(sched):
            d_str = cycle_dates[i]
            key   = f"{nurse_uid}_{d_str}"
            if shift == "OFF":
                continue  # 休假不寫入，留空即可
            if key in existing_map:
                if not overwrite_confirmed and existing_map[key]:
                    continue  # 已確認班不覆蓋
                to_update.append({"nurse_uid": nurse_uid, "date": d_str, "shift": shift})
            else:
                to_insert.append({
                    "code":      key,
                    "label":     shift,
                    "nurse_uid": nurse_uid,
                    "date":      d_str,
                    "shift":     shift,
                    "confirmed": False,
                    "updated_by": uid,
                })

    if to_insert:
        supabase.table("shifts").insert(to_insert).execute()
    for row in to_update:
        supabase.table("shifts").update({
            "shift": row["shift"], "confirmed": False, "updated_by": uid,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("nurse_uid", row["nurse_uid"]).eq("date", row["date"]).execute()

    total = len(to_insert) + len(to_update)
    return {
        "message": f"✓ 已生成 {len(nurses)} 位護理師的班表（共 {total} 格）",
        "nurses": len(nurses), "cells": total,
        "inserted": len(to_insert), "updated": len(to_update),
    }


@app.get("/logs")
def get_logs(
    limit: int = 200,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    res = supabase.table("shift_logs").select("*").order("created_at", desc=True).limit(limit).execute()
    return {"logs": res.data}


@app.delete("/logs")
def delete_logs(
    before_hours: int,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    cutoff = (datetime.utcnow() - timedelta(hours=before_hours)).isoformat()
    supabase.table("shift_logs").delete().lt("created_at", cutoff).execute()
    return {"message": f"已清除 {before_hours} 小時前的操作紀錄"}
