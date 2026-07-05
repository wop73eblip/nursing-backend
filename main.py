from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import bcrypt as _bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta, date as date_type
import math, os, io
from urllib.parse import quote
from dotenv import load_dotenv
from supabase import create_client, Client
from ortools.sat.python import cp_model
import openpyxl
from openpyxl.styles import Font, Border, Side, Alignment, PatternFill

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
    try:
        res = supabase.table("users").select(
            "uid, name, role, level, attr, halftime, note, sort_order, created_at"
        ).order("sort_order").order("created_at").execute()
    except Exception:
        res = supabase.table("users").select(
            "uid, name, role, level, attr, halftime, note, created_at"
        ).order("created_at").execute()
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
    CP-SAT 排班演算法，遵守以下規則：
    硬規則：leader 配置、反向班、每週至少休1天、每週至多兩種班別、連班上限
    軟規則：順班（同種班連排）、固定班不切換、符合各班人數需求
    休假規則：週期首週末不同時休、每週休假上限、一例一休、特休最高順位
    """
    operator_uid = current_user.get("sub")

    # ── 讀取規則
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "請先設定排班規則")
    rules = rules_res.data[0].get("data") or {}

    cycle      = rules.get("cycle", {})
    scheduling = rules.get("scheduling", {})
    ratio      = rules.get("ratio", {})
    ratio_overrides_list = rules.get("ratio_overrides", [])
    ratio_overrides = {o["nurse_uid"]: o["ratio"] for o in ratio_overrides_list}

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
    weekdays = [(start_d + timedelta(days=i)).weekday() for i in range(n)]
    # weekday(): Mon=0 … Sat=5, Sun=6

    # ── 規則參數
    max_consec   = int(scheduling.get("max_consecutive_work", 5))
    daily_d      = int(scheduling.get("daily_d", 3))
    daily_e      = int(scheduling.get("daily_e", 3))
    daily_n      = int(scheduling.get("daily_n", 3))
    no_reverse   = bool(scheduling.get("no_reverse_shift", True))
    restrict_first_weekend = bool(scheduling.get("restrict_first_weekend", True))
    one_in_seven = bool(scheduling.get("one_in_seven", True))   # 一例一休
    lock_first_day       = bool(scheduling.get("lock_first_day", True))
    lock_designated_off  = bool(scheduling.get("lock_designated_off", True))
    weekly_max_off_auto  = int(scheduling.get("weekly_max_off_auto", 2))   # 自動休連續天數上限
    weekly_max_off_total = int(scheduling.get("weekly_max_off_total", 3))  # 每週應休總上限
    holiday_days = int(cycle.get("holiday_days", 0))
    full_off  = min(8 + holiday_days, 13)
    part_off  = min(16 + holiday_days, 21)

    # 從規則讀取班別定義（前端班別設定儲存的三分類）
    shift_defs = rules.get("shifts", {})
    _rest_defs  = shift_defs.get("rest", [])   # 應休班別（OFF、半）
    _leave_defs = shift_defs.get("off",  [])   # 放假/調整類（V、喪、員⋯）
    _work_defs  = shift_defs.get("work", [])   # 上班類（D、E、N、會、公、書記⋯）

    # 應休代碼集：計入應休天數名額（預設 OFF + 半）
    REST_CODES = {s["code"] for s in _rest_defs if s.get("code")} or {"OFF", "半"}
    # 放假/調整代碼集：最高順位鎖定，不佔應休名額（預設 V、員⋯）
    LEAVE_ADJUST = {s["code"] for s in _leave_defs if s.get("code")} or {"V", "員", "喪", "延休", "補休", "調移"}
    # 行政/上班班別視同 D（不計臨床人力）：admin_only 的上班類
    ADMIN_SHIFTS = {s["code"] for s in _work_defs if s.get("admin_only")} or {"會", "公", "書記"}
    # 固定班型索引（用於軟懲罰）
    FIXED_SHIFT_MAP = {"固定D": 0, "固定E": 1, "固定N": 2}

    # ── 讀取護理師
    nurses_res = supabase.table("users").select(
        "uid, attr, halftime, level"
    ).in_("role", ["nurse", "dual"]).order("sort_order").execute()
    nurses = nurses_res.data or []
    if not nurses:
        raise HTTPException(400, "尚無護理師帳號")
    M = len(nurses)
    nid = {n["uid"]: i for i, n in enumerate(nurses)}

    # ── 讀取已確認班 / 指定班（含特休、指定休）
    existing_res = supabase.table("shifts").select("nurse_uid, date, shift, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    existing: dict[tuple, dict] = {
        (r["nurse_uid"], r["date"]): r
        for r in (existing_res.data or [])
    }

    # ── helper：計算各護理師每週的 ISO 週邊界
    def week_ranges(dates: list[str]) -> list[tuple[int,int]]:
        """回傳 [(start_i, end_i)] 代表週一到週日的日期索引範圍（週期內）"""
        weeks = []
        i = 0
        while i < len(dates):
            wd = weekdays[i]
            week_start = i - wd  # Mon of that week (may be < 0)
            week_end   = week_start + 6
            # 夾到週期內
            ws = max(0, week_start)
            we = min(len(dates) - 1, week_end)
            weeks.append((ws, we))
            # 跳到下個週一
            i = week_end + 1
        return weeks
    weeks = week_ranges(cycle_dates)

    # ── 計算各護理師應排班次數（依比例）
    def shift_counts(attr: str, work_days: int, nurse_uid: str) -> tuple[int,int,int]:
        if attr == "固定D": return (work_days, 0, 0)
        if attr == "固定E": return (0, work_days, 0)
        if attr == "固定N": return (0, 0, work_days)
        ov = ratio_overrides.get(nurse_uid, {})
        def r(key, default=1): return max(1, int(ov.get(key, ratio.get(key, default))))
        if attr == "輪班DE":
            rd, re = r("D",1), r("E",1); tot = rd+re
            d = round(work_days*rd/tot); return (d, work_days-d, 0)
        if attr == "輪班EN":
            re, rn = r("E",1), r("N",1); tot = re+rn
            e = round(work_days*re/tot); return (0, e, work_days-e)
        if attr == "輪班DN":
            rd, rn = r("D",1), r("N",1); tot = rd+rn
            d = round(work_days*rd/tot); return (d, 0, work_days-d)
        rd, re, rn = r("D",1), r("E",1), r("N",1); tot = rd+re+rn
        d = round(work_days*rd/tot); e = round(work_days*re/tot)
        return (d, e, work_days-d-e)

    # ── 允許班種（依輪班屬性）
    SHIFT_ALLOWED: dict[str, list[str]] = {
        "固定D":   ["D"],
        "固定E":   ["E"],
        "固定N":   ["N"],
        "輪班DE":  ["D","E"],
        "輪班EN":  ["E","N"],
        "輪班DN":  ["D","N"],
        "輪班DEN": ["D","E","N"],
    }
    WORK_SHIFTS = ["D","E","N"]
    SI = {s: i for i, s in enumerate(["D","E","N","OFF"])}  # shift index

    # ── 讀取上週參考資料（週期前 7 天，用於跨週連班與班型轉換判斷）
    prev_dates_list = [(start_d - timedelta(days=7-i)).isoformat() for i in range(7)]
    prev_res = supabase.table("shifts").select("nurse_uid, date, shift") \
        .gte("date", prev_dates_list[0]).lte("date", prev_dates_list[-1]).execute()
    prev_shifts_by_nurse: dict[str, list[str]] = {}
    for r in (prev_res.data or []):
        uid_r = r["nurse_uid"]
        if uid_r not in prev_shifts_by_nurse:
            prev_shifts_by_nurse[uid_r] = ["OFF"] * 7
        try:
            idx = prev_dates_list.index(r["date"])
            prev_shifts_by_nurse[uid_r][idx] = r.get("shift") or "OFF"
        except ValueError:
            pass

    # ── CP-SAT 模型
    model = cp_model.CpModel()
    leave_adjust_per_m: dict[int, set[int]] = {}  # 各護理師的 LEAVE_ADJUST 天索引
    off_slack_vars: list[tuple[int, any]] = []     # (m, slack_var) for shortage warning

    # x[m][t] ∈ {0,1,2,3} → D/E/N/OFF
    x: list[list] = [
        [model.new_int_var(0, 3, f"x_{m}_{t}") for t in range(n)]
        for m in range(M)
    ]
    # bool 變數：is_shift[m][t][s]
    b: list[list[list]] = [
        [[model.new_bool_var(f"b_{m}_{t}_{s}") for s in range(4)] for t in range(n)]
        for m in range(M)
    ]

    for m in range(M):
        nurse = nurses[m]
        attr  = nurse.get("attr") or "輪班DEN"
        is_ht = nurse.get("halftime", False)
        lvl   = nurse.get("level", "member")
        uid   = nurse["uid"]

        # x ↔ b 對應
        for t in range(n):
            model.add(x[m][t] == sum(s * b[m][t][s] for s in range(4)))
            model.add_exactly_one(b[m][t])

        # ── 鎖定已確認班 / 放假調整類 / 指定休
        locked_off_days_m: set[int] = set()    # 指定 OFF（計入應休名額）
        leave_adjust_days_m: set[int] = set()  # 放假/調整類（不佔應休名額）
        for t, d_str in enumerate(cycle_dates):
            key = (uid, d_str)
            if key not in existing:
                continue
            row = existing[key]
            shift = row.get("shift") or "OFF"
            confirmed = row.get("confirmed", False)

            # 應休類（REST_CODES）一律視同 OFF 處理（計入應休名額）
            if shift in REST_CODES and shift != "OFF":
                shift = "OFF"

            # 行政班視同 D
            if shift in ADMIN_SHIFTS:
                shift = "D"

            # 放假/調整類：鎖定為 OFF，不佔應休名額
            if shift in LEAVE_ADJUST:
                model.add(x[m][t] == 3)
                leave_adjust_days_m.add(t)
                continue

            # 已確認班
            if confirmed and not overwrite_confirmed:
                si = SI.get(shift, 3)
                model.add(x[m][t] == si)
                if si == 3:
                    locked_off_days_m.add(t)
                continue

            # 第一天鎖定（只鎖工作班，休假讓 CP-SAT 自行決定）
            if lock_first_day and t == 0 and shift not in REST_CODES and shift not in LEAVE_ADJUST and shift != "OFF":
                si = SI.get(shift, 3)
                model.add(x[m][t] == si)
                continue

            # 指定休不可覆蓋
            if lock_designated_off and shift == "OFF":
                model.add(x[m][t] == 3)
                locked_off_days_m.add(t)

        # ── 允許班種限制（輪班類硬限制；固定班改用軟懲罰）
        fixed_si = FIXED_SHIFT_MAP.get(attr)
        if fixed_si is None:
            allowed = SHIFT_ALLOWED.get(attr, WORK_SHIFTS)
            allowed_si = set(SI[s] for s in allowed) | {3}
            for t in range(n):
                for s in range(4):
                    if s not in allowed_si:
                        model.add(b[m][t][s] == 0)

        # ── 休假天數（LEAVE_ADJUST 不計入應休名額）
        la_count = len(leave_adjust_days_m)
        guaranteed_off = part_off if is_ht else full_off
        # 根據實際人數動態計算每人所需 OFF，避免上限過嚴導致 INFEASIBLE
        # 總 OFF 名額 = 總人天 - 每天所需人力 × 天數；每人平均 = 總 OFF / 人數
        _required_per_day = daily_d + daily_e + daily_n
        _total_off_needed = max(0, M * (n - la_count) - _required_per_day * n)
        _expected_off = (_total_off_needed + M - 1) // M  # ceiling
        off_days = max(guaranteed_off, _expected_off)
        off_days = min(off_days, n - la_count - 1)
        effective_work_days = max(0, n - off_days - la_count)
        d_cnt, e_cnt, nv_cnt = shift_counts(attr, effective_work_days, uid)

        # 班次數約束（允許偏差 ±2）
        total_d  = sum(b[m][t][0] for t in range(n))
        total_e  = sum(b[m][t][1] for t in range(n))
        total_nv = sum(b[m][t][2] for t in range(n))
        # 應休 OFF（排除 LEAVE_ADJUST）
        free_off = [b[m][t][3] for t in range(n) if t not in leave_adjust_days_m]
        # 人力不足鬆弛：off_days 下限允許最多減少 MAX_OFF_REDUCE 天
        # 注意：懲罰值在下方 penalties = [] 初始化後才加入，這裡只建立變數
        off_slack = model.new_int_var(0, 2, f"off_slack_{m}")
        off_slack_vars.append((m, off_slack))
        model.add(sum(free_off) >= off_days - 2 - off_slack)
        model.add(sum(free_off) <= off_days + 2)
        # 班次分配：移除硬約束（上限與下限）
        # 硬約束導致人少時 INFEASIBLE（上限）或班種分配過緊（下限）
        # 由每日 daily 等式約束（全局總量）+ FIX_PENALTY 軟懲罰（個人偏離）來保證分配均衡

        # ── 硬規則 2：反向班禁止
        # 允許模式：E, OFF, D  /  N, OFF, E  /  N, OFF, OFF, D
        # 禁止模式（直接或插非 OFF 換班）：
        #   E→D：E 後 1 天不能是 D（需先有 1 天 OFF）
        #   N→E：N 後 1 天不能是 E（需先有 1 天 OFF）
        #   N→D：N 後 1 天或 2 天都不能是 D（需先有 2 天 OFF）
        if no_reverse:
            for t in range(n - 1):
                # E 後緊接 D 禁止（E→D 需要 1 天 OFF 間隔）
                model.add(b[m][t+1][0] == 0).only_enforce_if(b[m][t][1])
                # N 後緊接 E 禁止（N→E 需要 1 天 OFF 間隔）
                model.add(b[m][t+1][1] == 0).only_enforce_if(b[m][t][2])
                # N 後緊接 D 禁止（N→D 需要 2 天 OFF 間隔）
                model.add(b[m][t+1][0] == 0).only_enforce_if(b[m][t][2])
            for t in range(n - 2):
                # N 後第 2 天也不能是 D（1 天 OFF 不夠，要 2 天）
                model.add(b[m][t+2][0] == 0).only_enforce_if(b[m][t][2])

        # ── 硬規則 3：每週至少一天應休（OFF 或半），LEAVE_ADJUST（V、員、喪⋯）不計入
        for ws, we in weeks:
            week_range = list(range(ws, we + 1))
            # 僅計算非 LEAVE_ADJUST 的天（LEAVE_ADJUST 不算應休）
            rest_eligible = [t for t in week_range if t not in leave_adjust_days_m]
            if not rest_eligible:
                continue  # 整週都是 LEAVE_ADJUST，跳過
            # 計算本週「可自由調整」的天（非確認上班且非第一天鎖定上班）
            free_in_week = []
            for t in rest_eligible:
                key = (uid, cycle_dates[t])
                if key not in existing:
                    free_in_week.append(t)
                    continue
                row = existing[key]
                sh  = (row.get("shift") or "OFF")
                locked_work = (
                    (row.get("confirmed") and not overwrite_confirmed and sh not in REST_CODES and sh not in LEAVE_ADJUST)
                    or (lock_first_day and t == 0 and sh not in REST_CODES and sh not in LEAVE_ADJUST)
                )
                if not locked_work:
                    free_in_week.append(t)
            if free_in_week:
                # 有至少一個可自由的天 → 強制至少一天 OFF/半（排除 LEAVE_ADJUST）
                model.add(sum(b[m][t][3] for t in rest_eligible) >= 1)
            # 否則整週鎖滿上班 → 跳過約束（異常偵測會在生成後標示警告）

        # ── 硬規則 4：每週 D/E/N 至多兩種班別
        for ws, we in weeks:
            has_D = model.new_bool_var(f"hasD_{m}_{ws}")
            has_E = model.new_bool_var(f"hasE_{m}_{ws}")
            has_N = model.new_bool_var(f"hasN_{m}_{ws}")
            wlen = we - ws + 1
            model.add(sum(b[m][t][0] for t in range(ws, we+1)) >= 1).only_enforce_if(has_D)
            model.add(sum(b[m][t][0] for t in range(ws, we+1)) == 0).only_enforce_if(has_D.negated())
            model.add(sum(b[m][t][1] for t in range(ws, we+1)) >= 1).only_enforce_if(has_E)
            model.add(sum(b[m][t][1] for t in range(ws, we+1)) == 0).only_enforce_if(has_E.negated())
            model.add(sum(b[m][t][2] for t in range(ws, we+1)) >= 1).only_enforce_if(has_N)
            model.add(sum(b[m][t][2] for t in range(ws, we+1)) == 0).only_enforce_if(has_N.negated())
            model.add(has_D + has_E + has_N <= 2)

        # ── 跨週連班：計算上週末尾連續上班天數，限制週期開頭
        prev_sched_m = prev_shifts_by_nurse.get(uid, ["OFF"] * 7)
        trailing_work = 0
        for ps in reversed(prev_sched_m):
            if ps not in REST_CODES and ps not in LEAVE_ADJUST and ps != "OFF":
                trailing_work += 1
            else:
                break
        if trailing_work > 0:
            remaining = max(0, max_consec - trailing_work)
            # 週期開頭 (remaining+1) 天內，上班天數不得超過 remaining
            end_t = min(n, remaining + 1)
            model.add(
                sum(b[m][t][s] for t in range(end_t) for s in range(3)) <= remaining
            )

        # ── 連班上限（週期內）
        for t in range(n - max_consec):
            model.add(
                sum(b[m][t+k][s] for k in range(max_consec+1) for s in range(3)) <= max_consec
            )

        # ── 一例一休（可勾選）：每週至少 2 天休假
        if one_in_seven:
            for ws, we in weeks:
                model.add(sum(b[m][t][3] for t in range(ws, we+1)) >= 2)

        # ── 週期首個週末不同時休（restrict_first_weekend）
        if restrict_first_weekend:
            sat_idx, sun_idx = None, None
            for t, d_str in enumerate(cycle_dates):
                d_obj = start_d + timedelta(days=t)
                if d_obj.weekday() == 5 and sat_idx is None:
                    sat_idx = t
                if d_obj.weekday() == 6 and sun_idx is None:
                    sun_idx = t
                if sat_idx is not None and sun_idx is not None:
                    break
            if sat_idx is not None and sun_idx is not None:
                # 不能同時都是 OFF
                model.add(b[m][sat_idx][3] + b[m][sun_idx][3] <= 1)

        # ── 規則 7：連續 OFF 總天數上限（指定休 + 自動休，不含 LEAVE_ADJUST）
        # 滑動視窗：任意 weekly_max_off_total+1 天的視窗內（無 LEAVE_ADJUST 介入時），OFF 不得全滿
        for t in range(n - weekly_max_off_total):
            # 若視窗內有 LEAVE_ADJUST，該天自然中斷連休，跳過
            if any((t + k) in leave_adjust_days_m for k in range(weekly_max_off_total + 1)):
                continue
            model.add(
                sum(b[m][t + k][3] for k in range(weekly_max_off_total + 1))
                <= weekly_max_off_total
            )

        # ── 規則 6（新）：自動休連續天數不超過 weekly_max_off_auto 天
        for t in range(n - weekly_max_off_auto):
            auto_off_win = [
                b[m][t+k][3]
                for k in range(weekly_max_off_auto + 1)
                if (t+k) not in locked_off_days_m and (t+k) not in leave_adjust_days_m
            ]
            if len(auto_off_win) > weekly_max_off_auto:
                model.add(sum(auto_off_win) <= weekly_max_off_auto)

        leave_adjust_per_m[m] = leave_adjust_days_m

    # ── 硬規則 1：每班每日剛好 req 人；leader/second 為軟約束（懲罰），避免人力不足時 INFEASIBLE
    leaders = [i for i, n in enumerate(nurses) if n.get("level") == "leader"]
    seconds = [i for i, n in enumerate(nurses) if n.get("level") in ("leader", "second")]

    SHIFT_ALLOWED_MAP = {
        "固定D": ["D"], "固定E": ["E"], "固定N": ["N"],
        "輪班DE": ["D", "E"], "輪班EN": ["E", "N"], "輪班DN": ["D", "N"], "輪班DEN": ["D", "E", "N"],
    }
    _WORK_SHIFTS_LIST = ["D", "E", "N"]
    # 各班別有能力上班的 leader/second 清單（用於檢查可行性）
    _capable_leaders = {
        si: [m for m in leaders if _WORK_SHIFTS_LIST[si] in SHIFT_ALLOWED_MAP.get(nurses[m].get("attr") or "輪班DEN", _WORK_SHIFTS_LIST)]
        for si in range(3)
    }
    _capable_seconds = {
        si: [m for m in seconds if _WORK_SHIFTS_LIST[si] in SHIFT_ALLOWED_MAP.get(nurses[m].get("attr") or "輪班DEN", _WORK_SHIFTS_LIST)]
        for si in range(3)
    }
    # 各班別有能力的 leader 數量 = 若 <= 1，強制排班會造成 INFEASIBLE（那唯一 leader 無法休假）
    # 改為高懲罰軟約束：缺 1 leader 罰 50，缺 leader+second 各罰 30
    LEADER_PENALTY  = 200   # 缺 leader 高懲罰，盡量安排 leader；不設為硬約束以免人少時 INFEASIBLE
    SECOND_PENALTY  = 100

    for t in range(n):
        for si, req in [(0, daily_d), (1, daily_e), (2, daily_n)]:
            if req == 0:
                continue
            model.add(sum(b[m][t][si] for m in range(M)) == req)

    # ── 軟規則：順班目標 + 固定班偏離懲罰 + leader/second 出勤偏好
    FIX_PENALTY = 20
    penalties = []
    # leader/second 軟懲罰（先佔位，懲罰值後加入）
    leader_miss_vars: list[tuple[object, int]] = []   # (bool_var, penalty)
    for t in range(n):
        for si in range(3):
            req = [daily_d, daily_e, daily_n][si]
            if req == 0:
                continue
            # 至少 1 leader（軟）
            cl = _capable_leaders[si]
            if cl:
                miss_l = model.new_bool_var(f"miss_leader_{t}_{si}")
                # miss_l = 1 iff no capable leader works this shift this day
                model.add(sum(b[m][t][si] for m in cl) >= 1 - miss_l)
                model.add(miss_l <= 1 - sum(b[m][t][si] for m in cl) // max(1, len(cl)))
                # simpler formulation
                # miss_l == 1  <=>  sum == 0
                model.add(sum(b[m][t][si] for m in cl) == 0).only_enforce_if(miss_l)
                model.add(sum(b[m][t][si] for m in cl) >= 1).only_enforce_if(miss_l.negated())
                leader_miss_vars.append((miss_l, LEADER_PENALTY))
            # 至少 2 capable leaders/seconds（軟）
            cs = _capable_seconds[si]
            if len(cs) >= 2:
                miss_s = model.new_bool_var(f"miss_second_{t}_{si}")
                model.add(sum(b[m][t][si] for m in cs) == 0).only_enforce_if(miss_s)
                model.add(sum(b[m][t][si] for m in cs) >= 1).only_enforce_if(miss_s.negated())
                leader_miss_vars.append((miss_s, SECOND_PENALTY))
    # off_slack 懲罰在此加入（必須在 penalties = [] 之後）
    for _, slack_var in off_slack_vars:
        penalties.append(slack_var * 200)  # 遠高於切換懲罰，只在人力不足時才縮減
    # leader/second 軟約束懲罰
    for miss_var, pen in leader_miss_vars:
        penalties.append(miss_var * pen)
    for m in range(M):
        attr = nurses[m].get("attr") or "輪班DEN"
        fixed_si = FIXED_SHIFT_MAP.get(attr)
        la_set = leave_adjust_per_m.get(m, set())

        # ── 班次分配偏差懲罰（雙向，只約束獨立班種）
        # D+E / D+N / E+N 是固定值，只需約束其中一個方向，另一個自動對齊
        # DEN 約束 D 和 E，N 自動跟著
        DIST_PENALTY = 8
        _total_d  = sum(b[m][t][0] for t in range(n))
        _total_e  = sum(b[m][t][1] for t in range(n))
        _total_nv = sum(b[m][t][2] for t in range(n))
        _la_count_m = len(leave_adjust_per_m.get(m, set()))
        _guaranteed_off_m = part_off if nurses[m].get("halftime") else full_off
        _req_per_day = daily_d + daily_e + daily_n
        _total_off_m = max(0, M * (n - _la_count_m) - _req_per_day * n)
        _expected_off_m = (_total_off_m + M - 1) // M
        _off_days_m = max(_guaranteed_off_m, _expected_off_m)
        _off_days_m = min(_off_days_m, n - _la_count_m - 1)
        _work_m = max(0, n - _off_days_m - _la_count_m)
        _dc, _ec, _nc = shift_counts(attr, _work_m, uid)

        def _add_abs_penalty(total_var, target: int, label: str):
            """懲罰雙向偏差：±1 天彈性，超過才開始計分"""
            if target <= 0:
                return
            dev = model.new_int_var(0, n, label)
            model.add(dev >= total_var - target - 1)   # actual > target+1 才罰
            model.add(dev >= target - total_var - 1)   # actual < target-1 才罰
            model.add(dev >= 0)
            penalties.append(dev * DIST_PENALTY)

        if attr == "輪班DE":
            _add_abs_penalty(_total_d, _dc, f"dev_d_{m}")
            # E 自動對齊，不重複懲罰
        elif attr == "輪班DN":
            _add_abs_penalty(_total_d, _dc, f"dev_d_{m}")
            # N 自動對齊
        elif attr == "輪班EN":
            _add_abs_penalty(_total_e, _ec, f"dev_e_{m}")
            # N 自動對齊
        elif attr == "輪班DEN":
            _add_abs_penalty(_total_d, _dc, f"dev_d_{m}")
            _add_abs_penalty(_total_e, _ec, f"dev_e_{m}")
            # N 自動對齊
        else:
            # 固定班由 FIX_PENALTY 處理，此處不另外懲罰
            pass

        if fixed_si is not None:
            # 固定班：懲罰非固定班種（軟規則，人力不足時才允許偏離）
            for t in range(n):
                if t not in la_set:
                    for s in range(3):
                        if s != fixed_si:
                            penalties.append(b[m][t][s] * FIX_PENALTY)
        else:
            # 軟規則 A：盡量順班（減少切換班別）+ 切換前盡量安排休息
            # 直接切換（g=0）+3；隔 OFF 天再切換（g>=1）+2
            allowed = SHIFT_ALLOWED.get(attr, WORK_SHIFTS)
            if len(allowed) <= 1:
                continue
            max_gap = weekly_max_off_total  # Rule7 限制最大連續 OFF

            # 跨週班型轉換懲罰：上週最後一個非 OFF 班型
            uid_m = nurses[m]["uid"]
            prev_m = prev_shifts_by_nurse.get(uid_m, ["OFF"] * 7)
            last_prev_si = None
            for ps in reversed(prev_m):
                pi = SI.get(ps)
                if pi is not None and pi < 3 and WORK_SHIFTS[pi] in allowed:
                    last_prev_si = pi
                    break
            if last_prev_si is not None:
                for s2 in range(3):
                    if s2 == last_prev_si or WORK_SHIFTS[s2] not in allowed:
                        continue
                    # g=0（跨週直接切換）：day0 是 s2
                    sw_p0 = model.new_bool_var(f"prev_gsw0_{m}_{s2}")
                    model.add(sw_p0 >= b[m][0][s2])
                    penalties.append(sw_p0 * 3)
                    # g=1（跨週隔 1 OFF）：day0=OFF, day1=s2
                    if n >= 2:
                        sw_p1 = model.new_bool_var(f"prev_gsw1_{m}_{s2}")
                        model.add(sw_p1 >= b[m][0][3] + b[m][1][s2] - 1)
                        penalties.append(sw_p1 * 2)
                    # g=2（跨週隔 2 OFF）：day0=OFF, day1=OFF, day2=s2
                    if n >= 3:
                        sw_p2 = model.new_bool_var(f"prev_gsw2_{m}_{s2}")
                        model.add(sw_p2 >= b[m][0][3] + b[m][1][3] + b[m][2][s2] - 2)
                        penalties.append(sw_p2 * 2)

            # 週期內班型轉換懲罰
            for t in range(1, n):
                for s2 in range(3):
                    if WORK_SHIFTS[s2] not in allowed:
                        continue
                    for g in range(min(max_gap, t) + 1):  # g = 中間連續 OFF 天數
                        t1 = t - g - 1
                        if t1 < 0:
                            continue
                        for s1 in range(3):
                            if s1 == s2:
                                continue
                            if WORK_SHIFTS[s1] not in allowed:
                                continue
                            # t1=s1, t1+1..t-1 全為 OFF, t=s2
                            parts = ([b[m][t1][s1]]
                                     + [b[m][t1 + k][3] for k in range(1, g + 1)]
                                     + [b[m][t][s2]])
                            sw = model.new_bool_var(f"gsw_{m}_{t}_{g}_{s1}_{s2}")
                            model.add(sw >= sum(parts) - (g + 1))
                            cost = 3 if g == 0 else 2
                            penalties.append(sw * cost)

    model.minimize(sum(penalties))

    # ── 求解
    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 60
    solver.parameters.num_workers = 4
    status = solver.solve(model)

    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        # 回傳具體的違規原因
        violations = []
        if not leaders:
            violations.append("沒有設定 leader 層級的護理師")
        violations.append("人力可能不足以滿足每日每班最低人數需求")
        raise HTTPException(
            400,
            "⚠ 無法生成符合所有規則的班表。原因可能包含：" +
            "；".join(violations) if violations else
            "人力配置與規則限制衝突，請檢查人數設定、反向班規則或連班上限。"
        )

    # ── 解析結果
    SHIFT_NAMES = ["D", "E", "N", "OFF"]
    schedules: dict[str, list[str]] = {}
    for m, nurse in enumerate(nurses):
        sched = [SHIFT_NAMES[solver.value(x[m][t])] for t in range(n)]
        # 還原特休、指定休（不被 CP-SAT 覆蓋，從 existing 讀回）
        for t, d_str in enumerate(cycle_dates):
            key = (nurse["uid"], d_str)
            if key in existing:
                orig = existing[key].get("shift") or "OFF"
                if orig in LEAVE_ADJUST:
                    sched[t] = orig  # 放假/調整類：保留原班碼
                elif orig in ADMIN_SHIFTS:
                    sched[t] = orig  # 行政班：保留原班碼
                elif orig in REST_CODES and orig != "OFF":
                    sched[t] = orig  # 應休類（如半）：保留原班碼
        schedules[nurse["uid"]] = sched

    # ── 人力不足警告（off_slack > 0）
    warnings: list[str] = []
    reduced_nurses = []
    for mi, slack_var in off_slack_vars:
        v = solver.value(slack_var)
        if v > 0:
            nm = nurses[mi].get("name") or nurses[mi]["uid"]
            reduced_nurses.append(f"{nm}（減 {v} 天）")
    if reduced_nurses:
        warnings.append("⚠ 人力不足，以下護理師應休天數已自動縮減：" + "、".join(reduced_nurses))

    # ── 異常偵測
    anomalies: list[str] = []
    SHIFT_NAMES_DETECT = ["D", "E", "N", "OFF"]
    for mi, nurse in enumerate(nurses):
        sched_m = [SHIFT_NAMES_DETECT[solver.value(x[mi][t])] for t in range(n)]
        nm = nurse.get("name") or nurse["uid"]
        prev_m = prev_shifts_by_nurse.get(nurse["uid"], ["OFF"] * 7)
        combined = prev_m + sched_m
        consec = 0
        for ps in combined:
            if ps not in REST_CODES and ps not in LEAVE_ADJUST and ps != "OFF":
                consec += 1
                if consec > max_consec:
                    anomalies.append(f"⚠ {nm}：跨週連續上班超過 {max_consec} 天（含上週）")
                    break
            else:
                consec = 0
    leader_indices = [i for i, n in enumerate(nurses) if n.get("level") == "leader"]
    for t in range(n):
        for si, req, sh in [(0, daily_d, "D"), (1, daily_e, "E"), (2, daily_n, "N")]:
            if req == 0:
                continue
            if not any(solver.value(b[li][t][si]) for li in leader_indices):
                anomalies.append(f"⚠ {cycle_dates[t]} {sh}班：無 leader 排班")

    # ── 計算格子數（供前端顯示）
    existing_map_keys: set[str] = {
        f"{r['nurse_uid']}_{r['date']}" for r in (existing_res.data or [])
    }
    existing_confirmed: set[str] = {
        f"{r['nurse_uid']}_{r['date']}"
        for r in (existing_res.data or []) if r.get("confirmed")
    }
    new_cells, update_cells = 0, 0
    for nurse_uid, sched in schedules.items():
        for i, shift in enumerate(sched):
            if shift == "OFF":
                continue
            key = f"{nurse_uid}_{cycle_dates[i]}"
            if key in existing_map_keys:
                if overwrite_confirmed or key not in existing_confirmed:
                    update_cells += 1
            else:
                new_cells += 1

    # ── schedules 轉為 {nurse_uid: {date: shift}} 方便前端傳回 commit
    schedules_dict = {
        uid: {cycle_dates[i]: s for i, s in enumerate(sched) if s != "OFF"}
        for uid, sched in schedules.items()
    }

    return {
        "message": f"✓ CP-SAT 計算完成（{len(nurses)} 位護理師，新增 {new_cells} 格、更新 {update_cells} 格）",
        "schedules": schedules_dict,
        "cycle_dates": cycle_dates,
        "overwrite_confirmed": overwrite_confirmed,
        "solver_status": solver.status_name(status),
        "nurses": len(nurses), "new_cells": new_cells, "update_cells": update_cells,
        "warnings": warnings,
        "anomalies": anomalies,
    }


class CommitScheduleBody(BaseModel):
    schedules: dict[str, dict[str, str]]   # {nurse_uid: {date: shift}}
    cycle_dates: list[str]
    overwrite_confirmed: bool = False


@app.post("/schedule/commit")
def commit_schedule(
    body: CommitScheduleBody,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """將 generate 回傳的 schedules 寫入資料庫"""
    operator_uid = current_user.get("sub")

    # 讀取規則以取得班別定義（用於分類）
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    rules = rules_res.data[0].get("data") or {} if rules_res.data else {}
    shift_defs = rules.get("shifts", {})
    _rest_defs  = shift_defs.get("rest", [])
    _leave_defs = shift_defs.get("off",  [])
    REST_CODES   = {s["code"] for s in _rest_defs  if s.get("code")} or {"OFF", "半"}
    LEAVE_ADJUST = {s["code"] for s in _leave_defs if s.get("code")} or {"V", "員", "喪", "延休", "補休", "調移"}

    all_dates = body.cycle_dates
    if not all_dates:
        raise HTTPException(400, "無排班日期")

    # 讀取現有班別
    start_str, end_str = all_dates[0], all_dates[-1]
    existing_res = supabase.table("shifts").select("nurse_uid, date, shift, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    existing_map: dict[str, bool] = {
        f"{r['nurse_uid']}_{r['date']}": r.get("confirmed", False)
        for r in (existing_res.data or [])
    }

    to_insert, to_update = [], []
    generated_keys = []

    for nurse_uid, date_shifts in body.schedules.items():
        for d_str, shift in date_shifts.items():
            if shift == "OFF":
                continue
            key = f"{nurse_uid}_{d_str}"
            if key in existing_map:
                if not body.overwrite_confirmed and existing_map[key]:
                    continue  # 已確認且不覆蓋 → 跳過
                to_update.append({"nurse_uid": nurse_uid, "date": d_str, "shift": shift})
            else:
                to_insert.append({
                    "code": key, "label": shift,
                    "nurse_uid": nurse_uid, "date": d_str,
                    "shift": shift, "confirmed": False,
                    "updated_by": operator_uid,
                })
                generated_keys.append(key)

    if to_insert:
        supabase.table("shifts").insert(to_insert).execute()
    for row in to_update:
        supabase.table("shifts").update({
            "shift": row["shift"], "confirmed": False,
            "updated_by": operator_uid,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("nurse_uid", row["nurse_uid"]).eq("date", row["date"]).execute()

    # 儲存生成鍵（供 Excel 匯出區分人工／系統）
    rules_res2 = supabase.table("rules").select("id", "data").limit(1).execute()
    if rules_res2.data:
        cur_data = rules_res2.data[0].get("data") or {}
        cur_data["last_generated_keys"] = generated_keys
        cur_data["last_generated_at"] = datetime.utcnow().isoformat()
        # 備份匯入前的預假狀態（供「回復到預假狀態」使用）
        backup_rows = [
            {"nurse_uid": r["nurse_uid"], "date": r["date"],
             "shift": r.get("shift") or "OFF", "confirmed": r.get("confirmed", False)}
            for r in (existing_res.data or [])
        ]
        cur_data["schedule_backup"] = {
            "rows": backup_rows,
            "start_date": start_str,
            "end_date": end_str,
            "backed_up_at": datetime.utcnow().isoformat(),
        }
        supabase.table("rules").update({"data": cur_data}).eq("id", rules_res2.data[0]["id"]).execute()

    total = len(to_insert) + len(to_update)
    return {
        "message": f"✓ 已匯入 {total} 格（新增 {len(to_insert)}、更新 {len(to_update)}）",
        "inserted": len(to_insert), "updated": len(to_update),
    }


def _make_border(thick=False):
    s = Side(style="medium" if thick else "thin", color="000000")
    return Border(left=s, right=s, top=s, bottom=s)

def _build_excel(title: str, rows: list[dict], bold_keys: set[str], rest_codes: set[str]) -> io.BytesIO:
    """
    共用 Excel 建構函式。
    rows: [{name, uid, date, shift}]
    bold_keys: nurse_uid_date 組合 → 外框加粗（人工填寫）
    rest_codes: 需轉顯示為「休假」的班別代碼集合（應休類）
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = title

    headers = ["姓名", "帳號", "日期", "班別"]
    for ci, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=ci, value=h)
        cell.font = Font(bold=True, size=11)
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = _make_border(thick=False)
        cell.fill = PatternFill("solid", fgColor="D9EAF7")

    for ri, row in enumerate(rows, 2):
        key = f"{row['uid']}_{row['date']}"
        is_manual = key in bold_keys
        display_shift = "休假" if row["shift"] in rest_codes else row["shift"]
        vals = [row["name"], row["uid"], row["date"], display_shift]
        for ci, v in enumerate(vals, 1):
            cell = ws.cell(row=ri, column=ci, value=v)
            cell.alignment = Alignment(horizontal="center", vertical="center")
            cell.border = _make_border(thick=is_manual)
            if is_manual:
                cell.font = Font(bold=False)

    # 欄寬
    for ci, w in enumerate([14, 14, 14, 10], 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(ci)].width = w

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


@app.get("/export/preview")
def export_preview(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """匯出預假狀態：目前所有護理師已填寫的班別（不分系統/人工）"""
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    rules = rules_res.data[0].get("data") or {} if rules_res.data else {}
    cycle = rules.get("cycle", {})
    start_str, end_str = cycle.get("start_date"), cycle.get("end_date")
    if not start_str or not end_str:
        raise HTTPException(400, "請先設定排班週期")
    shift_defs = rules.get("shifts", {})
    rest_codes = {s["code"] for s in shift_defs.get("rest", []) if s.get("code")} or {"OFF", "半"}

    users_res = supabase.table("users").select("uid, name").in_("role", ["nurse", "dual"]).order("sort_order").execute()
    uid_name = {u["uid"]: u["name"] for u in (users_res.data or [])}

    shifts_res = supabase.table("shifts").select("nurse_uid, date, shift") \
        .gte("date", start_str).lte("date", end_str).order("date").execute()

    rows = []
    for r in (shifts_res.data or []):
        if not r.get("shift") or r["shift"] == "OFF":
            continue
        rows.append({"name": uid_name.get(r["nurse_uid"], r["nurse_uid"]),
                     "uid": r["nurse_uid"], "date": r["date"], "shift": r["shift"]})

    buf = _build_excel("預假狀態", rows, bold_keys=set(), rest_codes=rest_codes - {"OFF"})
    filename = f"預假狀態_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}"},
    )


@app.get("/export/schedule")
def export_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """匯出完整班表：生成前人工填寫的格子外框加粗；半職轉顯示為休假"""
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    rules = rules_res.data[0].get("data") or {} if rules_res.data else {}
    cycle = rules.get("cycle", {})
    start_str, end_str = cycle.get("start_date"), cycle.get("end_date")
    if not start_str or not end_str:
        raise HTTPException(400, "請先設定排班週期")
    shift_defs = rules.get("shifts", {})
    rest_codes = {s["code"] for s in shift_defs.get("rest", []) if s.get("code")} or {"OFF", "半"}
    # 人工填寫的格子 = 不在 last_generated_keys 裡的格子
    generated_keys = set(rules.get("last_generated_keys", []))

    users_res = supabase.table("users").select("uid, name").in_("role", ["nurse", "dual"]).order("sort_order").execute()
    uid_name = {u["uid"]: u["name"] for u in (users_res.data or [])}

    shifts_res = supabase.table("shifts").select("nurse_uid, date, shift") \
        .gte("date", start_str).lte("date", end_str).order("date").execute()

    rows = []
    manual_keys = set()
    for r in (shifts_res.data or []):
        shift = r.get("shift") or "OFF"
        if shift == "OFF":
            continue
        key = f"{r['nurse_uid']}_{r['date']}"
        if key not in generated_keys:
            manual_keys.add(key)
        rows.append({"name": uid_name.get(r["nurse_uid"], r["nurse_uid"]),
                     "uid": r["nurse_uid"], "date": r["date"], "shift": shift})

    buf = _build_excel("完整班表", rows, bold_keys=manual_keys, rest_codes=rest_codes - {"OFF"})
    filename = f"完整班表_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}"},
    )


class ExportTempBody(BaseModel):
    schedules: dict[str, dict[str, str]]   # {nurse_uid: {date: shift}}
    cycle_dates: list[str]


@app.post("/export/temp")
def export_temp(
    body: ExportTempBody,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """匯出暫時班表（CP-SAT 計算完成但尚未寫入 DB 的結果）"""
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    rules = rules_res.data[0].get("data") or {} if rules_res.data else {}
    cycle = rules.get("cycle", {})
    start_str = body.cycle_dates[0] if body.cycle_dates else cycle.get("start_date")
    end_str   = body.cycle_dates[-1] if body.cycle_dates else cycle.get("end_date")
    if not start_str or not end_str:
        raise HTTPException(400, "無排班日期")

    shift_defs = rules.get("shifts", {})
    rest_codes = {s["code"] for s in shift_defs.get("rest", []) if s.get("code")} or {"OFF", "半"}

    users_res = supabase.table("users").select("uid, name, halftime").in_("role", ["nurse", "dual"]).order("sort_order").execute()
    uid_name   = {u["uid"]: u["name"] for u in (users_res.data or [])}
    uid_halftime = {u["uid"]: u.get("halftime", False) for u in (users_res.data or [])}

    # 現有 DB 中的班別 → 為「人工填寫」（外框加粗）
    existing_res = supabase.table("shifts").select("nurse_uid, date, shift, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    manual_keys = {f"{r['nurse_uid']}_{r['date']}" for r in (existing_res.data or [])}

    rows = []
    for uid, date_shifts in body.schedules.items():
        for d_str in body.cycle_dates:
            shift = date_shifts.get(d_str, "OFF")
            if not shift or shift == "OFF":
                continue
            # 半職護理師的應休班顯示為「休假」
            display = "休假" if (uid_halftime.get(uid) and shift in rest_codes) else shift
            rows.append({"name": uid_name.get(uid, uid), "uid": uid, "date": d_str, "shift": display})

    # 排序：依 sort_order 的 uid 順序，再依日期
    uid_order = {u["uid"]: i for i, u in enumerate(users_res.data or [])}
    rows.sort(key=lambda r: (uid_order.get(r["uid"], 999), r["date"]))

    buf = _build_excel("暫時班表", rows, bold_keys=manual_keys, rest_codes=rest_codes - {"OFF"})
    filename = f"暫時班表_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}"},
    )


@app.post("/schedule/revert")
def revert_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """回復到預假狀態：刪除 CP-SAT 生成的班別，恢復匯入前的備份"""
    operator_uid = current_user.get("sub")

    rules_res = supabase.table("rules").select("id", "data").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "找不到規則資料")
    cur_data = rules_res.data[0].get("data") or {}
    rules_id = rules_res.data[0]["id"]

    backup = cur_data.get("schedule_backup")
    if not backup:
        raise HTTPException(400, "找不到備份資料，請先執行「匯入到班表」才能回復")

    start_str = backup["start_date"]
    end_str   = backup["end_date"]
    backup_rows: list[dict] = backup.get("rows", [])

    # 刪除該週期所有現有班別
    supabase.table("shifts").delete().gte("date", start_str).lte("date", end_str).execute()

    # 還原備份（排除 OFF，只插入有實際班別的資料）
    restore_rows = [
        {
            "code": f"{r['nurse_uid']}_{r['date']}",
            "label": r["shift"],
            "nurse_uid": r["nurse_uid"],
            "date": r["date"],
            "shift": r["shift"],
            "confirmed": r.get("confirmed", False),
            "updated_by": operator_uid,
        }
        for r in backup_rows
        if r.get("shift") and r["shift"] != "OFF"
    ]
    if restore_rows:
        supabase.table("shifts").insert(restore_rows).execute()

    # 清除備份與生成鍵，避免重複回復
    cur_data.pop("schedule_backup", None)
    cur_data.pop("last_generated_keys", None)
    cur_data.pop("last_generated_at", None)
    supabase.table("rules").update({"data": cur_data}).eq("id", rules_id).execute()

    return {
        "message": f"✓ 已回復到預假狀態（還原 {len(restore_rows)} 格）",
        "restored": len(restore_rows),
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
    before_hours: Optional[int] = None,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    if before_hours is None:
        supabase.table("shift_logs").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        return {"message": "已清除所有操作紀錄"}
    cutoff = (datetime.utcnow() - timedelta(hours=before_hours)).isoformat()
    supabase.table("shift_logs").delete().lt("created_at", cutoff).execute()
    return {"message": f"已清除 {before_hours} 小時前的操作紀錄"}
