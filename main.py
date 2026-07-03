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
from ortools.sat.python import cp_model

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
    one_in_seven = bool(scheduling.get("one_in_seven", False))  # 一例一休
    lock_designated_off = bool(scheduling.get("lock_designated_off", False))
    weekly_max_off_auto  = int(scheduling.get("weekly_max_off_auto", 2))   # 自動休每週上限
    weekly_max_off_total = int(scheduling.get("weekly_max_off_total", 3))  # 含指定休每週上限
    holiday_days = int(cycle.get("holiday_days", 0))
    full_off  = min(8 + holiday_days, 13)
    part_off  = min(16 + holiday_days, 21)

    # 班別視同 D 的特殊班（不計臨床人力，但算上班日）
    ADMIN_SHIFTS = {"會", "公", "書記"}
    # 特休 / 員旅 → 最高順位不被覆蓋
    PRIORITY_OFF = {"V", "員"}

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

    # ── CP-SAT 模型
    model = cp_model.CpModel()

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

        # ── 鎖定已確認班 / 特休 / 指定休
        locked_off_days_m: set[int] = set()  # 記錄指定 OFF 的天索引（不含特休/員旅）
        for t, d_str in enumerate(cycle_dates):
            key = (uid, d_str)
            if key not in existing:
                continue
            row = existing[key]
            shift = row.get("shift") or "OFF"
            confirmed = row.get("confirmed", False)

            # 半職視同 OFF
            if shift == "半":
                shift = "OFF"

            # 行政班視同 D（不計臨床人力，但視同上班）
            if shift in ADMIN_SHIFTS:
                shift = "D"

            if shift in PRIORITY_OFF:
                # 特休/員旅：最高順位，一定保留，不占指定休/自動休名額
                model.add(x[m][t] == 3)
                continue

            if confirmed and not overwrite_confirmed:
                si = SI.get(shift, 3)
                model.add(x[m][t] == si)
                if si == 3:
                    locked_off_days_m.add(t)  # 已確認的 OFF = 指定休
                continue

            if lock_designated_off and shift == "OFF":
                model.add(x[m][t] == 3)
                locked_off_days_m.add(t)

        # ── 允許班種限制（依輪班屬性）
        allowed = SHIFT_ALLOWED.get(attr, WORK_SHIFTS)
        allowed_si = set(SI[s] for s in allowed) | {3}  # OFF 永遠允許
        for t in range(n):
            for s in range(4):
                if s not in allowed_si:
                    model.add(b[m][t][s] == 0)

        # ── 休假天數
        off_days = part_off if is_ht else full_off
        off_days = min(off_days, n - 1)
        work_days = n - off_days
        d_cnt, e_cnt, nv_cnt = shift_counts(attr, work_days, uid)

        # 軟約束：目標班次數（允許偏差 ±2）
        total_d = sum(b[m][t][0] for t in range(n))
        total_e = sum(b[m][t][1] for t in range(n))
        total_nv = sum(b[m][t][2] for t in range(n))
        total_off = sum(b[m][t][3] for t in range(n))
        model.add(total_off >= off_days - 2)
        model.add(total_off <= off_days + 2)
        model.add(total_d  >= max(0, d_cnt  - 2))
        model.add(total_d  <= d_cnt  + 2)
        model.add(total_e  >= max(0, e_cnt  - 2))
        model.add(total_e  <= e_cnt  + 2)
        model.add(total_nv >= max(0, nv_cnt - 2))
        model.add(total_nv <= nv_cnt + 2)

        # ── 硬規則 2：反向班禁止（含隔天規則）
        # E→D: 禁止（隔1天 OFF 才行 → 兩天後才能 D）
        # N→E: 禁止
        # N→D: 禁止（且隔1天 OFF 後也不行，需隔2天）
        if no_reverse:
            for t in range(n - 1):
                # E 後不能直接 D
                model.add(b[m][t+1][0] == 0).only_enforce_if(b[m][t][1])
                # N 後不能直接 D 或 E
                model.add(b[m][t+1][0] == 0).only_enforce_if(b[m][t][2])
                model.add(b[m][t+1][1] == 0).only_enforce_if(b[m][t][2])
            for t in range(n - 2):
                # N 後隔一天（無論 OFF 或其他）仍不能排 D
                model.add(b[m][t+2][0] == 0).only_enforce_if(b[m][t][2])

        # ── 硬規則 3：每週至少一天休假（固定啟用）
        for ws, we in weeks:
            model.add(sum(b[m][t][3] for t in range(ws, we+1)) >= 1)

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

        # ── 連班上限
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

        # ── 規則 6/7：每週 OFF 天數上限
        for ws, we in weeks:
            # 規則 7：含指定休每週最多 weekly_max_off_total 天（預設 3）
            model.add(sum(b[m][t][3] for t in range(ws, we+1)) <= weekly_max_off_total)
            # 規則 6：自動休（排除已鎖定的指定休）每週最多 weekly_max_off_auto 天（預設 2）
            auto_off_in_week = [b[m][t][3] for t in range(ws, we+1) if t not in locked_off_days_m]
            if auto_off_in_week:
                model.add(sum(auto_off_in_week) <= weekly_max_off_auto)

    # ── 硬規則 1：每班每日至少 1 leader + 1 (leader or second)，不同人
    leaders = [i for i, n in enumerate(nurses) if n.get("level") == "leader"]
    seconds = [i for i, n in enumerate(nurses) if n.get("level") in ("leader", "second")]

    for t in range(n):
        for si, req in [(0, daily_d), (1, daily_e), (2, daily_n)]:
            if req == 0:
                continue
            # 至少 req 人上班
            model.add(sum(b[m][t][si] for m in range(M)) >= req)
            # 至少 1 leader
            if leaders:
                model.add(sum(b[m][t][si] for m in leaders) >= 1)
            # 至少 2 人達 leader/second 層級（若有足夠人員）
            if len(seconds) >= 2:
                model.add(sum(b[m][t][si] for m in seconds) >= 2)

    # ── 軟規則：順班目標（同種班連續排列）
    # 懲罰班別切換（相鄰兩天不同班種）
    penalties = []
    for m in range(M):
        attr = nurses[m].get("attr") or "輪班DEN"
        allowed = SHIFT_ALLOWED.get(attr, WORK_SHIFTS)
        if len(allowed) <= 1:
            continue  # 固定班不需要順班懲罰
        for t in range(n - 1):
            for s1 in range(3):
                for s2 in range(3):
                    if s1 != s2 and WORK_SHIFTS[s1] in allowed and WORK_SHIFTS[s2] in allowed:
                        switch = model.new_bool_var(f"sw_{m}_{t}_{s1}_{s2}")
                        # switch=1 iff (day t = s1 AND day t+1 = s2)
                        # 透過 >= 讓 minimize 自動把 switch 壓到 0（即避免切換）
                        model.add(switch >= b[m][t][s1] + b[m][t+1][s2] - 1)
                        penalties.append(switch)

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
                if orig in PRIORITY_OFF:
                    sched[t] = orig
                elif orig in ADMIN_SHIFTS:
                    sched[t] = orig  # 行政班保留原班碼
                elif orig == "半":
                    sched[t] = "半"
        schedules[nurse["uid"]] = sched

    # ── 寫入資料庫
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
                continue  # OFF 不寫入，留空
            if key in existing_map:
                if not overwrite_confirmed and existing_map[key]:
                    continue
                to_update.append({"nurse_uid": nurse_uid, "date": d_str, "shift": shift})
            else:
                to_insert.append({
                    "code":       key,
                    "label":      shift,
                    "nurse_uid":  nurse_uid,
                    "date":       d_str,
                    "shift":      shift,
                    "confirmed":  False,
                    "updated_by": operator_uid,
                })

    if to_insert:
        supabase.table("shifts").insert(to_insert).execute()
    for row in to_update:
        supabase.table("shifts").update({
            "shift": row["shift"], "confirmed": False, "updated_by": operator_uid,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("nurse_uid", row["nurse_uid"]).eq("date", row["date"]).execute()

    total = len(to_insert) + len(to_update)
    return {
        "message": f"✓ 已生成 {len(nurses)} 位護理師的班表（共 {total} 格）",
        "solver_status": solver.status_name(status),
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
