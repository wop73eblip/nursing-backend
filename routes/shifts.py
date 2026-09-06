"""排班表 CRUD + 週期維護 endpoints。

CRUD:
- GET  /schedule
- POST /schedule/shift          單格
- POST /schedule/shifts/batch   批次
- POST /schedule/confirm        確認
- POST /schedule/unconfirm      取消確認

週期維護(操作類):
- POST /schedule/clear-generated  清生成內容
- POST /schedule/clear-cycle      清整週期
- POST /schedule/restore-manual   還原備份
- POST /schedule/restore-generated 還原上次生成
- POST /schedule/purge-old        清半年前
"""
from datetime import datetime, date as date_type, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import get_current_user, require_roles
from db import supabase

router = APIRouter()


# ── Pydantic
class ShiftUpdate(BaseModel):
    nurse_uid: str
    date: str
    shift: Optional[str] = None


class ShiftBatchItem(BaseModel):
    nurse_uid: str
    date: str
    shift: Optional[str] = None


# ── Helper: 備份整週期資料
def _backup_cycle_shifts(cur_data: dict) -> None:
    """把目前預班週期內所有已填寫內容(確認送出+待確認)備份到 rules.data.manual_backup。
    呼叫端負責把 cur_data 寫回 rules 資料表。"""
    cycle = cur_data.get("cycle", {})
    start_str, end_str = cycle.get("start_date"), cycle.get("end_date")
    if not start_str or not end_str:
        return
    rows_res = supabase.table("shifts").select("nurse_uid, date, shift, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    cur_data["manual_backup"] = {
        "rows": [
            {"nurse_uid": r["nurse_uid"], "date": r["date"],
             "shift": r["shift"], "confirmed": r.get("confirmed", False)}
            for r in (rows_res.data or []) if r.get("shift")
        ],
        "start_date": start_str,
        "end_date": end_str,
        "backed_up_at": datetime.utcnow().isoformat(),
    }


# ── CRUD Endpoints
@router.get("/schedule")
def get_schedule(
    year: int,
    month: int,
    current_user: dict = Depends(get_current_user),
):
    start = f"{year}-{month:02d}-01"
    end = f"{year+1}-01-01" if month == 12 else f"{year}-{month+1:02d}-01"
    res = supabase.table("shifts").select("*").gte("date", start).lt("date", end).execute()
    return {"schedule": res.data}


@router.post("/schedule/shift")
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
            "code": f"{update.nurse_uid}_{update.date}",
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
            "changed_by": uid,
            "operator_uid": uid,
            "operator_role": role,
            "action": "edit",
        }).execute()
    except Exception:
        pass

    return {"message": "班別更新成功"}


@router.post("/schedule/shifts/batch")
def batch_update_shifts(
    updates: List[ShiftBatchItem],
    current_user: dict = Depends(get_current_user),
):
    """批次寫入多格班別(一次 API 呼叫取代多次單格呼叫)"""
    if not updates:
        return {"message": "無資料", "updated": 0}

    role = current_user.get("role")
    uid  = current_user.get("sub")

    if role == "nurse":
        if any(u.nurse_uid != uid for u in updates):
            raise HTTPException(status_code=403, detail="只能修改自己的預班")

    pairs = [(u.nurse_uid, u.date) for u in updates]
    existing_keys: set[str] = set()
    nurse_uids = list({p[0] for p in pairs})
    min_date = min(p[1] for p in pairs)
    max_date = max(p[1] for p in pairs)
    res = supabase.table("shifts").select("nurse_uid, date") \
        .in_("nurse_uid", nurse_uids) \
        .gte("date", min_date).lte("date", max_date).execute()
    for r in (res.data or []):
        existing_keys.add(f"{r['nurse_uid']}_{r['date']}")

    to_insert, to_update_clear, to_update_set = [], [], []
    for u in updates:
        key = f"{u.nurse_uid}_{u.date}"
        if key in existing_keys:
            if u.shift:
                to_update_set.append(u)
            else:
                to_update_clear.append(u)
        else:
            if u.shift:
                to_insert.append(u)

    now = datetime.utcnow().isoformat()

    if to_insert:
        supabase.table("shifts").insert([{
            "code": f"{u.nurse_uid}_{u.date}",
            "label": u.shift or "",
            "nurse_uid": u.nurse_uid,
            "date": u.date,
            "shift": u.shift,
            "confirmed": False,
            "updated_by": uid,
        } for u in to_insert]).execute()

    for u in to_update_set:
        supabase.table("shifts").update({
            "shift": u.shift, "confirmed": False,
            "updated_by": uid, "updated_at": now,
        }).eq("nurse_uid", u.nurse_uid).eq("date", u.date).execute()

    for u in to_update_clear:
        supabase.table("shifts").update({
            "shift": None, "confirmed": False,
            "updated_by": uid, "updated_at": now,
        }).eq("nurse_uid", u.nurse_uid).eq("date", u.date).execute()

    try:
        supabase.table("shift_logs").insert([{
            "nurse_uid": u.nurse_uid, "date": u.date, "shift": u.shift,
            "changed_by": uid, "operator_uid": uid,
            "operator_role": role, "action": "edit",
        } for u in updates]).execute()
    except Exception:
        pass

    total = len(to_insert) + len(to_update_set) + len(to_update_clear)
    return {"message": f"批次更新完成", "updated": total}


@router.post("/schedule/confirm")
def confirm_shifts(
    shifts: List[ShiftUpdate],
    current_user: dict = Depends(get_current_user),
):
    uid = current_user.get("sub")
    role = current_user.get("role")

    if not shifts:
        return {"message": "已確認 0 筆班別"}

    if role == "nurse":
        for s in shifts:
            if s.nurse_uid != uid:
                raise HTTPException(status_code=403, detail="只能確認自己的班別")

    now = datetime.utcnow().isoformat()
    shift_rows = [{
        "code": f"{s.nurse_uid}_{s.date}",
        "label": s.shift or "",
        "nurse_uid": s.nurse_uid,
        "date": s.date,
        "shift": s.shift,
        "confirmed": True,
        "updated_by": uid,
        "updated_at": now,
    } for s in shifts]
    supabase.table("shifts").upsert(shift_rows, on_conflict="code").execute()

    try:
        log_rows = [{
            "nurse_uid": s.nurse_uid, "date": s.date, "shift": s.shift,
            "changed_by": uid, "operator_uid": uid,
            "operator_role": role, "action": "confirm",
        } for s in shifts]
        supabase.table("shift_logs").insert(log_rows).execute()
    except Exception:
        pass

    return {"message": f"已確認 {len(shifts)} 筆班別"}


@router.post("/schedule/unconfirm")
def unconfirm_shifts(
    shifts: List[ShiftUpdate],
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    uid = current_user.get("sub")
    role = current_user.get("role")
    if not shifts:
        return {"message": "已取消確認 0 筆"}

    now = datetime.utcnow().isoformat()
    shift_rows = [{
        "code": f"{s.nurse_uid}_{s.date}",
        "label": s.shift or "",
        "nurse_uid": s.nurse_uid,
        "date": s.date,
        "shift": s.shift,
        "confirmed": False,
        "updated_by": uid,
        "updated_at": now,
    } for s in shifts]
    supabase.table("shifts").upsert(shift_rows, on_conflict="code").execute()

    try:
        log_rows = [{
            "nurse_uid": s.nurse_uid, "date": s.date, "shift": s.shift,
            "changed_by": uid, "operator_uid": uid,
            "operator_role": role, "action": "unconfirm",
        } for s in shifts]
        supabase.table("shift_logs").insert(log_rows).execute()
    except Exception:
        pass
    return {"message": f"已取消確認 {len(shifts)} 筆"}


# ── 週期維護 Endpoints
@router.post("/schedule/clear-generated")
def clear_generated_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """操作1:清除所有 CP-SAT 生成內容,只留下人員填寫的內容"""
    rules_res = supabase.table("rules").select("id", "data").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "找不到規則資料")
    cur_data = rules_res.data[0].get("data") or {}
    rules_id = rules_res.data[0]["id"]

    keys: list[str] = cur_data.get("last_generated_keys", [])
    rng = cur_data.get("last_generated_range")
    if not keys or not rng:
        return {"message": "✓ 無需清除(沒有 CP-SAT 生成紀錄)", "deleted": 0}

    _backup_cycle_shifts(cur_data)

    key_set = set(keys)
    rows_res = supabase.table("shifts").select("id, nurse_uid, date") \
        .gte("date", rng["start_date"]).lte("date", rng["end_date"]).execute()
    ids_to_delete = [
        r["id"] for r in (rows_res.data or [])
        if f"{r['nurse_uid']}_{r['date']}" in key_set
    ]
    if ids_to_delete:
        supabase.table("shifts").delete().in_("id", ids_to_delete).execute()

    cur_data["last_generated_keys"] = []
    supabase.table("rules").update({"data": cur_data}).eq("id", rules_id).execute()

    return {"message": f"✓ 已清除 CP-SAT 生成內容({len(ids_to_delete)} 格)", "deleted": len(ids_to_delete)}


@router.post("/schedule/clear-cycle")
def clear_cycle_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """操作:清除預班週期內所有填寫內容(執行前自動備份,可用「恢復確認送出及待確認內容」還原)"""
    rules_res = supabase.table("rules").select("id", "data").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "找不到規則資料")
    cur_data = rules_res.data[0].get("data") or {}
    rules_id = rules_res.data[0]["id"]

    cycle = cur_data.get("cycle", {})
    start_str, end_str = cycle.get("start_date"), cycle.get("end_date")
    if not start_str or not end_str:
        raise HTTPException(400, "請先設定排班週期")

    _backup_cycle_shifts(cur_data)

    rows_res = supabase.table("shifts").select("id") \
        .gte("date", start_str).lte("date", end_str).execute()
    ids = [r["id"] for r in (rows_res.data or [])]
    if ids:
        supabase.table("shifts").delete().in_("id", ids).execute()

    cur_data["last_generated_keys"] = []
    supabase.table("rules").update({"data": cur_data}).eq("id", rules_id).execute()

    return {"message": f"✓ 已清除預班週期內所有填寫內容({len(ids)} 格),可用「恢復確認送出及待確認內容」還原", "deleted": len(ids)}


@router.post("/schedule/restore-manual")
def restore_manual_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """操作:恢復預班週期內確認送出及待確認的內容(還原最近一次自動備份)"""
    operator_uid = current_user.get("sub")

    rules_res = supabase.table("rules").select("id", "data").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "找不到規則資料")
    cur_data = rules_res.data[0].get("data") or {}

    backup = cur_data.get("manual_backup")
    if not backup or not backup.get("rows"):
        raise HTTPException(400, "找不到備份資料(執行清除/還原操作時才會自動建立備份)")

    start_str, end_str = backup["start_date"], backup["end_date"]

    rows_res = supabase.table("shifts").select("id") \
        .gte("date", start_str).lte("date", end_str).execute()
    ids = [r["id"] for r in (rows_res.data or [])]
    if ids:
        supabase.table("shifts").delete().in_("id", ids).execute()

    restore_rows = [
        {
            "code": f"{r['nurse_uid']}_{r['date']}", "label": r["shift"],
            "nurse_uid": r["nurse_uid"], "date": r["date"], "shift": r["shift"],
            "confirmed": r.get("confirmed", False), "updated_by": operator_uid,
        }
        for r in backup["rows"]
    ]
    if restore_rows:
        supabase.table("shifts").insert(restore_rows).execute()

    backed_at = (backup.get("backed_up_at") or "")[:19].replace("T", " ")
    return {
        "message": f"✓ 已恢復確認送出及待確認的內容({len(restore_rows)} 格,備份時間 {backed_at} UTC)",
        "restored": len(restore_rows),
    }


@router.post("/schedule/restore-generated")
def restore_generated_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """操作2:恢復到上次 CP-SAT 生成的內容"""
    operator_uid = current_user.get("sub")

    rules_res = supabase.table("rules").select("id", "data").limit(1).execute()
    if not rules_res.data:
        raise HTTPException(400, "找不到規則資料")
    cur_data = rules_res.data[0].get("data") or {}
    rules_id = rules_res.data[0]["id"]

    full: dict = cur_data.get("last_generated_full")
    rng = cur_data.get("last_generated_range")
    if not full or not rng:
        raise HTTPException(400, "找不到上次 CP-SAT 生成的完整記錄")

    start_str, end_str = rng["start_date"], rng["end_date"]

    _backup_cycle_shifts(cur_data)
    supabase.table("rules").update({"data": cur_data}).eq("id", rules_id).execute()

    supabase.table("shifts").delete().gte("date", start_str).lte("date", end_str).execute()

    restore_rows = [
        {
            "code": f"{uid}_{d_str}", "label": shift,
            "nurse_uid": uid, "date": d_str, "shift": shift,
            "confirmed": False, "updated_by": operator_uid,
        }
        for uid, date_shifts in full.items()
        for d_str, shift in date_shifts.items()
        if shift
    ]
    if restore_rows:
        supabase.table("shifts").insert(restore_rows).execute()

    return {
        "message": f"✓ 已恢復到上次 CP-SAT 生成的內容({len(restore_rows)} 格)",
        "restored": len(restore_rows),
    }


@router.post("/schedule/purge-old")
def purge_old_schedule(
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    """操作3:清除半年之外所有班表(不可復原)"""
    cutoff = (date_type.today() - timedelta(days=182)).isoformat()
    res = supabase.table("shifts").select("id").lt("date", cutoff).execute()
    ids = [r["id"] for r in (res.data or [])]
    if ids:
        supabase.table("shifts").delete().in_("id", ids).execute()
    return {"message": f"✓ 已清除 {cutoff} 之前的班表({len(ids)} 格)", "deleted": len(ids), "cutoff": cutoff}
