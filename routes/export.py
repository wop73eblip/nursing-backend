"""匯出 Excel:預假狀態、完整班表、暫時班表。"""
import io
from datetime import date as date_type, timedelta
from urllib.parse import quote

import openpyxl
from openpyxl.styles import Font, Border, Side, Alignment, PatternFill
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth import require_roles
from db import supabase

router = APIRouter()


def _date_range(start_str: str, end_str: str) -> list[str]:
    s = date_type.fromisoformat(start_str)
    e = date_type.fromisoformat(end_str)
    return [(s + timedelta(days=i)).isoformat() for i in range((e - s).days + 1)]


def _make_border(thick=False):
    s = Side(style="medium" if thick else "thin", color="000000")
    return Border(left=s, right=s, top=s, bottom=s)


def _compute_demand(rules: dict, cycle_dates: list[str]) -> tuple[dict[str, tuple[int, int, int]], set[str]]:
    """回傳 {date: (需求D, 需求E, 需求N)} 與特殊日期覆蓋的日期集合。"""
    scheduling = rules.get("scheduling", {})
    daily_d = int(scheduling.get("daily_d", 3))
    daily_e = int(scheduling.get("daily_e", 3))
    daily_n = int(scheduling.get("daily_n", 3))
    special_raw = scheduling.get("special_dates", []) or []
    special_map = {
        sd["date"]: (int(sd.get("d", daily_d)), int(sd.get("e", daily_e)), int(sd.get("n", daily_n)))
        for sd in special_raw if sd.get("date")
    }
    demand = {d: special_map.get(d, (daily_d, daily_e, daily_n)) for d in cycle_dates}
    special_cols = {d for d in cycle_dates if d in special_map}
    return demand, special_cols


def _build_matrix_excel(
    title: str,
    cycle_dates: list[str],
    nurse_rows: list[dict],       # [{uid, name, shifts: {date: display_shift}}] 依顯示順序
    manual_keys: set[str],        # f"{uid}_{date}" → 人工預填（淡黃底）
    rest_codes: set[str] | None = None,          # 計入應休天數的班別（OFF、半）
    demand: dict[str, tuple[int, int, int]] | None = None,  # date → (需求D, 需求E, 需求N)
    special_date_cols: set[str] | None = None,   # 特殊日期覆蓋 → 表頭標黃
) -> io.BytesIO:
    """矩陣式班表：列=護理師、欄=日期；OFF 紅字；人工預填淡黃底；底部 D/E/N 每日統計；
    右側 OFF 天數合計；人數不足當日統計標黃；特殊日期表頭標黃。"""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = title

    rest_codes = rest_codes or {"OFF", "半"}
    special_date_cols = special_date_cols or set()

    thin = _make_border(False)
    center = Alignment(horizontal="center", vertical="center")
    fill_header   = PatternFill("solid", fgColor="D9EAF7")
    fill_weekend  = PatternFill("solid", fgColor="EDEDED")
    fill_manual   = PatternFill("solid", fgColor="FFF9DB")   # 很淡的黃：人工預填
    fill_special  = PatternFill("solid", fgColor="FFF176")   # 特殊日期表頭：黃
    fill_short    = PatternFill("solid", fgColor="FFF176")   # 人數不足：黃
    red_font  = Font(color="FF0000", size=10)
    bold_font = Font(bold=True, size=10)
    norm_font = Font(size=10)

    ND = len(cycle_dates)
    date_objs = [date_type.fromisoformat(d) for d in cycle_dates]
    weekend_cols = {ci for ci, d in enumerate(date_objs, 2) if d.weekday() >= 5}
    special_cols = {ci for ci, d in enumerate(cycle_dates, 2) if d in special_date_cols}

    # 週切分（週一~週日，夾到週期內），用於每週 OFF 天數
    weekdays = [d.weekday() for d in date_objs]
    weeks: list[tuple[int, int]] = []
    _i = 0
    while _i < ND:
        wstart = _i - weekdays[_i]
        wend = wstart + 6
        weeks.append((max(0, wstart), min(ND - 1, wend)))
        _i = wend + 1
    NW = len(weeks)

    # 右側統計欄位位置
    d_col = 2 + ND
    e_col = 3 + ND
    n_col = 4 + ND
    week_cols = [5 + ND + w for w in range(NW)]   # 每週 OFF 欄
    last_col = 4 + ND + NW

    # 資深護理師（leader / second）
    senior_uids = {nr["uid"] for nr in nurse_rows if nr.get("level") in ("leader", "second")}

    # Row1：日期（數字）、Row2：星期
    dow_zh = ["一", "二", "三", "四", "五", "六", "日"]
    ws.cell(row=1, column=1, value="姓名").font = bold_font
    ws.cell(row=1, column=1).fill = fill_header
    ws.cell(row=1, column=1).border = thin
    ws.cell(row=1, column=1).alignment = center
    ws.cell(row=2, column=1, value="").border = thin
    for ci, d in enumerate(date_objs, 2):
        c1 = ws.cell(row=1, column=ci, value=d.day)
        c2 = ws.cell(row=2, column=ci, value=dow_zh[d.weekday()])
        for c in (c1, c2):
            c.font = bold_font
            c.alignment = center
            c.border = thin
            c.fill = fill_special if ci in special_cols else (fill_weekend if ci in weekend_cols else fill_header)
    # 右側統計欄表頭
    stat_headers = [(d_col, "D"), (e_col, "E"), (n_col, "N")]
    for w in range(NW):
        stat_headers.append((week_cols[w], f"{w+1}週OFF"))
    for col, label in stat_headers:
        h = ws.cell(row=1, column=col, value=label)
        ws.cell(row=2, column=col, value="")
        for rr in (1, 2):
            c = ws.cell(row=rr, column=col)
            c.font = bold_font; c.alignment = center; c.border = thin; c.fill = fill_header

    # 護理師列
    ri = 3
    for nr in nurse_rows:
        name_cell = ws.cell(row=ri, column=1, value=nr["name"])
        name_cell.font = norm_font
        name_cell.alignment = center
        name_cell.border = thin
        dcnt = ecnt = ncnt = 0
        for ci, d_str in enumerate(cycle_dates, 2):
            shift = nr["shifts"].get(d_str, "")
            if shift == "D": dcnt += 1
            elif shift == "E": ecnt += 1
            elif shift == "N": ncnt += 1
            cell = ws.cell(row=ri, column=ci, value=shift)
            cell.alignment = center
            cell.border = thin
            cell.font = red_font if shift == "OFF" else norm_font
            if f"{nr['uid']}_{d_str}" in manual_keys and shift:
                cell.fill = fill_manual
            elif ci in special_cols:
                cell.fill = fill_special
            elif ci in weekend_cols:
                cell.fill = fill_weekend
        # 右側：D/E/N 天數
        for col, val in ((d_col, dcnt), (e_col, ecnt), (n_col, ncnt)):
            c = ws.cell(row=ri, column=col, value=val)
            c.alignment = center; c.border = thin; c.font = bold_font
        # 右側：每週 OFF 天數
        for w, (a, b) in enumerate(weeks):
            woff = sum(1 for k in range(a, b + 1) if nr["shifts"].get(cycle_dates[k]) in rest_codes)
            c = ws.cell(row=ri, column=week_cols[w], value=woff)
            c.alignment = center; c.border = thin; c.font = bold_font
        ri += 1

    # ── 底部區塊①：各班 leader+second 人數（每日）
    ri += 1
    for sname in ("D", "E", "N"):
        label = ws.cell(row=ri, column=1, value=f"{sname} 資深")
        label.font = bold_font; label.alignment = center; label.border = thin; label.fill = fill_header
        for ci, d_str in enumerate(cycle_dates, 2):
            # 新人和行政人員不計入資深臨床帶班統計
            cnt = sum(1 for nr in nurse_rows
                      if nr["uid"] in senior_uids
                      and not nr.get("is_trainee") and not nr.get("admin_staff")
                      and nr["shifts"].get(d_str) == sname)
            c = ws.cell(row=ri, column=ci, value=cnt)
            c.alignment = center; c.border = thin; c.font = norm_font
            if ci in weekend_cols: c.fill = fill_weekend
        ri += 1

    # ── 底部區塊②：各班總人數（每日，人數不足標黃；新人和行政人員不計入）
    for si, sname in enumerate(("D", "E", "N")):
        label = ws.cell(row=ri, column=1, value=f"{sname} 總數")
        label.font = bold_font; label.alignment = center; label.border = thin
        for ci, d_str in enumerate(cycle_dates, 2):
            cnt = sum(1 for nr in nurse_rows
                      if not nr.get("is_trainee") and not nr.get("admin_staff")
                      and nr["shifts"].get(d_str) == sname)
            cell = ws.cell(row=ri, column=ci, value=cnt)
            cell.alignment = center; cell.border = thin; cell.font = norm_font
            req = demand.get(d_str, (0, 0, 0))[si] if demand else None
            if req is not None and cnt < req:
                cell.fill = fill_short
            elif ci in weekend_cols:
                cell.fill = fill_weekend
        ri += 1

    # 欄寬
    ws.column_dimensions["A"].width = 12
    for ci in range(2, 2 + ND):
        ws.column_dimensions[openpyxl.utils.get_column_letter(ci)].width = 5.5
    for col in (d_col, e_col, n_col):
        ws.column_dimensions[openpyxl.utils.get_column_letter(col)].width = 6
    for col in week_cols:
        ws.column_dimensions[openpyxl.utils.get_column_letter(col)].width = 8
    ws.freeze_panes = "B3"

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


@router.get("/export/preview")
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

    users_res = supabase.table("users").select("uid, name, level").in_("role", ["nurse", "dual"]).order("sort_order").execute()

    shifts_res = supabase.table("shifts").select("nurse_uid, date, shift") \
        .gte("date", start_str).lte("date", end_str).order("date").execute()

    cycle_dates = _date_range(start_str, end_str)
    shift_map: dict[str, dict[str, str]] = {}
    manual_keys: set[str] = set()
    for r in (shifts_res.data or []):
        if not r.get("shift"):
            continue
        shift_map.setdefault(r["nurse_uid"], {})[r["date"]] = r["shift"]
        manual_keys.add(f"{r['nurse_uid']}_{r['date']}")  # 預假匯出：全部都是人工填寫
    nurse_rows = [
        {"uid": u["uid"], "name": u["name"], "level": u.get("level"), "shifts": shift_map.get(u["uid"], {})}
        for u in (users_res.data or [])
    ]

    demand, special_cols = _compute_demand(rules, cycle_dates)
    buf = _build_matrix_excel("預假狀態", cycle_dates, nurse_rows, manual_keys,
                              rest_codes=rest_codes, demand=demand, special_date_cols=special_cols)
    filename = f"預假狀態_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )


@router.get("/export/schedule")
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

    users_res = supabase.table("users").select("uid, name, level").in_("role", ["nurse", "dual"]).order("sort_order").execute()

    shifts_res = supabase.table("shifts").select("nurse_uid, date, shift") \
        .gte("date", start_str).lte("date", end_str).order("date").execute()

    cycle_dates = _date_range(start_str, end_str)
    shift_map: dict[str, dict[str, str]] = {}
    manual_keys: set[str] = set()
    for r in (shifts_res.data or []):
        if not r.get("shift"):
            continue
        key = f"{r['nurse_uid']}_{r['date']}"
        if key not in generated_keys:
            manual_keys.add(key)  # 人工預填（非系統生成）→ 淡黃底
        shift_map.setdefault(r["nurse_uid"], {})[r["date"]] = r["shift"]
    nurse_rows = [
        {"uid": u["uid"], "name": u["name"], "level": u.get("level"), "shifts": shift_map.get(u["uid"], {})}
        for u in (users_res.data or [])
    ]

    demand, special_cols = _compute_demand(rules, cycle_dates)
    buf = _build_matrix_excel("完整班表", cycle_dates, nurse_rows, manual_keys,
                              rest_codes=rest_codes, demand=demand, special_date_cols=special_cols)
    filename = f"完整班表_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )


class ExportTempBody(BaseModel):
    schedules: dict[str, dict[str, str]]   # {nurse_uid: {date: shift}}
    cycle_dates: list[str]


@router.post("/export/temp")
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

    users_res = supabase.table("users").select("uid, name, halftime, level, is_trainee, admin_staff").in_("role", ["nurse", "dual"]).order("sort_order").execute()
    uid_name   = {u["uid"]: u["name"] for u in (users_res.data or [])}
    uid_halftime = {u["uid"]: u.get("halftime", False) for u in (users_res.data or [])}

    # 現有 DB 中的班別（人工預填）→ 淡黃底
    existing_res = supabase.table("shifts").select("nurse_uid, date, shift, confirmed") \
        .gte("date", start_str).lte("date", end_str).execute()
    manual_keys = {
        f"{r['nurse_uid']}_{r['date']}"
        for r in (existing_res.data or []) if r.get("shift")
    }

    shift_map: dict[str, dict[str, str]] = {}
    for uid, date_shifts in body.schedules.items():
        for d_str in body.cycle_dates:
            shift = date_shifts.get(d_str, "")
            if not shift:
                continue
            # 半職護理師的應休班（含「半」）統一顯示為 OFF
            display = "OFF" if (uid_halftime.get(uid) and shift in rest_codes) else shift
            shift_map.setdefault(uid, {})[d_str] = display

    nurse_rows = [
        {
            "uid": u["uid"], "name": u["name"], "level": u.get("level"),
            "is_trainee": u.get("is_trainee", False),
            "admin_staff": u.get("admin_staff", False),
            "shifts": shift_map.get(u["uid"], {}),
        }
        for u in (users_res.data or [])
    ]

    demand, special_cols = _compute_demand(rules, body.cycle_dates)
    buf = _build_matrix_excel("暫時班表", body.cycle_dates, nurse_rows, manual_keys,
                              rest_codes=rest_codes, demand=demand, special_date_cols=special_cols)
    filename = f"暫時班表_{start_str}_{end_str}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )
