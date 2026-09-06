"""Warning 訊息正確性測試 — 抓今天發現的 bug(warning 減 X 天要對應實際 OFF)。"""
import re
import math

REST_LIKE = {"OFF", "半"}
LEAVE_ADJUST = {"V", "員", "喪", "延休", "補休", "調移"}


def test_warning_reduce_days_matches_actual_off(generated_balanced, rules, cycle_dates, users):
    """Warning 顯示「減 X 天」必須等於實際的(應休 - 實休)。

    今天抓到的 bug:solver 給 slack_var=2 但實際只少 1 天 OFF。
    修正:warning 用實際計算(quota - free_off,排除 LA),不用 solver 決策變數。
    """
    warnings = generated_balanced.get("warnings") or []
    reduce_warning = next((w for w in warnings if "人力不足" in w), None)
    if not reduce_warning:
        import pytest
        pytest.skip("本次無「人力不足」警告(可能沒人被縮減)")

    schedules = generated_balanced["schedules"]
    cycle = rules.get("cycle", {})
    holiday_days = int(cycle.get("holiday_days", 0))
    n = len(cycle_dates)
    full_off = min(8 + holiday_days, 13)
    part_work = math.floor((160 - holiday_days * 8) / 2 / 8)
    part_off = 28 - part_work

    # name → user 對照(排除 admin_staff,只留參與生成的)
    name_to_user = {u["name"]: u for u in users if not u.get("admin_staff") and u.get("role") in ("nurse", "dual")}

    # 解析「減 X 天:name1、name2、...」
    pattern = re.compile(r"減\s*(\d+)\s*天\s*[::]\s*([^\n]+)")

    mismatches = []
    for m in pattern.finditer(reduce_warning):
        days_reduced = int(m.group(1))
        names_str = m.group(2)
        names = [nm.strip() for nm in re.split(r"[、,]", names_str) if nm.strip()]
        for name in names:
            u = name_to_user.get(name)
            if u is None:
                # 用戶名可能有變體,先跳過
                continue
            sched = schedules.get(u["uid"], {})
            actual_off = sum(1 for d in cycle_dates if (sched.get(d) or "OFF") in REST_LIKE)
            la_cnt = sum(1 for d in cycle_dates if (sched.get(d) or "OFF") in LEAVE_ADJUST)
            is_ht = bool(u.get("halftime"))
            guaranteed = part_off if is_ht else full_off
            quota = max(0, min(guaranteed, n - la_cnt - 1))
            expected = max(0, quota - actual_off)
            if expected != days_reduced:
                mismatches.append(
                    f"{name}(quota={quota}, 實休={actual_off}, la={la_cnt}): "
                    f"warning 說減 {days_reduced}, 實際應為 {expected}"
                )

    assert not mismatches, "Warning 顯示與實際不符:\n  " + "\n  ".join(mismatches)


def test_warning_no_reduce_matches_full_off(generated_balanced, rules, cycle_dates, users):
    """Warning「沒減少」名單的人,實休 >= 應休 quota。"""
    warnings = generated_balanced.get("warnings") or []
    reduce_warning = next((w for w in warnings if "人力不足" in w), None)
    if not reduce_warning:
        import pytest
        pytest.skip("本次無「人力不足」警告")

    schedules = generated_balanced["schedules"]
    cycle = rules.get("cycle", {})
    holiday_days = int(cycle.get("holiday_days", 0))
    n = len(cycle_dates)
    full_off = min(8 + holiday_days, 13)
    part_work = math.floor((160 - holiday_days * 8) / 2 / 8)
    part_off = 28 - part_work

    name_to_user = {u["name"]: u for u in users if not u.get("admin_staff") and u.get("role") in ("nurse", "dual")}

    match = re.search(r"沒減少\s*[::]\s*([^\n]+)", reduce_warning)
    if not match:
        import pytest
        pytest.skip("warning 無「沒減少」名單")

    names = [nm.strip() for nm in re.split(r"[、,]", match.group(1)) if nm.strip()]
    mismatches = []
    for name in names:
        u = name_to_user.get(name)
        if u is None:
            continue
        sched = schedules.get(u["uid"], {})
        actual_off = sum(1 for d in cycle_dates if (sched.get(d) or "OFF") in REST_LIKE)
        la_cnt = sum(1 for d in cycle_dates if (sched.get(d) or "OFF") in LEAVE_ADJUST)
        is_ht = bool(u.get("halftime"))
        guaranteed = part_off if is_ht else full_off
        quota = max(0, min(guaranteed, n - la_cnt - 1))
        if actual_off < quota:
            mismatches.append(
                f"{name}: 被標「沒減少」但實休 {actual_off} < quota {quota}(la={la_cnt})"
            )
    assert not mismatches, "「沒減少」名單有誤:\n  " + "\n  ".join(mismatches)
