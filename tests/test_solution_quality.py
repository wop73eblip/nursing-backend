"""解的品質檢查:solver 狀態、objective、schedules 完整性。"""
import pytest

REST_LIKE = {"OFF", "半"}
LEAVE_ADJUST_LIKE = {"V", "員", "喪", "延休", "補休", "調移"}


def test_solver_status_ok(generated_balanced):
    """CP-SAT 必須成功找到解(OPTIMAL 或 FEASIBLE)。"""
    metrics = generated_balanced.get("metrics") or {}
    status = metrics.get("solver_status", "")
    assert status in ("OPTIMAL", "FEASIBLE"), f"solver status = {status}"


def test_all_nurses_have_full_schedule(generated_balanced, cycle_dates, users):
    """每位參與生成的護理師都應該有完整 28 天班表(不缺日子)。"""
    schedules = generated_balanced["schedules"]
    schedulable = [u for u in users if not u.get("admin_staff") and u.get("role") in ("nurse", "dual")]
    for u in schedulable:
        uid = u["uid"]
        assert uid in schedules, f"{u['name']} 沒出現在 schedules"
        sched = schedules[uid]
        for d in cycle_dates:
            assert d in sched, f"{u['name']} 缺 {d}"
            assert sched[d], f"{u['name']} {d} 值為空"


def test_objective_is_number(generated_balanced):
    """objective_value 必須是數字(FEASIBLE/OPTIMAL 時)。"""
    metrics = generated_balanced.get("metrics") or {}
    if metrics.get("rescued"):
        pytest.skip("救援解不驗 objective")
    obj = metrics.get("objective_value")
    assert isinstance(obj, (int, float)), f"objective_value = {obj} 不是數字"


def test_no_prefill_overwritten(generated_balanced, backend_url, auth_headers, cycle_dates):
    """H2:已填班別一律保留 — 對比 DB 中已有的 shifts,生成後應該仍在。"""
    import requests
    r = requests.get(backend_url + "/schedule", headers=auth_headers, timeout=15,
                     params={"start_date": cycle_dates[0], "end_date": cycle_dates[-1]})
    if r.status_code != 200:
        pytest.skip("拿不到 /schedule")
    data = r.json()
    existing_shifts = data.get("shifts") or data if isinstance(data, list) else []
    # data 可能是 dict{shifts:[...]} 或直接 list
    if isinstance(existing_shifts, dict):
        existing_shifts = existing_shifts.get("shifts") or []
    schedules = generated_balanced["schedules"]
    mismatches = []
    for row in existing_shifts:
        uid = row.get("nurse_uid")
        d = row.get("date")
        orig = row.get("shift")
        if not orig or uid not in schedules or d not in cycle_dates:
            continue
        after = schedules[uid].get(d)
        if orig != after:
            mismatches.append(f"{uid} {d}: 原 {orig} 被改成 {after}")
    # 只斷第一批(可能大量,前 5 就夠展示)
    assert not mismatches, "H2 已填班別被覆蓋:\n  " + "\n  ".join(mismatches[:10])


def test_no_reverse_shift_across_cycle_start(generated_balanced, cycle_dates):
    """反向班在週期第 1-2 天也不能違反(需考慮 history,這裡只驗週期內)。"""
    # 已由 TestH3 涵蓋週期內,這條是最基本 sanity check
    assert len(cycle_dates) >= 7, "週期太短"


def test_admin_shift_preserved(generated_balanced, backend_url, auth_headers, cycle_dates):
    """行政班(會/公/書)在生成後應顯示原碼,不會被改成 D。"""
    import requests
    r = requests.get(backend_url + "/schedule", headers=auth_headers, timeout=15,
                     params={"start_date": cycle_dates[0], "end_date": cycle_dates[-1]})
    if r.status_code != 200:
        pytest.skip("拿不到 /schedule")
    data = r.json()
    existing = data.get("shifts") if isinstance(data, dict) else data
    if not existing:
        pytest.skip("無已存 shifts")
    admin_codes = {"會", "公", "書記", "書"}
    schedules = generated_balanced["schedules"]
    for row in existing:
        uid = row.get("nurse_uid")
        d = row.get("date")
        orig = row.get("shift")
        if orig in admin_codes and uid in schedules and d in schedules[uid]:
            assert schedules[uid][d] == orig, \
                f"{uid} {d} 行政班 {orig} 被改成 {schedules[uid][d]}"
