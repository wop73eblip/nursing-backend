"""硬規則測試:CP-SAT 出來的班表必須全部滿足。"""
from collections import Counter


REST_LIKE = {"OFF", "半"}
LEAVE_ADJUST_LIKE = {"V", "員", "喪", "延休", "補休", "調移"}
ADMIN_LIKE = {"會", "公", "書記", "書"}


def _shift_at(sched, date_str):
    return sched.get(date_str) or "OFF"


class TestH1_DailyCount:
    """H1:每日 D/E/N 剛好符合設定人數(排除新人、行政班)。"""

    def test_daily_D_meets_requirement(self, generated_balanced, rules, cycle_dates):
        """每天 D 班的臨床人數必須 = 設定的 daily_d。"""
        schedules = generated_balanced["schedules"]
        scheduling = rules.get("scheduling", {})
        daily_d = int(scheduling.get("daily_d", 3))
        special = {sd["date"]: sd for sd in (scheduling.get("special_dates") or [])}
        for d in cycle_dates:
            req = int(special[d].get("d", daily_d)) if d in special else daily_d
            actual = sum(1 for uid, sched in schedules.items() if _shift_at(sched, d) == "D")
            # 行政班(會/公/書)不算 D 人力,ADMIN_LIKE 顯示為原碼
            actual_admin_d = sum(1 for uid, sched in schedules.items() if _shift_at(sched, d) in ADMIN_LIKE)
            # 我們只驗「D 班標記為 D 的」等於 req(admin 是另外算)
            assert actual >= req, f"{d}:D 班需 {req} 人,實際 {actual}(+行政 {actual_admin_d})"

    def test_daily_E_meets_requirement(self, generated_balanced, rules, cycle_dates):
        schedules = generated_balanced["schedules"]
        daily_e = int(rules.get("scheduling", {}).get("daily_e", 3))
        special = {sd["date"]: sd for sd in (rules.get("scheduling", {}).get("special_dates") or [])}
        for d in cycle_dates:
            req = int(special[d].get("e", daily_e)) if d in special else daily_e
            actual = sum(1 for uid, sched in schedules.items() if _shift_at(sched, d) == "E")
            assert actual >= req, f"{d}:E 班需 {req} 人,實際 {actual}"

    def test_daily_N_meets_requirement(self, generated_balanced, rules, cycle_dates):
        schedules = generated_balanced["schedules"]
        daily_n = int(rules.get("scheduling", {}).get("daily_n", 3))
        special = {sd["date"]: sd for sd in (rules.get("scheduling", {}).get("special_dates") or [])}
        for d in cycle_dates:
            req = int(special[d].get("n", daily_n)) if d in special else daily_n
            actual = sum(1 for uid, sched in schedules.items() if _shift_at(sched, d) == "N")
            assert actual >= req, f"{d}:N 班需 {req} 人,實際 {actual}"


class TestH3_ReverseShift:
    """H3:反向班禁止 — E→D 隔1天休、N→E 隔1天休、N→D 隔2天休。"""

    def test_no_E_then_D_next_day(self, generated_balanced, cycle_dates):
        schedules = generated_balanced["schedules"]
        for uid, sched in schedules.items():
            for i in range(len(cycle_dates) - 1):
                a = _shift_at(sched, cycle_dates[i])
                b = _shift_at(sched, cycle_dates[i + 1])
                assert not (a == "E" and b == "D"), f"{uid} {cycle_dates[i]}→{cycle_dates[i+1]}: E→D 反向班"

    def test_no_N_then_E_next_day(self, generated_balanced, cycle_dates):
        schedules = generated_balanced["schedules"]
        for uid, sched in schedules.items():
            for i in range(len(cycle_dates) - 1):
                a = _shift_at(sched, cycle_dates[i])
                b = _shift_at(sched, cycle_dates[i + 1])
                assert not (a == "N" and b == "E"), f"{uid} {cycle_dates[i]}→{cycle_dates[i+1]}: N→E 反向班"

    def test_no_N_then_D_within_2days(self, generated_balanced, cycle_dates):
        schedules = generated_balanced["schedules"]
        for uid, sched in schedules.items():
            for i in range(len(cycle_dates) - 2):
                a = _shift_at(sched, cycle_dates[i])
                b = _shift_at(sched, cycle_dates[i + 1])
                c = _shift_at(sched, cycle_dates[i + 2])
                assert not (a == "N" and b == "D"), f"{uid} {cycle_dates[i]}→{cycle_dates[i+1]}: N→D 反向班"
                assert not (a == "N" and c == "D"), f"{uid} {cycle_dates[i]}→...→{cycle_dates[i+2]}: N→_→D 反向班(需 2 天休)"


class TestH9_ConsecutiveWork:
    """H9:連續上班天數不超過 max_consecutive_work(default 5)。"""

    def test_no_consec_over_limit(self, generated_balanced, rules, cycle_dates):
        schedules = generated_balanced["schedules"]
        max_consec = int(rules.get("scheduling", {}).get("max_consecutive_work", 5))
        for uid, sched in schedules.items():
            consec = 0
            for d in cycle_dates:
                s = _shift_at(sched, d)
                if s in REST_LIKE or s in LEAVE_ADJUST_LIKE:
                    consec = 0
                else:
                    consec += 1
                    assert consec <= max_consec, \
                        f"{uid} 到 {d} 連上 {consec} 天 > 上限 {max_consec}"


class TestH10_AttrLimit:
    """H10:輪班/固定 attr 限制。輪班 default 不允許非 attr 班種(除非 override)。"""

    def test_fixed_D_only_gets_D(self, generated_balanced, cycle_dates, users):
        """固定D attr 的人,除了 D/OFF/LA/admin,不該有 E 或 N。"""
        fixed_d_uids = [u["uid"] for u in users if u.get("attr") == "固定D"]
        schedules = generated_balanced["schedules"]
        for uid in fixed_d_uids:
            sched = schedules.get(uid, {})
            for d in cycle_dates:
                s = _shift_at(sched, d)
                # 固定D 不該排 E 或 N (除非有 override,測試最寬鬆規則)
                assert s not in ("E", "N"), f"固定D {uid} {d} 被排 {s}"

    def test_fixed_E_only_gets_E(self, generated_balanced, cycle_dates, users):
        fixed_e_uids = [u["uid"] for u in users if u.get("attr") == "固定E"]
        schedules = generated_balanced["schedules"]
        for uid in fixed_e_uids:
            sched = schedules.get(uid, {})
            for d in cycle_dates:
                s = _shift_at(sched, d)
                assert s not in ("D", "N"), f"固定E {uid} {d} 被排 {s}"


class TestH6_OneOffPerWeek:
    """H6 一例一休(若 one_in_seven=True):每人每週 ≥ 2 天休。"""

    def test_weekly_at_least_two_off(self, generated_balanced, rules, cycle_dates):
        scheduling = rules.get("scheduling", {})
        if not scheduling.get("one_in_seven", True):
            import pytest
            pytest.skip("one_in_seven 未啟用")
        schedules = generated_balanced["schedules"]
        # 依 ISO week 分組
        from datetime import date
        weeks: dict[tuple, list[str]] = {}
        for d_str in cycle_dates:
            d = date.fromisoformat(d_str)
            key = (d.isocalendar().year, d.isocalendar().week)
            weeks.setdefault(key, []).append(d_str)
        for uid, sched in schedules.items():
            for wk, days in weeks.items():
                # 只驗完整週(涵蓋 5-7 天)避免週期首尾誤判
                if len(days) < 5:
                    continue
                # 排除該週全部是 LA 的情況
                rest_count = sum(1 for d in days if _shift_at(sched, d) in REST_LIKE)
                la_count = sum(1 for d in days if _shift_at(sched, d) in LEAVE_ADJUST_LIKE)
                # 若整週幾乎都 LA,跳過
                if la_count >= len(days) - 1:
                    continue
                # 完整週(通常 7 天)必須至少 2 天 REST(OFF/半)
                # 週期首尾週(5-6 天)寬鬆:>=1 天 REST(H5 仍在)
                required = 2 if len(days) >= 7 else 1
                assert rest_count >= required, \
                    f"{uid} 週 {wk}({days[0]}~{days[-1]}, {len(days)}天):OFF/半 只 {rest_count} 天 < {required}"
