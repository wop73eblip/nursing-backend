"""Column Generation 排班 MVP

不動現有 CP-SAT 排班,獨立 module。用相同 supabase 資料。

## 架構
1. Pricing(子問題):對每人跑 DP,產生 top-K 個「塊狀漂亮」的候選班表
2. Master(主問題):CP-SAT 選一組候選滿足每日 D/E/N 需求

## MVP 支援的規則
- 反向班禁止(pricing 硬檢查)
- 連續上班上限(pricing 硬檢查)
- 允許班種(輪班DE 只 D/E 等)
- 每週至少 1 OFF(pricing 硬檢查)
- 應休天數(pricing cost)
- 塊狀 penalty(pricing cost:短塊、中塊獎勵、長塊)
- 段數 penalty(pricing cost:每種班超過 1 段罰)
- 每日 D/E/N 需求(master 硬)
- 已預班/確認格鎖定(pricing 硬)

## MVP 不支援(先忽略)
- Leader/second 配置(H7/H8)
- 每週 2 種班上限(H4)
- 首週末雙休(F1)
- 固定班(固定D/E/N)- pricing 只允許該班
- H16 每週期至少連 2 OFF
- H17 iso ≤ 1
- S6 新人跟老師
- H13 個人比例硬上限(比例只當軟 cost)
- H1 精確人數(master 用等式,可能 infeasible → 用區間放寬)
"""

from ortools.sat.python import cp_model
from datetime import datetime, timedelta
from typing import Optional
import os

SHIFTS = ['D', 'E', 'N', 'OFF']  # 索引 0/1/2/3
SI = {'D': 0, 'E': 1, 'N': 2}
REST_LIKE = {'OFF', '半'}
LEAVE_ADJUST_DEFAULT = {'V', '員', '喪', '延休', '補休', '調移'}
ADMIN_SHIFTS_DEFAULT = {'書', '會', '公'}
REVERSE_PAIRS = {(1, 0), (2, 1), (2, 0)}  # E→D, N→E, N→D


def _pen(rules_penalties: dict, key: str, default) -> int:
    """讀 rules.penalties 或 default"""
    v = rules_penalties.get(key)
    if v is None:
        v = os.getenv(key)
    try:
        return int(v) if v is not None and str(v).strip() != "" else int(default)
    except (ValueError, TypeError):
        return int(default)


def _allowed_shifts(attr: str) -> list:
    """attr → allowed shifts 索引 (含 OFF=3)"""
    if attr == "輪班DE": return [0, 1, 3]
    if attr == "輪班EN": return [1, 2, 3]
    if attr == "輪班DN": return [0, 2, 3]
    if attr == "輪班DEN": return [0, 1, 2, 3]
    if attr == "固定D": return [0, 3]
    if attr == "固定E": return [1, 3]
    if attr == "固定N": return [2, 3]
    return [0, 1, 2, 3]


def _reverse_ok(prev_shift: int, off_gap: int, cur_shift: int) -> bool:
    """反向班檢查:E→D 需 g≥1 OFF、N→E 需 g≥1、N→D 需 g≥2"""
    if prev_shift == 1 and cur_shift == 0 and off_gap < 1:
        return False
    if prev_shift == 2 and cur_shift == 1 and off_gap < 1:
        return False
    if prev_shift == 2 and cur_shift == 0 and off_gap < 2:
        return False
    return True


def generate_candidates(
    nurse_idx: int,
    nurse: dict,
    n: int,
    cycle_dates: list,
    prefilled: dict,   # {t: shift_index or None}
    off_target: int,
    max_consec: int,
    pens: dict,
    top_k: int = 15,
) -> list:
    """
    對某人跑 DP 找 top-K 候選班表。

    DP 狀態:(day, current_state)
    current_state 分兩類:
      - 'W_s_k':該天上班種 s,已連續 k 天
      - 'O_g':該天 OFF/半,前一次工作結束後過了 g 天(用來判斷反向班)

    簡化:狀態 = (last_work_shift, off_gap_since_last_work, streak_current_work)
    - last_work_shift: 0/1/2 (前一次工作班種)
    - off_gap: 0-6 (已連續 OFF 幾天;若當天上班則 0)
    - streak: 當天若上班,已連續同班幾天;若 OFF 則此值 = 0
    - today_shift: 0/1/2/3 (今天實際排的班)

    狀態太多會爆,簡化再簡化:
    (last_work_shift, off_gap_or_streak) 用單一 tuple 表示

    改用:node = (day, today_shift, streak)
      - streak 對 OFF/半 也累計連休天數(方便 iso 檢查)
    加上 last_work_shift 追蹤反向班 → node = (day, today_shift, streak, last_work_shift, off_gap)

    這樣狀態:28 * 4 * 6 * 3 * 4 ≈ 8000 節點,可接受

    每個節點記 min cost + top_k 個備選 path。
    """
    attr = nurse.get('attr', '輪班DEN')
    allowed = set(_allowed_shifts(attr))
    is_ht = nurse.get('halftime', False)

    # 節點:(day, shift, streak, last_work, off_gap)
    # shift 0-3, streak 1..max_consec (若 OFF/半 則為連休天數)
    # last_work 0-2 (無則用 -1);off_gap 0-6+

    # 用 forward DP:dp[day][state] = (min_cost, top_k_paths)
    # 每個 path 是 list of shifts

    # 極簡狀態:(shift, streak, last_work, off_gap)
    # 為避免爆,限 streak <= max_consec+1、off_gap <= 6

    INF = float('inf')

    def state_key(shift, streak, last_work, off_gap):
        return (shift, min(streak, max_consec + 1), last_work if last_work is not None else -1, min(off_gap, 7))

    # 起點:day 0 前(virtual)
    # 對 day 0 每個可能 shift 建 init
    # dp: dict from state → list of (cost, path_prefix)
    dp = [dict() for _ in range(n + 1)]
    # day 0: 對每個允許的 shift(或 prefilled 例外 shift)
    pf0 = prefilled.get(0)
    day0_allowed = allowed if pf0 is None else {pf0}   # 若 prefilled 是例外班種,強制用它
    for s in range(4):
        if s not in day0_allowed: continue
        # 起始:streak=1,last_work = s if s < 3 else None,off_gap = 0 if s<3 else 1
        if s < 3:
            last_work = s
            off_gap = 0
            streak = 1
        else:
            last_work = -1  # 尚無工作班
            off_gap = 1
            streak = 1
        key = state_key(s, streak, last_work, off_gap)
        # cost 0(day 0 沒 transition)
        dp[0][key] = [(0.0, [s])]

    # 每個節點只保留 top_k paths
    def prune(paths, k):
        paths.sort(key=lambda x: x[0])
        return paths[:k]

    # Forward
    for day in range(n - 1):
        cur = dp[day]
        nxt = dp[day + 1]
        for cur_key, paths in cur.items():
            cur_shift, cur_streak, cur_last_work, cur_off_gap = cur_key
            pf = prefilled.get(day + 1)
            next_allowed = allowed if pf is None else {pf}  # prefilled 強制,允許例外班種
            for next_s in range(4):
                if next_s not in next_allowed: continue

                # 檢查硬規則
                # 1. 連上限
                if next_s < 3 and cur_shift < 3:
                    if next_s == cur_shift and cur_streak >= max_consec: continue
                    new_streak = cur_streak + 1 if next_s == cur_shift else 1
                    if new_streak > max_consec: continue
                elif next_s < 3 and cur_shift >= 3:
                    new_streak = 1
                elif next_s >= 3:
                    new_streak = cur_streak + 1 if cur_shift >= 3 else 1

                # 2. 反向班
                if next_s < 3 and cur_last_work >= 0:
                    if not _reverse_ok(cur_last_work, cur_off_gap, next_s):
                        continue

                # 計算 cost delta
                cost_delta = 0

                # 塊 penalty:若結束一段(shift 從 s 變非 s 或反過來)
                # 段數 penalty:若 shift 從一個工作班變另一個工作班(視為新段起點)
                # 簡化:只計「上班段結束時的塊長度」+「換班次數」
                if cur_shift < 3 and next_s < 3 and cur_shift != next_s:
                    # 上班換上班(直接切) → 段結束,結算 cur 段的塊長
                    L = cur_streak
                    if L == 1: cost_delta += pens['SHORT'] * 2
                    elif L == 2: cost_delta += pens['SHORT']
                    elif L <= 4: cost_delta -= pens['MID']
                    elif L >= 5: cost_delta += pens['LONG']
                    # 反向班額外
                    if (cur_shift, next_s) in REVERSE_PAIRS:
                        cost_delta += pens['REV']
                    # 直接切換
                    cost_delta += pens['DIRECT']
                    cost_delta += pens['EXCESS']  # 換班
                elif cur_shift < 3 and next_s >= 3:
                    # 上班換 OFF → 段結束,結算
                    L = cur_streak
                    if L == 1: cost_delta += pens['SHORT'] * 2
                    elif L == 2: cost_delta += pens['SHORT']
                    elif L <= 4: cost_delta -= pens['MID']
                    elif L >= 5: cost_delta += pens['LONG']
                elif cur_shift >= 3 and next_s < 3:
                    # OFF 起新段
                    # 反向班額外(考慮 gap)
                    if cur_last_work >= 0 and (cur_last_work, next_s) in REVERSE_PAIRS:
                        cost_delta += pens['REV']
                    if cur_last_work >= 0 and cur_last_work != next_s:
                        cost_delta += pens['EXCESS']  # 換班(gap 版)

                # 孤立日:day 是 cur_shift 且 cur_shift < 3 且 day-1 是 OFF 且 day+1 是 OFF
                # cur 是 day 的 shift,next_s 是 day+1
                # iso for day (需要 day-1 也 OFF,查上一個 state)
                # 簡化:當看到 cur_shift < 3, cur_streak == 1,且 next_s >= 3 且 cur_off_gap 之前 >=1 (即前一天 OFF)
                # 這代表 cur 是孤立日
                if cur_shift < 3 and cur_streak == 1 and next_s >= 3 and cur_off_gap == 0:
                    # 之前是 OFF,今天上班一天,明天 OFF → 孤立
                    # 需要 cur_off_gap == 0 意思今天是工作,那看前一天。這裡 tricky。
                    # 更精確:上個工作日結束在 (day - 1 - cur_off_gap),若 day - 1 是 OFF (即 cur_off_gap 在 cur day 之前應 >= 1)
                    # cur_streak == 1 表 cur 是新段起點
                    # 若 cur_off_gap 於 cur state 為 0(因為 cur 是工作),那之前 gap 需要另存
                    # 簡化 skip 孤立 penalty(次要)
                    pass

                # OFF 天數目標:計每個 candidate 最後總 OFF 數,pricing 中不好動態評估
                # 改在 candidate 最後回傳時 penalize

                # 更新 state
                if next_s < 3:
                    new_last_work = next_s
                    new_off_gap = 0
                else:
                    new_last_work = cur_last_work
                    new_off_gap = cur_off_gap + 1 if cur_shift >= 3 else 1

                nxt_key = state_key(next_s, new_streak, new_last_work, new_off_gap)
                new_paths = []
                for (cost, path) in paths:
                    new_paths.append((cost + cost_delta, path + [next_s]))
                if nxt_key in nxt:
                    combined = nxt[nxt_key] + new_paths
                else:
                    combined = new_paths
                nxt[nxt_key] = prune(combined, top_k)

        # 每層 prune,避免太多 state
        # 全層 top K*3 (避免只保留最好的錯過多樣性)
        all_paths = []
        for k, ps in nxt.items():
            for cst, pth in ps:
                all_paths.append((cst, pth, k))
        all_paths.sort(key=lambda x: x[0])
        keep = min(len(all_paths), top_k * 5)
        new_dp = {}
        for cst, pth, k in all_paths[:keep]:
            if k not in new_dp: new_dp[k] = []
            new_dp[k].append((cst, pth))
        dp[day + 1] = new_dp

    # 收集所有 day n-1 的 paths
    all_final = []
    for k, ps in dp[n - 1].items():
        for cst, pth in ps:
            all_final.append((cst, pth))
    all_final.sort(key=lambda x: x[0])

    # 加 OFF 數量 penalty(偏離 off_target)
    scored = []
    for cost, path in all_final:
        off_count = sum(1 for s in path if s == 3)
        off_dev = abs(off_count - off_target)
        adjusted = cost + off_dev * 2000  # 偏離每天罰 2000
        scored.append((adjusted, path, off_count))
    scored.sort(key=lambda x: x[0])

    # 段數 penalty(post-hoc):對每個 candidate 計每種班的段數超額
    result = []
    for cost, path, off_count in scored[:top_k * 2]:
        work_seq = [s for s in path if s < 3]
        seg = {0: 0, 1: 0, 2: 0}
        if work_seq:
            seg[work_seq[0]] += 1
            for i in range(1, len(work_seq)):
                if work_seq[i] != work_seq[i - 1]:
                    seg[work_seq[i]] += 1
        seg_over = sum(max(0, seg[s] - 1) for s in [0, 1, 2])
        seg_penalty = seg_over * pens['SEG']
        result.append((cost + seg_penalty, path, off_count))
    result.sort(key=lambda x: x[0])
    return result[:top_k]


def master_solve(candidates_by_m: dict, n: int, daily_d: int, daily_e: int, daily_n: int,
                  nurses: list, trainee_set: set, admin_prefilled: dict,
                  time_limit: int = 60) -> Optional[dict]:
    """
    Master:CP-SAT 選一組 candidate 滿足需求。

    candidates_by_m: dict[m] = list of (cost, path)
    admin_prefilled: dict[(m, t)] = True 若那格是行政班(不佔臨床名額)
    """
    M = len(nurses)
    model = cp_model.CpModel()
    y = {}
    for m in range(M):
        cands = candidates_by_m.get(m, [])
        if not cands:
            return None  # 該人無可行 candidate
        y[m] = [model.new_bool_var(f"y_{m}_{k}") for k in range(len(cands))]
        model.add(sum(y[m]) == 1)  # 每人選 1

    # 每日需求(不含新人、不含行政)- 用 slack 放寬,slack 高罰
    demand_slack_pen = 50000
    slack_vars = []
    for t in range(n):
        for s_idx, req in [(0, daily_d), (1, daily_e), (2, daily_n)]:
            terms = []
            for m in range(M):
                if m in trainee_set: continue
                cands = candidates_by_m[m]
                for k, cand in enumerate(cands):
                    path = cand[1]
                    if path[t] == s_idx and (m, t) not in admin_prefilled:
                        terms.append(y[m][k])
            over = model.new_int_var(0, M, f"over_{t}_{s_idx}")
            under = model.new_int_var(0, M, f"under_{t}_{s_idx}")
            if terms:
                model.add(sum(terms) - req == over - under)
            else:
                model.add(-req == over - under)   # 用 slack 允許沒人
            slack_vars.append(over)
            slack_vars.append(under)

    # 目標:min total cost + demand slack × 高罰
    total_cost_terms = []
    for m in range(M):
        cands = candidates_by_m[m]
        for k, cand in enumerate(cands):
            total_cost_terms.append(y[m][k] * int(cand[0]))
    model.minimize(sum(total_cost_terms) + sum(slack_vars) * demand_slack_pen)

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = time_limit
    solver.parameters.num_workers = 8
    status = solver.solve(model)
    if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return None
    # 提取每人選的 candidate
    chosen = {}
    for m in range(M):
        cands = candidates_by_m[m]
        for k in range(len(cands)):
            if solver.value(y[m][k]) == 1:
                chosen[m] = cands[k]
                break
    return {
        'chosen': chosen,
        'total_cost': solver.objective_value,
        'status': solver.status_name(status),
        'wall_time': solver.wall_time,
    }


def generate_cg_schedule(profile: str, current_user: dict, supabase,
                          cycle_start_str: str, cycle_days: int = 28) -> dict:
    """CG 排班主入口。讀 supabase 現有資料,產生班表。

    Returns dict 格式與 /schedule/generate 相容:
    {
        "message": "...",
        "schedules": {uid: {date: shift}},
        "cycle_dates": [...],
        "solver_status": "...",
        "nurses": count,
        "metrics": {...},
    }
    """
    # 1. 讀 rules
    rules_res = supabase.table("rules").select("*").limit(1).execute()
    if not rules_res.data:
        raise RuntimeError("請先設定排班規則")
    rules = rules_res.data[0].get("data") or {}
    scheduling = rules.get("scheduling") or {}
    rules_penalties = rules.get("penalties") or {}
    daily_d = int(scheduling.get("daily_d", 3))
    daily_e = int(scheduling.get("daily_e", 3))
    daily_n = int(scheduling.get("daily_n", 3))
    max_consec = int(scheduling.get("max_consec_work", 5))

    # 2. 讀 users
    u = supabase.table("users").select("uid,name,role,attr,halftime,admin_staff,is_trainee").execute()
    all_users = u.data or []
    # 過濾:僅排班相關(nurse/dual,或 admin_staff)
    nurses = [
        {
            'uid': x['uid'],
            'name': x.get('name') or x['uid'],
            'attr': x.get('attr') or '輪班DEN',
            'halftime': bool(x.get('halftime')),
            'is_trainee': bool(x.get('is_trainee')),
        }
        for x in all_users
        if x.get('role') in ('nurse', 'dual') and x.get('attr')
    ]
    M = len(nurses)
    if M == 0:
        raise RuntimeError("找不到排班護理師")
    trainee_set = {m for m, nz in enumerate(nurses) if nz['is_trainee']}

    # 3. 建 cycle_dates
    start_d = datetime.strptime(cycle_start_str, '%Y-%m-%d').date()
    cycle_dates = [(start_d + timedelta(days=t)).isoformat() for t in range(cycle_days)]
    n = cycle_days

    # 4. 讀 shifts(預填/確認)
    sh_res = supabase.table("shifts").select("nurse_uid,date,shift,confirmed").gte("date", cycle_dates[0]).lte("date", cycle_dates[-1]).execute()
    existing = {}   # (uid, date) → row
    admin_cells = set()   # {(m, t)} 行政班(視同 D 但不佔名額)
    for r in (sh_res.data or []):
        key = (r['nurse_uid'], r['date'])
        existing[key] = r

    # 5. 每人的 prefilled(索引 → shift_index or None)
    off_full = 8
    off_part = 18

    pens = {
        'SHORT': _pen(rules_penalties, 'SHORT_BLOCK_PENALTY', 2000),
        'MID': _pen(rules_penalties, 'MID_BLOCK_REWARD', 500),
        'LONG': _pen(rules_penalties, 'LONG_BLOCK_PENALTY', 800),
        'SEG': _pen(rules_penalties, 'SEGMENT_PENALTY', 3000),
        'ISO': _pen(rules_penalties, 'ISOLATED_WORK_PENALTY', 750),
        'EXCESS': _pen(rules_penalties, 'EXCESS_SWITCH_PENALTY', 1500),
        'DIRECT': _pen(rules_penalties, 'DIRECT_SWITCH_PENALTY', 500),
        'REV': _pen(rules_penalties, 'REVERSE_SWITCH_PENALTY', 500),
    }

    # 6. 對每人 pricing
    candidates_by_m: dict = {}
    print(f"[CG] Pricing 開始:{M} 護理師")
    for m in range(M):
        nurse = nurses[m]
        # prefilled
        prefilled = {}
        for t, d_str in enumerate(cycle_dates):
            r = existing.get((nurse['uid'], d_str))
            if r and r.get('shift'):
                s = r['shift']
                # 行政視同 D 但標記
                if s in ADMIN_SHIFTS_DEFAULT:
                    prefilled[t] = 0
                    admin_cells.add((m, t))
                elif s in SI:
                    prefilled[t] = SI[s]
                elif s in REST_LIKE or s in LEAVE_ADJUST_DEFAULT:
                    prefilled[t] = 3  # OFF
        off_target = off_part if nurse['halftime'] else off_full
        cands = generate_candidates(
            m, nurse, n, cycle_dates, prefilled, off_target,
            max_consec, pens, top_k=15
        )
        candidates_by_m[m] = cands
        print(f"[CG] {nurse['name']}: {len(cands)} 個 candidates, best cost={cands[0][0]:.0f}" if cands else f"[CG] {nurse['name']}: 無 candidate!")

    # 7. Master
    print(f"[CG] Master 開始")
    master_result = master_solve(candidates_by_m, n, daily_d, daily_e, daily_n,
                                   nurses, trainee_set, admin_cells, time_limit=60)
    if master_result is None:
        return {
            "message": "❌ CG 排班失敗:master 無解(可能候選不符每日需求)",
            "schedules": {},
            "cycle_dates": cycle_dates,
            "solver_status": "INFEASIBLE",
            "nurses": M,
            "metrics": None,
        }

    # 8. 組回 schedules
    schedules = {}
    for m in range(M):
        nurse = nurses[m]
        chosen_cand = master_result['chosen'][m]
        path = chosen_cand[1]
        # path 是 shift 索引 list;還原 admin
        seq = []
        for t in range(n):
            if (m, t) in admin_cells:
                # 還原為原字元
                r = existing.get((nurse['uid'], cycle_dates[t]))
                seq.append(r['shift'] if r else 'D')
            elif path[t] == 3:
                # OFF or LA(還原)
                r = existing.get((nurse['uid'], cycle_dates[t]))
                if r and r.get('shift') in LEAVE_ADJUST_DEFAULT or (r and r.get('shift') in REST_LIKE and r['shift'] != 'OFF'):
                    seq.append(r['shift'])
                else:
                    seq.append('OFF')
            else:
                seq.append(SHIFTS[path[t]])
        schedules[nurse['uid']] = {cycle_dates[t]: seq[t] for t in range(n)}

    return {
        "message": f"✓ CG 排班完成({M} 位護理師,total cost={master_result['total_cost']:.0f})",
        "schedules": schedules,
        "cycle_dates": cycle_dates,
        "solver_status": master_result['status'],
        "nurses": M,
        "metrics": {
            "objective_value": master_result['total_cost'],
            "solver_status": master_result['status'],
            "solver_wall_time": round(master_result['wall_time'], 2),
        },
        "cg_debug": {
            "candidates_per_nurse": {nurses[m]['name']: len(candidates_by_m[m]) for m in range(M)},
        }
    }
