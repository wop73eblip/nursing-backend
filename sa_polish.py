"""
SA post-processing (Phase 1)

用「模擬退火」在 CP-SAT 找到的可行解上做局部改進。
只 propose swap-same-day-two-nurses(兩人同一天上班班種對調),
安全區間不會破壞 H1 每日人數 / OFF 相關的 H3/H17/H18 規則,
需驗的硬規則:
  - fixed cells / admin cells / 新人 skip
  - attr allowed (含 per-nurse dev override)
  - no reverse shift (E→D, N→E, N→D)
  - max_consec 連上限 (視窗)
  - 每週 shift types ≤ 2
  - leader >= 1, leader+second >= min(2, req)

軟分只算 3 項(Phase 1 最痛的):
  - SEGMENT_PENALTY (段數集中)
  - ULTRA_SHORT_BLOCK / SHORT_BLOCK (短塊懲罰,只算全職)
  - DIST_PENALTY (比例偏差,每人 pair)

回傳的解永遠 ≥ 起點(SA 只 keep best-so-far)。
"""
from __future__ import annotations
import math
import random
import time
from dataclasses import dataclass, field
from typing import Callable

# shift index: 0=D, 1=E, 2=N, 3=OFF
WORK_SI = (0, 1, 2)


@dataclass
class SAContext:
    M: int
    n: int
    # per-nurse info
    attr_map: dict[int, str]            # m -> "輪班DE" / "固定D" / ...
    halftime: dict[int, bool]           # m -> True/False
    trainee: set[int]                   # 新人 index
    is_leader: dict[int, bool]          # m -> is leader
    is_leader_or_second: dict[int, bool]
    allowed_si: dict[int, set[int]]     # m -> set of allowed shift si (含 3)
    dev_cap_rot: dict[int, int]         # m -> attr 偏離配額(輪班),default 0
    fixed_si: dict[int, int | None]     # m -> 固定 si (0/1/2) 或 None
    # per-cell locks
    fixed_cells: set[tuple[int, int]]   # 不能動的格
    admin_cells: set[tuple[int, int]]   # 行政班格,視同上班但不佔人力(不動)
    # daily demand
    day_d: list[int]
    day_e: list[int]
    day_n: list[int]
    # scheduling params
    max_consec: int
    weekly_ranges: list[tuple[int, int]]  # weeks 分段 (ws, we) inclusive
    # per-nurse history (前 HISTORY_DAYS 天的 si)
    hist_si: dict[int, list[int]]         # m -> [si...] length = HISTORY_DAYS
    # ratio pairs per nurse: list of (si_a, ra, si_b, rb) 每個 pair 都算一次 DIST
    ratio_pairs: dict[int, list[tuple[int, int, int, int]]]
    # penalties
    seg_pen: int
    ultra_pen: int
    short_pen: int
    dist_pen: int
    # sa params
    max_seconds: float = 30.0
    max_iter: int = 100000
    T0: float = 10000.0
    cooling: float = 0.9995
    no_improve_limit: int = 20000
    # RNG seed
    seed: int = 0


# ─── 軟分計算 ─────────────────────────────────────────────
def _seg_count_for_nurse(assign_m: list[int]) -> int:
    """每人「段數 - 1」總和(對 D/E/N 各算段數)。OFF/rest 穿透。"""
    total_over = 0
    for target in WORK_SI:
        segs = 0
        prev_was_target = False
        for v in assign_m:
            if v == 3:
                continue  # 穿透
            if v == target:
                if not prev_was_target:
                    segs += 1
                prev_was_target = True
            else:
                prev_was_target = False
        if segs > 1:
            total_over += (segs - 1)
    return total_over


def _short_block_penalty_for_nurse(assign_m: list[int], ultra_pen: int, short_pen: int) -> int:
    """每人短塊懲罰:1 天塊 * ultra_pen + 2 天塊 * short_pen。OFF 斷開。"""
    total = 0
    n = len(assign_m)
    i = 0
    while i < n:
        v = assign_m[i]
        if v not in WORK_SI:
            i += 1
            continue
        j = i
        while j < n and assign_m[j] == v:
            j += 1
        blk_len = j - i
        if blk_len == 1:
            total += ultra_pen
        elif blk_len == 2:
            total += short_pen
        i = j
    return total


def _dist_penalty_for_nurse(
    counts: tuple[int, int, int],  # (D, E, N)
    pairs: list[tuple[int, int, int, int]],  # (si_a, ra, si_b, rb)
    dist_pen: int,
) -> int:
    """對每個 pair 算 |va*rb - vb*ra| - tol,累加 * dist_pen。"""
    total = 0
    for si_a, ra, si_b, rb in pairs:
        va, vb = counts[si_a], counts[si_b]
        tol = ra + rb - 1
        diff = va * rb - vb * ra
        dev = max(0, abs(diff) - tol)
        total += dev * dist_pen
    return total


def _full_soft_score(assign: dict[tuple[int, int], int], ctx: SAContext) -> int:
    """整份 assignment 的軟分總和(Phase 1 只算 3 項)。"""
    total = 0
    for m in range(ctx.M):
        assign_m = [assign[(m, t)] for t in range(ctx.n)]
        # 段數(半職也算,因為它反映班種集中)
        total += _seg_count_for_nurse(assign_m) * ctx.seg_pen
        # 短塊(半職除外)
        if not ctx.halftime.get(m, False):
            total += _short_block_penalty_for_nurse(assign_m, ctx.ultra_pen, ctx.short_pen)
        # DIST:算每人 D/E/N 天數
        cnt = [0, 0, 0]
        for v in assign_m:
            if v < 3:
                cnt[v] += 1
        pairs = ctx.ratio_pairs.get(m, [])
        if pairs:
            total += _dist_penalty_for_nurse((cnt[0], cnt[1], cnt[2]), pairs, ctx.dist_pen)
    return total


# ─── 硬規則檢查 (swap 2 nurses same day, both work shifts) ────────────
def _reverse_shift_ok(seq: list[int], t: int) -> bool:
    """檢查 seq 中位置 t 前後 2 天內是否有反向班違反。
    禁止:E→D、N→E(隔 1)、N→D(隔 1 或 2)。OFF (=3) 才算間隔。
    seq 可以包含 history + assign 拼起來,t 是相對 seq 的索引。"""
    n = len(seq)
    if t < 0 or t >= n:
        return True
    v = seq[t]
    # 檢查 t 相對 t-1, t-2 (向前看)
    if v == 0:  # D
        if t >= 1 and seq[t - 1] == 1:  # E→D 隔 0
            return False
        if t >= 1 and seq[t - 1] == 2:  # N→D 隔 0
            return False
        if t >= 2 and seq[t - 2] == 2:  # N→_→D 隔 1
            return False
    elif v == 1:  # E
        if t >= 1 and seq[t - 1] == 2:  # N→E 隔 0
            return False
    # 檢查 t 相對 t+1, t+2 (向後看)
    if v == 1:  # E, 後面不能緊接 D
        if t + 1 < n and seq[t + 1] == 0:
            return False
    if v == 2:  # N, 後面不能緊接 E 或 D
        if t + 1 < n and seq[t + 1] in (0, 1):
            return False
        if t + 2 < n and seq[t + 2] == 0:
            return False
    return True


def _consec_ok(seq: list[int], t: int, max_consec: int) -> bool:
    """檢查 t 這天所在的「連續上班區塊」長度 ≤ max_consec。"""
    n = len(seq)
    if t < 0 or t >= n:
        return True
    if seq[t] == 3:
        return True   # OFF 天,連續斷開
    # 從 t 向前找連續起點
    l = t
    while l > 0 and seq[l - 1] != 3:
        l -= 1
    r = t
    while r + 1 < n and seq[r + 1] != 3:
        r += 1
    return (r - l + 1) <= max_consec


def _weekly_shift_types_ok(assign_m: list[int], ws: int, we: int) -> bool:
    """該週內出現的 D/E/N 種類數 ≤ 2。"""
    types = set()
    for t in range(ws, we + 1):
        v = assign_m[t]
        if v in WORK_SI:
            types.add(v)
    return len(types) <= 2


def _swap_is_valid(
    assign: dict, ctx: SAContext,
    a: int, b: int, t: int,
    sa: int, sb: int,  # 舊班別
    leader_cnt: dict, second_cnt: dict,
) -> bool:
    """驗證 swap(a的t班從sa變sb, b的t班從sb變sa) 是否合法。
    前提:sa, sb ∈ {0,1,2}, sa != sb, 兩格都不 fixed 也不 admin, 兩人皆非新人。"""
    # attr 允許
    allowed_a = ctx.allowed_si.get(a, {0, 1, 2, 3})
    allowed_b = ctx.allowed_si.get(b, {0, 1, 2, 3})
    if sb not in allowed_a or sa not in allowed_b:
        # 若有 dev override 也可考慮,Phase 1 保守跳過(不接受偏離)
        return False
    # 固定班屬性
    if ctx.fixed_si.get(a) is not None and sb != ctx.fixed_si.get(a):
        return False
    if ctx.fixed_si.get(b) is not None and sa != ctx.fixed_si.get(b):
        return False

    # 反向班 & 連上限:因為 swap 兩者都是上班,對每人來說「t 天上班」狀態不變,
    # 連上限視窗不變,只需驗反向班(D/E/N 之間切換)
    # 建 sequence: history + assign (改後)
    def check_person(m: int, new_v: int) -> bool:
        hist = ctx.hist_si.get(m, [])
        seq = list(hist)
        for tt in range(ctx.n):
            seq.append(assign[(m, tt)])
        # 覆寫 t
        seq[len(hist) + t] = new_v
        # 反向班檢查(t 附近 3 個位置)
        idx = len(hist) + t
        for k in (-2, -1, 0, 1, 2):
            if 0 <= idx + k < len(seq):
                if not _reverse_shift_ok(seq, idx + k):
                    return False
        # 連上限不變(因為 sa, sb 都是上班)
        return True

    if not check_person(a, sb):
        return False
    if not check_person(b, sa):
        return False

    # 每週 shift types ≤ 2
    # 找 t 所在的週
    week = None
    for ws, we in ctx.weekly_ranges:
        if ws <= t <= we:
            week = (ws, we)
            break
    if week is not None:
        ws, we = week
        assign_a = [assign[(a, tt)] if tt != t else sb for tt in range(ws, we + 1)]
        assign_b = [assign[(b, tt)] if tt != t else sa for tt in range(ws, we + 1)]
        types_a = {v for v in assign_a if v in WORK_SI}
        types_b = {v for v in assign_b if v in WORK_SI}
        if len(types_a) > 2 or len(types_b) > 2:
            return False

    # Leader/second (H7/H8) 檢查
    # a 從 sa → sb: sa 少 1 位 a,sb 多 1 位 a
    # b 從 sb → sa: sb 少 1 位 b,sa 多 1 位 b
    # 淨變化(算 admin/trainee 排除):
    #   sa: -is_clinical(a) + is_clinical(b)
    #   sb: +is_clinical(a) - is_clinical(b)
    # 但 admin_cells 不進 leader 計數,swap 前提是兩格都不 admin,兩人都不 trainee,所以都算 clinical
    # → 淨變化為 0!人數守恆
    # 但 leader/second 屬性可能不同:
    #   若 is_leader(a) True 且 is_leader(b) False → sa 少 1 leader、sb 多 1 leader
    a_is_ldr = ctx.is_leader.get(a, False)
    b_is_ldr = ctx.is_leader.get(b, False)
    a_is_ls = ctx.is_leader_or_second.get(a, False)
    b_is_ls = ctx.is_leader_or_second.get(b, False)

    delta_ldr_sa = (-1 if a_is_ldr else 0) + (1 if b_is_ldr else 0)
    delta_ldr_sb = (1 if a_is_ldr else 0) + (-1 if b_is_ldr else 0)
    delta_ls_sa  = (-1 if a_is_ls else 0) + (1 if b_is_ls else 0)
    delta_ls_sb  = (1 if a_is_ls else 0) + (-1 if b_is_ls else 0)

    req_map = {0: ctx.day_d[t], 1: ctx.day_e[t], 2: ctx.day_n[t]}

    for si, delta_l, delta_s in [(sa, delta_ldr_sa, delta_ls_sa), (sb, delta_ldr_sb, delta_ls_sb)]:
        req = req_map[si]
        if req <= 0:
            continue
        new_ldr = leader_cnt[(t, si)] + delta_l
        new_ls  = second_cnt[(t, si)] + delta_s
        if new_ldr < 1:
            return False
        if new_ls < min(2, req):
            return False
    return True


# ─── 增量式軟分變化 ────────────────────────────────────────────
def _delta_soft(
    assign: dict, ctx: SAContext,
    a: int, b: int, t: int, sa: int, sb: int,
) -> int:
    """算 swap 後 - swap 前 的軟分變化(只算涉及的 a、b 兩人,其他人不變)。"""
    # 舊分數:僅 a, b 兩人
    def score_for(m: int) -> int:
        assign_m = [assign[(m, tt)] for tt in range(ctx.n)]
        s = _seg_count_for_nurse(assign_m) * ctx.seg_pen
        if not ctx.halftime.get(m, False):
            s += _short_block_penalty_for_nurse(assign_m, ctx.ultra_pen, ctx.short_pen)
        cnt = [0, 0, 0]
        for v in assign_m:
            if v < 3:
                cnt[v] += 1
        pairs = ctx.ratio_pairs.get(m, [])
        if pairs:
            s += _dist_penalty_for_nurse((cnt[0], cnt[1], cnt[2]), pairs, ctx.dist_pen)
        return s

    old = score_for(a) + score_for(b)
    # 暫改
    assign[(a, t)] = sb
    assign[(b, t)] = sa
    new = score_for(a) + score_for(b)
    # 還原
    assign[(a, t)] = sa
    assign[(b, t)] = sb
    return new - old


# ─── SA 主迴圈 ───────────────────────────────────────────────
def sa_polish(assign: dict[tuple[int, int], int], ctx: SAContext,
              logger: Callable[[str], None] | None = None) -> tuple[dict[tuple[int, int], int], dict]:
    """跑 SA,回傳 (best_assign, stats)。best_assign 保證 ≥ 起點。"""
    def log(msg):
        if logger:
            logger(msg)

    rng = random.Random(ctx.seed if ctx.seed else 42)

    # 建 leader_cnt / second_cnt cache: (t, si) -> count(排除 trainee 和 admin)
    leader_cnt: dict[tuple[int, int], int] = {}
    second_cnt: dict[tuple[int, int], int] = {}
    for t in range(ctx.n):
        for si in WORK_SI:
            l_c = 0
            s_c = 0
            for m in range(ctx.M):
                if m in ctx.trainee:
                    continue
                if (m, t) in ctx.admin_cells:
                    continue
                if assign[(m, t)] != si:
                    continue
                if ctx.is_leader.get(m, False):
                    l_c += 1
                if ctx.is_leader_or_second.get(m, False):
                    s_c += 1
            leader_cnt[(t, si)] = l_c
            second_cnt[(t, si)] = s_c

    # 建候選格清單:所有非 fixed / 非 admin / 非 trainee 且當前是 work 的 (m, t)
    candidates_by_day: dict[int, list[int]] = {t: [] for t in range(ctx.n)}
    for t in range(ctx.n):
        for m in range(ctx.M):
            if m in ctx.trainee:
                continue
            if (m, t) in ctx.fixed_cells or (m, t) in ctx.admin_cells:
                continue
            if assign[(m, t)] in WORK_SI:
                candidates_by_day[t].append(m)

    curr_cost = _full_soft_score(assign, ctx)
    best_cost = curr_cost
    best_assign = dict(assign)
    log(f"[SA] start polish, initial soft_score={curr_cost}")

    T = ctx.T0
    accepted = 0
    proposed = 0
    improved_iters = 0
    last_improve_iter = 0

    start_time = time.time()
    iter_i = 0
    while iter_i < ctx.max_iter:
        # 時間卡
        if time.time() - start_time > ctx.max_seconds:
            log(f"[SA] stopped: max_seconds reached at iter={iter_i}")
            break
        # 無改善卡
        if iter_i - last_improve_iter > ctx.no_improve_limit:
            log(f"[SA] stopped: no improve for {ctx.no_improve_limit} iters, at iter={iter_i}")
            break

        # 隨機挑 t、a、b
        t = rng.randrange(ctx.n)
        cands = candidates_by_day[t]
        if len(cands) < 2:
            iter_i += 1
            continue
        a = cands[rng.randrange(len(cands))]
        b = cands[rng.randrange(len(cands))]
        if a == b:
            iter_i += 1
            continue
        sa = assign[(a, t)]
        sb = assign[(b, t)]
        if sa == sb:
            iter_i += 1
            continue

        proposed += 1
        if not _swap_is_valid(assign, ctx, a, b, t, sa, sb, leader_cnt, second_cnt):
            iter_i += 1
            continue

        delta = _delta_soft(assign, ctx, a, b, t, sa, sb)
        # accept?
        accept = False
        if delta < 0:
            accept = True
        else:
            try:
                p = math.exp(-delta / T) if T > 1e-6 else 0
            except OverflowError:
                p = 0
            if rng.random() < p:
                accept = True

        if accept:
            # apply
            assign[(a, t)] = sb
            assign[(b, t)] = sa
            # 更新 leader/second cache
            a_is_ldr = ctx.is_leader.get(a, False)
            b_is_ldr = ctx.is_leader.get(b, False)
            a_is_ls = ctx.is_leader_or_second.get(a, False)
            b_is_ls = ctx.is_leader_or_second.get(b, False)
            leader_cnt[(t, sa)] += (-1 if a_is_ldr else 0) + (1 if b_is_ldr else 0)
            leader_cnt[(t, sb)] += (1 if a_is_ldr else 0) + (-1 if b_is_ldr else 0)
            second_cnt[(t, sa)] += (-1 if a_is_ls else 0) + (1 if b_is_ls else 0)
            second_cnt[(t, sb)] += (1 if a_is_ls else 0) + (-1 if b_is_ls else 0)
            curr_cost += delta
            accepted += 1
            if curr_cost < best_cost:
                best_cost = curr_cost
                best_assign = dict(assign)
                improved_iters += 1
                last_improve_iter = iter_i

        T *= ctx.cooling
        iter_i += 1

        if iter_i % 5000 == 0:
            log(f"[SA] iter={iter_i} curr={curr_cost} best={best_cost} T={T:.1f} accept_ratio={accepted/max(1, proposed):.2f}")

    elapsed = time.time() - start_time
    improved_pct = ((_full_soft_score({k: v for k, v in assign.items()}, ctx) if False else 0))
    stats = {
        "initial_cost": _full_soft_score({(m, tt): assign[(m, tt)] for m in range(ctx.M) for tt in range(ctx.n)}, ctx),  # useless, just for record
        "final_cost": best_cost,
        "iters": iter_i,
        "accepted": accepted,
        "proposed": proposed,
        "elapsed": elapsed,
    }
    log(f"[SA] done. best={best_cost} iters={iter_i} accepted={accepted}/{proposed} elapsed={elapsed:.1f}s")
    return best_assign, stats
