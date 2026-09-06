# 排班系統測試

## 快速使用

**Terminal 1**(啟動 backend,只要開一次,可長時間跑):

```bash
cd backend
venv/Scripts/python -m uvicorn main:app --host 127.0.0.1 --port 8877 --log-level warning
```

**Terminal 2**(跑測試,可反覆跑,每次 ~2-3 分鐘):

```bash
cd backend
venv/Scripts/pytest tests/           # 跑全部
venv/Scripts/pytest tests/test_hard_rules.py    # 只跑硬規則
venv/Scripts/pytest tests/test_warnings.py -v   # verbose 模式
```

## 目前涵蓋的測試

### 硬規則(`test_hard_rules.py`)
| 測試 | 對應規則 |
|---|---|
| `test_daily_D/E/N_meets_requirement` | H1:每日 D/E/N 人數 |
| `test_no_E_then_D_next_day` | H3:E→D 反向班禁止 |
| `test_no_N_then_E_next_day` | H3:N→E 反向班禁止 |
| `test_no_N_then_D_within_2days` | H3:N→D 需 2 天休 |
| `test_no_consec_over_limit` | H9:連續上班不超過設定 |
| `test_fixed_D_only_gets_D` | H10:固定D 不排 E/N |
| `test_fixed_E_only_gets_E` | H10:固定E 不排 D/N |
| `test_weekly_at_least_two_off` | H6:每週至少 2 休(若啟用) |

### Warning 正確性(`test_warnings.py`)
| 測試 | 用途 |
|---|---|
| `test_warning_reduce_days_matches_actual_off` | 抓 2026-09-06 的 bug:warning 說減 X 天要對應班表實際 OFF |
| `test_warning_no_reduce_matches_full_off` | 「沒減少」名單的人必須實休 >= 應休 quota |

## 用意

**改 code → 跑測試 → 通過再 deploy**。若某條規則被誤改破壞,測試會立刻 FAIL,不用等用戶發現。

## 加新測試

在 `tests/` 建 `test_xxx.py`,函數名 `test_xxx`,用現有 fixture:

- `generated_balanced` — 呼叫一次生成的結果(schedules + warnings + metrics)
- `rules` — 目前 DB 中的規則
- `users` — 護理師名單
- `cycle_dates` — 週期日期列表

範例:
```python
def test_my_rule(generated_balanced, cycle_dates):
    schedules = generated_balanced["schedules"]
    for uid, sched in schedules.items():
        # ... your assertion
        assert ...
```
