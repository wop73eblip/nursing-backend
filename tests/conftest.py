"""pytest 全域 fixture:連到「已啟動的本地 backend」跑整合測試。

使用方式:
  Terminal 1(先啟動 backend,只需啟一次):
    cd backend
    venv/Scripts/python -m uvicorn main:app --host 127.0.0.1 --port 8877 --log-level warning

  Terminal 2(跑測試,可反覆跑):
    cd backend
    venv/Scripts/pytest tests/

BACKEND_URL 可用 env 覆蓋(default http://127.0.0.1:8877)。
"""
import os
from pathlib import Path

import pytest
import requests
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).parent.parent
load_dotenv(BACKEND_DIR / ".env")

BACKEND_URL = os.environ.get("TEST_BACKEND_URL", "http://127.0.0.1:8877")


def _make_jwt():
    import jwt
    from datetime import datetime, timedelta, timezone
    secret = os.environ["SECRET_KEY"]
    payload = {
        "sub": "test_user",
        "role": "superadmin",
        "name": "tester",
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture(scope="session")
def backend_url():
    """驗證 backend 已啟動,回傳 URL。"""
    try:
        r = requests.get(BACKEND_URL + "/", timeout=2)
        if r.status_code != 200:
            pytest.fail(f"backend {BACKEND_URL} 回應 status {r.status_code}")
    except requests.exceptions.RequestException as e:
        pytest.fail(
            f"backend 未啟動於 {BACKEND_URL}\n"
            f"請先在另一 terminal 執行:\n"
            f"  cd backend\n"
            f"  venv/Scripts/python -m uvicorn main:app --host 127.0.0.1 --port 8877 --log-level warning\n"
            f"錯誤:{e}"
        )
    return BACKEND_URL


@pytest.fixture(scope="session")
def auth_headers():
    return {"Authorization": f"Bearer {_make_jwt()}"}


@pytest.fixture(scope="session")
def rules(backend_url, auth_headers):
    r = requests.get(backend_url + "/rules", headers=auth_headers, timeout=15)
    assert r.status_code == 200, f"GET /rules 失敗: {r.text[:200]}"
    return r.json()["rules"]


@pytest.fixture(scope="session")
def users(backend_url, auth_headers):
    r = requests.get(backend_url + "/users", headers=auth_headers, timeout=15)
    assert r.status_code == 200, f"GET /users 失敗: {r.text[:200]}"
    data = r.json()
    return data.get("users", data) if isinstance(data, dict) else data


@pytest.fixture(scope="session")
def cycle_dates(rules):
    from datetime import date, timedelta
    cycle = rules.get("cycle", {})
    s = cycle.get("start_date")
    e = cycle.get("end_date")
    if not s or not e:
        pytest.skip("DB 無 cycle 設定")
    sd = date.fromisoformat(s)
    ed = date.fromisoformat(e)
    n = (ed - sd).days + 1
    return [(sd + timedelta(days=i)).isoformat() for i in range(n)]


@pytest.fixture(scope="session")
def generated_balanced(backend_url, auth_headers):
    """呼叫一次 balanced 生成,session 內所有測試共用(耗時 ~2-3 分鐘)。"""
    r = requests.post(
        backend_url + "/schedule/generate",
        params={"profile": "balanced", "seed": 12345, "overwrite_confirmed": False},
        json={},
        headers=auth_headers,
        timeout=400,   # CP-SAT + SA + LOCAL-RESOLVE 最壞 ~300s
    )
    assert r.status_code == 200, f"生成失敗 (status {r.status_code}): {r.text[:800]}"
    return r.json()
