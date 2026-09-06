"""三個 profile (balanced / smooth / fair) 都必須能生成 FEASIBLE。"""
import pytest
import requests


def _gen(backend_url, auth_headers, profile):
    r = requests.post(
        backend_url + "/schedule/generate",
        params={"profile": profile, "seed": 0, "overwrite_confirmed": False},
        json={},
        headers=auth_headers,
        timeout=400,
    )
    return r


def test_smooth_generates(backend_url, auth_headers):
    r = _gen(backend_url, auth_headers, "smooth")
    assert r.status_code == 200, f"smooth 生成失敗: {r.text[:400]}"
    metrics = r.json().get("metrics") or {}
    assert metrics.get("solver_status") in ("OPTIMAL", "FEASIBLE"), \
        f"smooth status = {metrics.get('solver_status')}"


def test_fair_generates(backend_url, auth_headers):
    r = _gen(backend_url, auth_headers, "fair")
    assert r.status_code == 200, f"fair 生成失敗: {r.text[:400]}"
    metrics = r.json().get("metrics") or {}
    assert metrics.get("solver_status") in ("OPTIMAL", "FEASIBLE"), \
        f"fair status = {metrics.get('solver_status')}"
