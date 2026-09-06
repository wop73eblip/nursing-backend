from fastapi import FastAPI, HTTPException, Depends, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, date as date_type
import math, os, io
from urllib.parse import quote
from dotenv import load_dotenv
from supabase import create_client, Client
from ortools.sat.python import cp_model
import openpyxl
from openpyxl.styles import Font, Border, Side, Alignment, PatternFill

load_dotenv()

# 認證相關(SECRET_KEY / JWT / 防暴力 / role 檢查):見 auth.py
from auth import (
    LoginRequest, Token, AdminResetPassword, ChangePassword,
    verify_password, get_password_hash, create_access_token,
    get_current_user, require_roles,
    login_key, login_is_locked, login_record_fail, login_clear,
    LOGIN_MAX_FAILS, LOGIN_WINDOW_SEC, LOGIN_LOCK_SEC,
)

app = FastAPI(title="護理排班系統 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

from db import supabase   # supabase client 統一由 db.py 提供

# ── 掛載已拆出的 routers
from routes import rules as rules_router
from routes import logs as logs_router
from routes import game as game_router
from routes import users as users_router
from routes import shifts as shifts_router
from routes import export as export_router
from routes import generate as generate_router
app.include_router(rules_router.router)
app.include_router(logs_router.router)
app.include_router(game_router.router)
app.include_router(users_router.router)
app.include_router(shifts_router.router)
app.include_router(export_router.router)
app.include_router(generate_router.router)


# ── 資料模型(auth 相關已挪至 auth.py;rules/game 相關已挪至各 route module)
# UserCreate / UserPatch 已挪至 routes/users.py
class ShiftUpdate(BaseModel):
    nurse_uid: str
    date: str
    shift: Optional[str] = None

# ── 路由
@app.get("/")
def root():
    return {"message": "護理排班系統 API 運行中", "version": "2.0.0"}


@app.post("/auth/login", response_model=Token)
def login(request: LoginRequest, http_request: Request):
    uid_in = (request.uid or "").strip()

    # 取得來源 IP（Railway 在反向代理後，優先讀 X-Forwarded-For）
    fwd = http_request.headers.get("x-forwarded-for", "")
    client_ip = (fwd.split(",")[0].strip() if fwd else (http_request.client.host if http_request.client else "unknown"))
    rl_key = login_key(uid_in, client_ip)

    # 防暴力破解：鎖定中直接拒絕
    remain = login_is_locked(rl_key)
    if remain > 0:
        raise HTTPException(status_code=429, detail=f"登入嘗試過於頻繁，請於 {remain // 60 + 1} 分鐘後再試")

    # 帳號比對：取全部使用者於程式端做「大小寫不敏感的精確比對」，
    # 避免 ilike 把 % _ 當萬用字元造成的比對漏洞（uid 表小，效能無虞）
    res = supabase.table("users").select("uid, password_hash, role, name").execute()
    user = next((u for u in (res.data or []) if (u.get("uid") or "").lower() == uid_in.lower()), None)

    if not user or not verify_password(request.password, user["password_hash"]):
        login_record_fail(rl_key)
        raise HTTPException(status_code=401, detail="喔喔!! 帳號或密碼錯了")

    login_clear(rl_key)   # 成功後清除失敗紀錄
    token = create_access_token({
        "sub": user["uid"],
        "role": user["role"],
        "name": user["name"],
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "name": user["name"],
        "uid": user["uid"],
    }


# /users endpoints 已挪至 routes/users.py


# /schedule/generate + /schedule/commit 已挪至 routes/generate.py
# /schedule (GET/POST/batch/confirm/unconfirm) 已挪至 routes/shifts.py



# 匯出 Excel(/export/preview /export/schedule /export/temp)已挪至 routes/export.py


# /schedule/clear-generated + clear-cycle + restore-manual + restore-generated + purge-old
# 已挪至 routes/shifts.py
# /logs endpoints 已挪至 routes/logs.py
